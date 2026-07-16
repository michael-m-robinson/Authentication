using System.Reflection;
using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Logging;

namespace Authentication.Admin;

/// <summary>
/// Records every state-changing admin action to the audit trail, on both the MVC UI and the
/// JSON API, so no action can happen without being recorded.
/// </summary>
/// <remarks>
/// Registered as a global filter that audits only controllers from this assembly, so a host's
/// own controllers are untouched. Only unsafe methods (POST/PUT/PATCH/DELETE) are recorded:
/// the trail is a record of changes, and auditing every list and detail read would bury the
/// changes in noise. Reads are still gated by the admin role; they are simply not part of the
/// change trail.
/// <para>
/// This is an <see cref="IAsyncResultFilter"/> so it reads the <em>actual</em>
/// <c>Response.StatusCode</c> after the result has run, rather than inferring it from the result
/// type. For the JSON API that status is the outcome directly. The MVC UI uses
/// post-redirect-get for both success and failure (both are 302), with the failure reason in
/// <c>TempData["Error"]</c>, so the presence of that key marks a failed outcome.
/// </para>
/// <para>
/// Denied admin access (401/403) short-circuits before MVC filters run and is recorded
/// separately by <see cref="AdminAuthorizationDenialAuditor"/>. Antiforgery-validation failures
/// short-circuit before both hooks and are a documented gap in the trail. Writing the trail
/// never fails the action: a sink that throws is caught and logged, not propagated.
/// </para>
/// </remarks>
internal sealed class AdminAuditFilter : IAsyncResultFilter
{
    private static readonly Assembly AdminAssembly = typeof(AdminAuditFilter).Assembly;
    private static readonly string[] SafeMethods = ["GET", "HEAD", "OPTIONS", "TRACE"];

    private readonly IAdminAuditLog _audit;
    private readonly TimeProvider _clock;
    private readonly ILogger<AdminAuditFilter> _logger;

    public AdminAuditFilter(IAdminAuditLog audit, TimeProvider clock, ILogger<AdminAuditFilter> logger)
    {
        _audit = audit;
        _clock = clock;
        _logger = logger;
    }

    public async Task OnResultExecutionAsync(ResultExecutingContext context, ResultExecutionDelegate next)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(next);

        bool audit = ShouldAudit(context);

        // Run the result; the response status is settled once this returns.
        await next();

        if (audit)
        {
            await RecordAsync(context);
        }
    }

    private static bool ShouldAudit(ResultExecutingContext context)
    {
        if (context.Controller.GetType().Assembly != AdminAssembly)
        {
            return false;   // not an admin action
        }

        string method = context.HttpContext.Request.Method;
        return !SafeMethods.Contains(method, StringComparer.OrdinalIgnoreCase);
    }

    private async Task RecordAsync(ResultExecutingContext context)
    {
        int statusCode = context.HttpContext.Response.StatusCode;
        ClaimsPrincipal actor = context.HttpContext.User;

        AdminAuditEntry entry = new(
            OccurredAt: _clock.GetUtcNow(),
            ActorUserId: actor.FindFirstValue(ClaimTypes.NameIdentifier),
            ActorName: actor.Identity?.Name ?? actor.FindFirstValue(ClaimTypes.Email),
            Action: ActionName(context),
            TargetUserId: context.RouteData.Values.TryGetValue("id", out object? id) ? id?.ToString() : null,
            Succeeded: Succeeded(context, statusCode),
            StatusCode: statusCode);

        try
        {
            await _audit.RecordAsync(entry, context.HttpContext.RequestAborted);
        }
#pragma warning disable CA1031 // A failed audit write must not turn a completed action into an error.
        catch (Exception ex)
#pragma warning restore CA1031
        {
            _logger.LogWarning(ex, "Failed to record an admin audit entry for {Action}.", entry.Action);
        }
    }

    private static bool Succeeded(ResultExecutingContext context, int statusCode)
    {
        if (statusCode >= 400)
        {
            return false;
        }

        // The MVC UI redirects on both success and failure; the failure reason lives in
        // TempData["Error"]. ContainsKey is non-consuming, so it does not steal the banner the
        // redirected page is about to show. The JSON API sets no TempData, so this is a no-op
        // there and the status code alone decides.
        if (context.Controller is Controller controller && controller.TempData.ContainsKey("Error"))
        {
            return false;
        }

        return true;
    }

    private static string ActionName(ResultExecutingContext context)
        => context.ActionDescriptor is ControllerActionDescriptor descriptor
            ? $"{descriptor.ControllerName}.{descriptor.ActionName}"
            : context.ActionDescriptor.DisplayName ?? "Unknown";
}
