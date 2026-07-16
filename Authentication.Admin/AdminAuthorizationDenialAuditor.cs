using System.Reflection;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Policy;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Authentication.Admin;

/// <summary>
/// Records denied attempts to reach an admin endpoint (401 challenge / 403 forbid) to the audit
/// trail. These short-circuit before MVC filters run, so <see cref="AdminAuditFilter"/> never
/// sees them; a failed admin-access attempt is exactly the kind of security event a trail wants.
/// </summary>
/// <remarks>
/// Follows the documented pattern for customizing authorization-middleware behaviour: implement
/// <see cref="IAuthorizationMiddlewareResultHandler"/>, do the extra work, then delegate to the
/// built-in <see cref="AuthorizationMiddlewareResultHandler"/> so normal handling is unchanged.
/// It only records denials on this assembly's admin endpoints, so a host's own authorization is
/// untouched. Antiforgery-validation failures are handled elsewhere in the pipeline and are not
/// captured here (a documented gap).
/// </remarks>
internal sealed class AdminAuthorizationDenialAuditor : IAuthorizationMiddlewareResultHandler
{
    private static readonly Assembly AdminAssembly = typeof(AdminAuthorizationDenialAuditor).Assembly;

    // The framework default this decorator delegates to for the actual challenge/forbid.
    private readonly AuthorizationMiddlewareResultHandler _default = new();

    private readonly TimeProvider _clock;
    private readonly ILogger<AdminAuthorizationDenialAuditor> _logger;

    // This handler is a singleton (that is how IAuthorizationMiddlewareResultHandler resolves),
    // so it cannot hold the scoped IAdminAuditLog: that is resolved per request from
    // context.RequestServices in RecordDenialAsync. TimeProvider and the logger are singletons
    // and safe to inject.
    public AdminAuthorizationDenialAuditor(TimeProvider clock, ILogger<AdminAuthorizationDenialAuditor> logger)
    {
        _clock = clock;
        _logger = logger;
    }

    public async Task HandleAsync(
        RequestDelegate next,
        HttpContext context,
        AuthorizationPolicy policy,
        PolicyAuthorizationResult authorizeResult)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(authorizeResult);

        if ((authorizeResult.Challenged || authorizeResult.Forbidden) && IsAdminEndpoint(context))
        {
            await RecordDenialAsync(context, authorizeResult);
        }

        // Delegate to the default handler so the challenge/forbid happens exactly as normal.
        await _default.HandleAsync(next, context, policy, authorizeResult);
    }

    private static bool IsAdminEndpoint(HttpContext context)
    {
        ControllerActionDescriptor? descriptor = context.GetEndpoint()?.Metadata
            .GetMetadata<ControllerActionDescriptor>();
        return descriptor?.ControllerTypeInfo.Assembly == AdminAssembly;
    }

    private async Task RecordDenialAsync(HttpContext context, PolicyAuthorizationResult authorizeResult)
    {
        ClaimsPrincipal actor = context.User;
        ControllerActionDescriptor? descriptor = context.GetEndpoint()?.Metadata
            .GetMetadata<ControllerActionDescriptor>();

        AdminAuditEntry entry = new(
            OccurredAt: _clock.GetUtcNow(),
            ActorUserId: actor.FindFirstValue(ClaimTypes.NameIdentifier),
            ActorName: actor.Identity?.Name ?? actor.FindFirstValue(ClaimTypes.Email) ?? "anonymous",
            Action: descriptor is not null ? $"{descriptor.ControllerName}.{descriptor.ActionName}" : "admin",
            TargetUserId: context.Request.RouteValues.TryGetValue("id", out object? id) ? id?.ToString() : null,
            Succeeded: false,
            StatusCode: authorizeResult.Challenged
                ? StatusCodes.Status401Unauthorized
                : StatusCodes.Status403Forbidden);

        try
        {
            IAdminAuditLog audit = context.RequestServices.GetRequiredService<IAdminAuditLog>();
            await audit.RecordAsync(entry, context.RequestAborted);
        }
#pragma warning disable CA1031 // A failed audit write must not turn a denial into a server error.
        catch (Exception ex)
#pragma warning restore CA1031
        {
            _logger.LogWarning(ex, "Failed to record an admin authorization-denial audit entry.");
        }
    }
}
