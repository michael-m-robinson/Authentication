using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Hosting;

namespace Authentication.Admin;

/// <summary>
/// Seals the first-admin setup page: it returns <c>404 Not Found</c> once an administrator
/// exists, and - outside Development - also when no setup secret has been configured.
/// </summary>
/// <remarks>
/// Applied to the setup controller (and only it) with <c>[ServiceFilter(typeof(SetupSealFilter))]</c>,
/// so the check runs before any setup action - the GET that renders the form and the POST that
/// creates the first admin alike - and no action can forget it. It reads live state through
/// <see cref="SetupState"/> on every request, so the seal is permanent from the moment the
/// first admin exists.
/// <para>
/// <strong>Fail-closed in Production.</strong> While no admin exists the page is anonymous, so
/// whoever reaches it first becomes the administrator. In Development that is a convenience; in
/// Production it is a risk, so unless a <see cref="AdminOptions.SetupToken"/> is configured, the
/// page is sealed there too. A production deployment must set a setup secret to bootstrap the
/// first admin, which closes the first-run race.
/// </para>
/// <para>
/// A 404, deliberately, not a redirect: a redirect would confirm the setup route exists, and a
/// sealed setup page should look exactly like a page that was never there.
/// </para>
/// </remarks>
internal sealed class SetupSealFilter : IAsyncActionFilter
{
    private readonly SetupState _state;
    private readonly AdminOptions _options;
    private readonly IHostEnvironment _environment;

    public SetupSealFilter(SetupState state, AdminOptions options, IHostEnvironment environment)
    {
        _state = state;
        _options = options;
        _environment = environment;
    }

    public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(next);

        if (IsSealed() || await _state.AnyAdminExistsAsync())
        {
            // Short-circuit: do not call next(), so the setup action never runs.
            context.Result = new NotFoundResult();
            return;
        }

        await next();
    }

    // Outside Development, refuse the setup page entirely unless a setup secret is configured.
    private bool IsSealed()
        => !_environment.IsDevelopment() && string.IsNullOrEmpty(_options.SetupToken);
}
