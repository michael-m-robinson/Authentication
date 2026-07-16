using Microsoft.AspNetCore.Routing;

namespace Microsoft.AspNetCore.Builder;

/// <summary>
/// Maps the admin panel's endpoints into a host's routing.
/// </summary>
public static class ReusableAuthAdminEndpointRouteBuilderExtensions
{
    /// <summary>
    /// Maps the admin panel's controllers, so its pages under the configured route prefix
    /// (<c>/admin</c> by default) are reachable.
    /// </summary>
    /// <param name="endpoints">The endpoint route builder to add to.</param>
    /// <returns>
    /// A builder for the mapped controller endpoints, for further conventions if wanted.
    /// </returns>
    /// <exception cref="ArgumentNullException"><paramref name="endpoints"/> is null.</exception>
    /// <remarks>
    /// The admin's controllers are attribute-routed, so this is a call to
    /// <see cref="ControllerEndpointRouteBuilderExtensions.MapControllers"/>. That method is
    /// idempotent - a host that already calls <c>MapControllers</c> or
    /// <c>MapControllerRoute</c> will not double-register - so this is the one documented line
    /// a host adds, and it works whether or not the host maps controllers of its own.
    /// <code>
    /// var app = builder.Build();
    /// // ... UseAuthentication(); UseAuthorization(); ...
    /// app.MapReusableAuthAdmin();
    /// </code>
    /// </remarks>
    public static ControllerActionEndpointConventionBuilder MapReusableAuthAdmin(
        this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        return endpoints.MapControllers();
    }
}
