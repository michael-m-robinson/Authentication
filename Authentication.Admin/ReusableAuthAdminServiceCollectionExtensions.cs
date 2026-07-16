using System.Linq;
using Authentication;
using Authentication.Admin;
using Authentication.Social;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Wires the admin panel into a host's container.
/// </summary>
/// <remarks>
/// Call this alongside <c>AddReusableAuth</c> (and the EF store call), not instead of any part
/// of it. The admin consumes the identity managers and services those calls already register;
/// it never re-registers Identity, cookies, or antiforgery.
/// <para>
/// The panel is gated behind the <c>Admin</c> role. For the gate to redirect a browser rather
/// than answer a bare 403, set <c>AccessDeniedPath</c> in <c>ReusableAuthOptions</c>. The first
/// administrator is created through the one-time setup page at <c>/{RoutePrefix}/setup</c>,
/// which seals itself once an admin exists.
/// </para>
/// </remarks>
public static class ReusableAuthAdminServiceCollectionExtensions
{
    /// <summary>
    /// Adds the admin panel over the built-in <see cref="ReusableAuthUser"/>.
    /// </summary>
    /// <param name="services">The service collection to add to.</param>
    /// <param name="configure">Optional overrides; every value already has a safe default.</param>
    /// <returns>The same <paramref name="services"/>, for chaining.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="services"/> is null.</exception>
    public static IServiceCollection AddReusableAuthAdmin(
        this IServiceCollection services,
        Action<AdminOptions>? configure = null)
        => services.AddReusableAuthAdmin<ReusableAuthUser>(configure);

    /// <summary>
    /// Adds the admin panel over a host-supplied user type.
    /// </summary>
    /// <typeparam name="TUser">
    /// The user type given to <c>AddReusableAuth&lt;TUser&gt;</c>. The admin's user service is
    /// closed over it so it can list and manage users through
    /// <see cref="UserManager{TUser}"/>.
    /// </typeparam>
    /// <param name="services">The service collection to add to.</param>
    /// <param name="configure">Optional overrides; every value already has a safe default.</param>
    /// <returns>The same <paramref name="services"/>, for chaining.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="services"/> is null.</exception>
    /// <remarks>
    /// <code>
    /// builder.Services.AddReusableAuthAdmin&lt;AppUser&gt;();
    /// // then, after building the app:
    /// app.MapReusableAuthAdmin();
    /// </code>
    /// </remarks>
    public static IServiceCollection AddReusableAuthAdmin<TUser>(
        this IServiceCollection services,
        Action<AdminOptions>? configure = null)
        where TUser : IdentityUser<string>, new()
    {
        ArgumentNullException.ThrowIfNull(services);

        // Idempotency guard: AdminOptions is registered exactly once per mount, so its presence
        // means the panel is already mounted. Returning early stops a second call from adding
        // the audit filter and route-prefix convention twice (which would double-log and turn
        // the prefix into /admin/admin/...). The host's own AddControllersWithViews is
        // idempotent already; this guards re-entry of our method.
        if (services.Any(descriptor => descriptor.ServiceType == typeof(AdminOptions)))
        {
            return services;
        }

        AdminOptions options = new();
        configure?.Invoke(options);

        // Auto-detect Social: the alerts pages light up only when the host has wired
        // Authentication.Social, i.e. an IAlertService is in the container. A host can still
        // force them off by setting EnableAlerts = false in configure; it cannot force them on
        // without Social, because the alerts controller would fail to resolve IAlertService -
        // which is exactly why a feature provider (added in a later step) removes that
        // controller when this stays false.
        options.EnableAlerts = options.EnableAlerts
            || services.Any(descriptor => descriptor.ServiceType == typeof(IAlertService));

        // A single shared instance, injected directly. The options are fixed at mount time
        // (the Social auto-detect can only be computed here, against the live registrations),
        // so there is nothing to reload and no need for the IOptions machinery.
        services.AddSingleton(options);

        // Make the RCL's controllers and compiled views discoverable by the host's MVC. They
        // live in this assembly, not the host's, so without registering it as an application
        // part the host would never find them. AddControllersWithViews is safe to call again -
        // the ApplicationPartManager is a single shared instance - so this composes with a host
        // that already called it.
        services
            .AddControllersWithViews()
            .AddApplicationPart(typeof(ReusableAuthAdminServiceCollectionExtensions).Assembly)
            // When Social is not wired, physically remove the alerts controller so its route
            // never exists and it can never fail to resolve IAlertService.
            .ConfigureApplicationPartManager(manager =>
                manager.FeatureProviders.Add(new AdminAlertsControllerFeatureProvider(options.EnableAlerts)));

        // The one place TUser is closed: a non-generic IAdminUserService the controllers
        // depend on, backed by the generic implementation over the host's user type. TryAdd so
        // a host that supplied its own admin user service wins.
        services.TryAddScoped<IAdminUserService, AdminUserService<TUser>>();

        // The last-administrator guard, shared by the MVC UI and the JSON API.
        services.TryAddScoped<LastAdminGuard>();

        // Ensure the admin role exists at startup so the first-admin setup can grant it.
        if (options.EnsureAdminRoleOnStartup)
        {
            services.AddHostedService<AdminRoleBootstrapper>();
        }

        // Mount the whole panel under the configured prefix (/admin by default). The convention
        // touches only this assembly's controllers, so the host's own routes are untouched.
        services.Configure<Microsoft.AspNetCore.Mvc.MvcOptions>(mvc =>
            mvc.Conventions.Add(new AdminRoutePrefixConvention(options.RoutePrefix)));

        // The "does an admin already exist?" seam, shared by the setup page's seal and its
        // create action so the rule lives in one place.
        services.TryAddScoped<SetupState>();

        // The seal itself, resolved by [ServiceFilter] on the setup controller.
        services.TryAddScoped<SetupSealFilter>();

        // Audit: a store-agnostic default (structured logging) behind a seam a host can replace,
        // and a global filter that records every state-changing admin action. TimeProvider is
        // registered here because a host without Social would not otherwise have one.
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddScoped<IAdminAuditLog, LoggerAdminAuditLog>();
        services.TryAddScoped<AdminAuditFilter>();
        services.Configure<Microsoft.AspNetCore.Mvc.MvcOptions>(mvc =>
            mvc.Filters.AddService<AdminAuditFilter>());

        // Record denied admin-access attempts (401/403), which short-circuit before the audit
        // filter runs. Decorates the authorization-middleware result handler and delegates to
        // the default, so normal challenge/forbid behaviour is unchanged.
        services.AddSingleton<Microsoft.AspNetCore.Authorization.IAuthorizationMiddlewareResultHandler, AdminAuthorizationDenialAuditor>();

        // The panel's gate as a single named policy (RequireRole over the configured role name),
        // so the rule lives in one place and honours a custom AdminRoleName. Controllers carry
        // [Authorize(Policy = AdminPolicies.Panel)].
        services.AddAuthorizationBuilder()
            .AddPolicy(AdminPolicies.Panel, policy => policy.RequireRole(options.AdminRoleName));

        // The alerts broadcaster depends on IAlertService, so register it only when Social is
        // wired - the same condition that keeps the alerts controller activatable.
        if (options.EnableAlerts)
        {
            services.TryAddScoped<IAdminAlertBroadcaster, AdminAlertBroadcaster>();
        }

        return services;
    }
}
