using System.Reflection;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.Extensions.DependencyInjection;

namespace Authentication.Admin.Tests;

/// <summary>
/// Covers the small infrastructure pieces: the role bootstrapper, the setup-state seam, and the
/// assembly guard on the alerts feature provider.
/// </summary>
/// <remarks>
/// The feature provider's positive behaviour - actually removing the real
/// <c>AdminAlertsController</c> when Social is absent - is proven in the HTTP integration tests,
/// because the provider matches on the admin assembly and only the real controller lives there.
/// What is unit-testable here is the safety guard: it must never remove a same-named controller
/// that belongs to some other assembly (a host's own), which is the property that keeps it from
/// damaging the host.
/// </remarks>
public sealed class AdminInfrastructureTests : IDisposable
{
    private readonly AdminTestHost _host = new();

    public void Dispose() => _host.Dispose();

    // ---- AdminRoleBootstrapper ----------------------------------------------------------

    [Fact]
    public async Task Bootstrapper_CreatesTheAdminRole_AndIsIdempotent()
    {
        using IServiceScope scope = _host.Scope();
        IRoleService roles = scope.ServiceProvider.GetRequiredService<IRoleService>();

        Assert.False(await roles.RoleExistsAsync("Admin"));

        await AdminRoleBootstrapper.EnsureRoleAsync(roles, "Admin");
        Assert.True(await roles.RoleExistsAsync("Admin"));

        // A second run must not fault - two hosts can start at once.
        await AdminRoleBootstrapper.EnsureRoleAsync(roles, "Admin");
        Assert.True(await roles.RoleExistsAsync("Admin"));
    }

    // ---- SetupState ---------------------------------------------------------------------

    [Fact]
    public async Task SetupState_IsFalseUntilAnAdminExists_ThenTrue()
    {
        using IServiceScope scope = _host.Scope();
        IRoleService roles = scope.ServiceProvider.GetRequiredService<IRoleService>();
        SetupState state = new(roles, new AdminOptions());

        // Fresh database, no admin role even: reads as "no admin".
        Assert.False(await state.AnyAdminExistsAsync());

        string userId = await _host.CreateUserAsync("admin@example.com");
        await roles.CreateRoleAsync("Admin");
        await roles.AddToRoleAsync(userId, "Admin");

        Assert.True(await state.AnyAdminExistsAsync());
    }

    [Fact]
    public async Task SetupState_HonoursACustomRoleName()
    {
        using IServiceScope scope = _host.Scope();
        IRoleService roles = scope.ServiceProvider.GetRequiredService<IRoleService>();
        SetupState state = new(roles, new AdminOptions { AdminRoleName = "SuperUser" });

        string userId = await _host.CreateUserAsync("super@example.com");
        await roles.CreateRoleAsync("SuperUser");
        await roles.AddToRoleAsync(userId, "SuperUser");

        Assert.True(await state.AnyAdminExistsAsync());
    }

    // ---- AdminAlertsControllerFeatureProvider (assembly guard) --------------------------

    [Fact]
    public void FeatureProvider_LeavesAForeignControllerAlone_EvenWhenDisabled()
    {
        // A type named exactly like the real alerts controller but living in this test assembly,
        // standing in for a host that happens to have its own AdminAlertsController. The
        // provider must not touch it, because it is not from the admin assembly.
        ControllerFeature feature = new();
        TypeInfo foreign = typeof(AdminAlertsController).GetTypeInfo();
        feature.Controllers.Add(foreign);

        new AdminAlertsControllerFeatureProvider(alertsEnabled: false).PopulateFeature([], feature);

        Assert.Contains(foreign, feature.Controllers);
    }

    [Fact]
    public void FeatureProvider_DoesNothing_WhenAlertsEnabled()
    {
        ControllerFeature feature = new();
        feature.Controllers.Add(typeof(AdminAlertsController).GetTypeInfo());

        new AdminAlertsControllerFeatureProvider(alertsEnabled: true).PopulateFeature([], feature);

        Assert.Single(feature.Controllers);
    }

    [Fact]
    public void FeatureProvider_NamesBothAlertsControllers()
    {
        // Both the MVC and API alerts controllers depend on Social, so both must be in the
        // removal set. If a new alerts controller is added without being listed here, it would
        // ship active on a non-Social host and 500 on IAlertService.
        Assert.Contains("AdminAlertsController", AdminAlertsControllerFeatureProvider.AlertsControllerTypeNames);
        Assert.Contains("AdminApiAlertsController", AdminAlertsControllerFeatureProvider.AlertsControllerTypeNames);
    }

    // ---- LastAdminGuard -----------------------------------------------------------------

    [Fact]
    public async Task Guard_BlocksTheLastAdmin_ButNotOneOfSeveral()
    {
        using IServiceScope scope = _host.Scope();
        IRoleService roles = scope.ServiceProvider.GetRequiredService<IRoleService>();
        LastAdminGuard guard = new(roles, new AdminOptions());

        string soleAdmin = await _host.CreateUserAsync("admin1@example.com");
        await roles.CreateRoleAsync("Admin");
        await roles.AddToRoleAsync(soleAdmin, "Admin");

        // The only admin: blocked.
        Assert.True(await guard.WouldLeaveNoAdminsAsync(soleAdmin));

        // Add a second admin; now removing the first leaves one, so it is allowed.
        string secondAdmin = await _host.CreateUserAsync("admin2@example.com");
        await roles.AddToRoleAsync(secondAdmin, "Admin");
        Assert.False(await guard.WouldLeaveNoAdminsAsync(soleAdmin));

        // A non-admin is never the last admin.
        string plain = await _host.CreateUserAsync("plain@example.com");
        Assert.False(await guard.WouldLeaveNoAdminsAsync(plain));
    }

    // Named to match the real controller's type name, deliberately in the test assembly, to
    // exercise the provider's assembly guard.
    private sealed class AdminAlertsController
    {
    }
}
