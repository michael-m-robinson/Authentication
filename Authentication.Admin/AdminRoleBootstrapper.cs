using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Authentication.Admin;

/// <summary>
/// Ensures the admin role exists at startup, so the first-admin setup can grant it.
/// </summary>
/// <remarks>
/// Neither the core library nor the EF store package seeds any role, so on a fresh database the
/// admin role does not exist until something creates it. This guarantees it is present before
/// the first setup request, so granting it is a plain add rather than a create-then-add that
/// could race. It is idempotent: if the role already exists it does nothing, and
/// <see cref="IRoleService.CreateRoleAsync"/> tolerates the already-exists case, so two hosts
/// starting at once cannot fault.
/// <para>
/// The setup flow also ensures the role itself, so a host that turns
/// <see cref="AdminOptions.EnsureAdminRoleOnStartup"/> off does not break setup; it only gives
/// up the startup guarantee.
/// </para>
/// </remarks>
internal sealed class AdminRoleBootstrapper : IHostedService
{
    private readonly IServiceProvider _services;
    private readonly AdminOptions _options;

    public AdminRoleBootstrapper(IServiceProvider services, AdminOptions options)
    {
        _services = services;
        _options = options;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        // A scope, because IRoleService is scoped and this runs at host startup where there is
        // no ambient request scope.
        using IServiceScope scope = _services.CreateScope();
        IRoleService roles = scope.ServiceProvider.GetRequiredService<IRoleService>();

        await EnsureRoleAsync(roles, _options.AdminRoleName);
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    /// <summary>
    /// Creates the role if it is not already there. Separate from <see cref="StartAsync"/> so a
    /// test can exercise it against a real <see cref="IRoleService"/> without a host.
    /// </summary>
    internal static async Task EnsureRoleAsync(IRoleService roles, string roleName)
    {
        ArgumentNullException.ThrowIfNull(roles);

        if (await roles.RoleExistsAsync(roleName))
        {
            return;
        }

        // Ignore the result: a concurrent starter may have created it between the check and
        // here, which CreateRoleAsync reports as a rejection, and that is the state we wanted.
        await roles.CreateRoleAsync(roleName);
    }
}
