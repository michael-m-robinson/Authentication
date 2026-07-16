using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Authentication;

/// <summary>
/// Fails the host at startup if the registered Identity store cannot support security
/// stamps.
/// </summary>
/// <remarks>
/// This guard exists because the underlying failure is silent. ASP.NET Core Identity
/// gates its stamp check on <c>UserManager.SupportsUserSecurityStamp</c>, which is just
/// <c>Store is IUserSecurityStampStore&lt;TUser&gt;</c>. When a store does not implement
/// that interface, <c>SignInManager.ValidateSecurityStampAsync</c> does not throw. It
/// returns <see langword="true"/> unconditionally. Session invalidation would then be a
/// no-op: a password reset or privilege change would leave every existing cookie working,
/// with nothing in the logs to say so.
/// <para>
/// Since this library is storage-agnostic and the host supplies the store, that
/// combination is a real risk rather than a theoretical one, so it is checked at boot.
/// </para>
/// </remarks>
/// <typeparam name="TUser">The Identity user type.</typeparam>
internal sealed class SecurityStampStoreGuard<TUser> : IHostedService
    where TUser : IdentityUser<string>
{
    private readonly IServiceProvider _services;

    public SecurityStampStoreGuard(IServiceProvider services)
    {
        _services = services;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        using IServiceScope scope = _services.CreateScope();
        UserManager<TUser> userManager = scope.ServiceProvider.GetRequiredService<UserManager<TUser>>();

        Verify(userManager);

        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    /// <summary>
    /// Throws if <paramref name="userManager"/> is backed by a store that does not
    /// support security stamps. Separate from <see cref="StartAsync"/> so it can be
    /// exercised directly by tests without standing up a host.
    /// </summary>
    internal static void Verify(UserManager<TUser> userManager)
    {
        ArgumentNullException.ThrowIfNull(userManager);

        if (userManager.SupportsUserSecurityStamp)
        {
            return;
        }

        throw new InvalidOperationException(
            $"The registered Identity store does not implement IUserSecurityStampStore<{typeof(TUser).Name}>. " +
            "ASP.NET Core Identity treats every security-stamp check as valid when the store lacks that " +
            "interface, so password resets and privilege changes would silently fail to invalidate existing " +
            "sessions. Register a store that implements IUserSecurityStampStore before calling AddReusableAuth.");
    }
}
