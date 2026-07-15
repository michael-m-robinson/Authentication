using Authentication;
using Authentication.Tests.Fakes;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;

namespace Authentication.Tests;

/// <summary>
/// Covers the guard that refuses to boot on a store which cannot support security
/// stamps.
/// </summary>
public class SecurityStampStoreGuardTests
{
    private static UserManager<ReusableAuthUser> UserManagerBackedBy<TStore>()
        where TStore : class, IUserStore<ReusableAuthUser>
    {
        ServiceCollection services = new();
        services.AddLogging();
        services.AddReusableAuth();
        services.AddSingleton<IUserStore<ReusableAuthUser>, TStore>();

        ServiceProvider provider = services.BuildServiceProvider();
        return provider.CreateScope().ServiceProvider.GetRequiredService<UserManager<ReusableAuthUser>>();
    }

    [Fact]
    public void Verify_Throws_WhenStoreCannotSupportSecurityStamps()
    {
        UserManager<ReusableAuthUser> userManager = UserManagerBackedBy<StamplessUserStore>();

        // Identity does not throw here on its own: it silently reports every stamp
        // check as valid, so session invalidation quietly becomes a no-op. The whole
        // point of the guard is to turn that into a loud startup failure.
        Assert.False(userManager.SupportsUserSecurityStamp);

        InvalidOperationException error = Assert.Throws<InvalidOperationException>(
            () => SecurityStampStoreGuard<ReusableAuthUser>.Verify(userManager));

        Assert.Contains("IUserSecurityStampStore", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Verify_Passes_WhenStoreSupportsSecurityStamps()
    {
        UserManager<ReusableAuthUser> userManager = UserManagerBackedBy<StampAwareUserStore>();

        Assert.True(userManager.SupportsUserSecurityStamp);

        SecurityStampStoreGuard<ReusableAuthUser>.Verify(userManager);
    }

    [Fact]
    public void Verify_Throws_WhenUserManagerIsNull()
    {
        Assert.Throws<ArgumentNullException>(() => SecurityStampStoreGuard<ReusableAuthUser>.Verify(null!));
    }
}
