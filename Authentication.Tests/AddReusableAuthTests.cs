using System.Reflection;
using Authentication;
using Authentication.Tests.Fakes;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Authentication.Tests;

/// <summary>
/// Covers what AddReusableAuth actually produces in the container: the cookies it emits
/// must be hardened, and the security-stamp validator must be attached.
/// </summary>
public class AddReusableAuthTests
{
    private static ServiceProvider Build(Action<ReusableAuthOptions>? configure = null)
    {
        ServiceCollection services = new();
        services.AddLogging();
        services.AddReusableAuth(configure);
        services.AddSingleton<IUserStore<ReusableAuthUser>, StampAwareUserStore>();
        return services.BuildServiceProvider();
    }

    private static CookieAuthenticationOptions CookieFor(ServiceProvider provider, string scheme)
        => provider.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>().Get(scheme);

    [Fact]
    public void SessionCookie_IsHttpOnlyAndSecure()
    {
        using ServiceProvider provider = Build();

        CookieAuthenticationOptions cookie = CookieFor(provider, IdentityConstants.ApplicationScheme);

        Assert.True(cookie.Cookie.HttpOnly);
        Assert.Equal(CookieSecurePolicy.Always, cookie.Cookie.SecurePolicy);
        Assert.Equal(SameSiteMode.Lax, cookie.Cookie.SameSite);
        Assert.Equal("/", cookie.Cookie.Path);
        Assert.Equal("__Host-auth", cookie.Cookie.Name);
        Assert.Equal(TimeSpan.FromHours(8), cookie.ExpireTimeSpan);
        Assert.True(cookie.SlidingExpiration);
    }

    [Fact]
    public void SessionCookie_ValidatesSecurityStamp()
    {
        using ServiceProvider provider = Build();

        CookieAuthenticationOptions cookie = CookieFor(provider, IdentityConstants.ApplicationScheme);

        // Assert the delegate's identity, not that it is non-null: CookieAuthenticationEvents
        // initialises OnValidatePrincipal to a no-op that returns Task.CompletedTask, so a
        // null check passes even when nothing is wired and the stamp is never validated.
        MethodInfo handler = cookie.Events.OnValidatePrincipal.Method;

        Assert.Equal(typeof(SecurityStampValidator), handler.DeclaringType);
        Assert.Equal(nameof(SecurityStampValidator.ValidatePrincipalAsync), handler.Name);
    }

    [Fact]
    public void TwoFactorSchemes_AreRegisteredAndHardened()
    {
        using ServiceProvider provider = Build();

        CookieAuthenticationOptions userId = CookieFor(provider, IdentityConstants.TwoFactorUserIdScheme);
        CookieAuthenticationOptions rememberMe = CookieFor(provider, IdentityConstants.TwoFactorRememberMeScheme);

        Assert.True(userId.Cookie.HttpOnly);
        Assert.Equal(CookieSecurePolicy.Always, userId.Cookie.SecurePolicy);
        Assert.Equal("__Host-auth-2fa", userId.Cookie.Name);
        Assert.Equal(TimeSpan.FromMinutes(5), userId.ExpireTimeSpan);

        Assert.True(rememberMe.Cookie.HttpOnly);
        Assert.Equal(CookieSecurePolicy.Always, rememberMe.Cookie.SecurePolicy);
        Assert.Equal("__Host-auth-2fa-remember", rememberMe.Cookie.Name);

        // Same reasoning as SessionCookie_ValidatesSecurityStamp: identity, not null-ness.
        Assert.Equal(typeof(SecurityStampValidator), rememberMe.Events.OnValidatePrincipal.Method.DeclaringType);
    }

    [Fact]
    public void TwoFactorCookieNames_FollowARenamedSessionCookie()
    {
        // The documented local-dev override drops the __Host- prefix; the 2FA cookies
        // have to come with it or they stay broken on plain http.
        using ServiceProvider provider = Build(o => o.CookieName = "dev-auth");

        Assert.Equal("dev-auth", CookieFor(provider, IdentityConstants.ApplicationScheme).Cookie.Name);
        Assert.Equal("dev-auth-2fa", CookieFor(provider, IdentityConstants.TwoFactorUserIdScheme).Cookie.Name);
        Assert.Equal(
            "dev-auth-2fa-remember",
            CookieFor(provider, IdentityConstants.TwoFactorRememberMeScheme).Cookie.Name);
    }

    [Fact]
    public void AntiforgeryCookie_IsHardened()
    {
        using ServiceProvider provider = Build();

        AntiforgeryOptions antiforgery = provider.GetRequiredService<IOptions<AntiforgeryOptions>>().Value;

        // Antiforgery's own SecurePolicy default is None, so this assertion is load-bearing.
        Assert.Equal(CookieSecurePolicy.Always, antiforgery.Cookie.SecurePolicy);
        Assert.True(antiforgery.Cookie.HttpOnly);
        Assert.Equal("__Host-csrf", antiforgery.Cookie.Name);
        Assert.Equal("X-CSRF-TOKEN", antiforgery.HeaderName);
    }

    [Fact]
    public void SecurityStampValidationInterval_TightensIdentityDefault()
    {
        using ServiceProvider provider = Build();

        SecurityStampValidatorOptions stamp =
            provider.GetRequiredService<IOptions<SecurityStampValidatorOptions>>().Value;

        // Identity ships 30 minutes; we deliberately do not.
        Assert.Equal(TimeSpan.FromMinutes(1), stamp.ValidationInterval);
    }

    [Fact]
    public void IdentityPolicy_ReflectsOptions()
    {
        using ServiceProvider provider = Build();

        IdentityOptions identity = provider.GetRequiredService<IOptions<IdentityOptions>>().Value;

        Assert.Equal(12, identity.Password.RequiredLength);
        Assert.True(identity.Password.RequireDigit);
        Assert.True(identity.Password.RequireNonAlphanumeric);
        Assert.Equal(5, identity.Lockout.MaxFailedAccessAttempts);
        Assert.Equal(TimeSpan.FromMinutes(15), identity.Lockout.DefaultLockoutTimeSpan);
        Assert.True(identity.Lockout.AllowedForNewUsers);
        Assert.True(identity.SignIn.RequireConfirmedEmail);
        Assert.True(identity.User.RequireUniqueEmail);
    }

    [Fact]
    public void HostOverrides_AreApplied()
    {
        using ServiceProvider provider = Build(o =>
        {
            o.SessionLifetime = TimeSpan.FromMinutes(30);
            o.CsrfHeaderName = "X-Custom-CSRF";
            o.PasswordMinimumLength = 16;
        });

        Assert.Equal(TimeSpan.FromMinutes(30), CookieFor(provider, IdentityConstants.ApplicationScheme).ExpireTimeSpan);
        Assert.Equal("X-Custom-CSRF", provider.GetRequiredService<IOptions<AntiforgeryOptions>>().Value.HeaderName);
        Assert.Equal(16, provider.GetRequiredService<IOptions<IdentityOptions>>().Value.Password.RequiredLength);
    }

    [Fact]
    public void HostOverrides_CannotWeakenHttpOnlyOrSecure()
    {
        // There is deliberately no option to turn these off; this test documents that
        // the invariant is structural, not a default someone can flip.
        using ServiceProvider provider = Build(o => o.CookieSameSite = SameSiteMode.None);

        CookieAuthenticationOptions cookie = CookieFor(provider, IdentityConstants.ApplicationScheme);

        Assert.True(cookie.Cookie.HttpOnly);
        Assert.Equal(CookieSecurePolicy.Always, cookie.Cookie.SecurePolicy);
        Assert.Equal(SameSiteMode.None, cookie.Cookie.SameSite);
    }

    [Fact]
    public void AddReusableAuth_Throws_WhenServicesIsNull()
    {
        Assert.Throws<ArgumentNullException>(
            () => ReusableAuthServiceCollectionExtensions.AddReusableAuth(null!));
    }
}
