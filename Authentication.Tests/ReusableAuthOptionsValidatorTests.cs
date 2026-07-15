using Authentication;
using Authentication.Tests.Fakes;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Authentication.Tests;

/// <summary>
/// Covers the startup validation that stops a host booting into a weakened or
/// self-contradictory auth configuration.
/// </summary>
public class ReusableAuthOptionsValidatorTests
{
    private static ValidateOptionsResult Validate(Action<ReusableAuthOptions> configure)
    {
        ReusableAuthOptions options = new();
        configure(options);
        return new ReusableAuthOptionsValidator().Validate(Options.DefaultName, options);
    }

    [Fact]
    public void Defaults_AreValid()
    {
        Assert.True(Validate(_ => { }).Succeeded);
    }

    [Fact]
    public void HostPrefixedCookie_WithDomain_IsRejected()
    {
        // Browsers ignore a __Host- cookie that carries a Domain, so this combination
        // would silently drop the guarantee the prefix is there to provide.
        ValidateOptionsResult result = Validate(o => o.CookieDomain = "example.com");

        Assert.True(result.Failed);
        Assert.Contains(result.Failures!, f => f.Contains("__Host-", StringComparison.Ordinal));
    }

    [Fact]
    public void HostPrefixDropped_WithDomain_IsAccepted()
    {
        ValidateOptionsResult result = Validate(o =>
        {
            o.CookieName = "auth";
            o.CsrfCookieName = "csrf";
            o.CookieDomain = "example.com";
        });

        Assert.True(result.Succeeded);
    }

    [Fact]
    public void PasswordLength_BelowFloor_IsRejected()
    {
        Assert.True(Validate(o => o.PasswordMinimumLength = 6).Failed);
        Assert.True(Validate(o => o.PasswordMinimumLength = ReusableAuthOptions.MinimumAllowedPasswordLength).Succeeded);
    }

    [Fact]
    public void SameSiteUnspecified_IsRejected()
    {
        // Unspecified omits the attribute entirely and defers to per-browser defaults,
        // which is not a decision this library is willing to leave implicit.
        Assert.True(Validate(o => o.CookieSameSite = SameSiteMode.Unspecified).Failed);
    }

    [Fact]
    public void CollidingCookieNames_AreRejected()
    {
        Assert.True(Validate(o => o.CsrfCookieName = o.CookieName).Failed);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void EmptyCookieName_IsRejected(string name)
    {
        Assert.True(Validate(o => o.CookieName = name).Failed);
    }

    [Fact]
    public void NonPositiveSessionLifetime_IsRejected()
    {
        Assert.True(Validate(o => o.SessionLifetime = TimeSpan.Zero).Failed);
        Assert.True(Validate(o => o.SessionLifetime = TimeSpan.FromSeconds(-1)).Failed);
    }

    [Fact]
    public void NegativeStampInterval_IsRejected_ButZeroIsAllowed()
    {
        Assert.True(Validate(o => o.SecurityStampValidationInterval = TimeSpan.FromSeconds(-1)).Failed);

        // Zero is meaningful: revalidate on every request.
        Assert.True(Validate(o => o.SecurityStampValidationInterval = TimeSpan.Zero).Succeeded);
    }

    [Fact]
    public void InvalidLockout_IsRejected()
    {
        Assert.True(Validate(o => o.LockoutMaxFailedAttempts = 0).Failed);
        Assert.True(Validate(o => o.LockoutDuration = TimeSpan.Zero).Failed);
    }

    [Fact]
    public void BadConfiguration_ActuallyThrows_WhenOptionsAreResolved()
    {
        // This test exists because ValidateOnStart() does NOT run under a plain
        // BuildServiceProvider - it needs a real IHost. Without this, every test above
        // could pass while the validator was never wired into the container at all.
        ServiceCollection services = new();
        services.AddLogging();
        services.AddReusableAuth(o => o.PasswordMinimumLength = 4);
        services.AddSingleton<IUserStore<ReusableAuthUser>, StampAwareUserStore>();

        using ServiceProvider provider = services.BuildServiceProvider();

        OptionsValidationException error = Assert.Throws<OptionsValidationException>(
            () => provider.GetRequiredService<IOptions<ReusableAuthOptions>>().Value);

        Assert.Contains(error.Failures, f => f.Contains(nameof(ReusableAuthOptions.PasswordMinimumLength), StringComparison.Ordinal));
    }
}
