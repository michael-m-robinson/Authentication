using Authentication;
using Authentication.Tests.Fakes;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Authentication.Tests;

/// <summary>
/// Covers binding <see cref="ReusableAuthOptions"/> from configuration, and the limit that
/// comes with it: the settings are read once, at startup.
/// </summary>
public class ConfigurationBindingTests
{
    private static IConfiguration ConfigurationFrom(Dictionary<string, string?> values)
        => new ConfigurationBuilder().AddInMemoryCollection(values).Build();

    private static ServiceProvider Build(IConfiguration configuration, Action<ReusableAuthOptions>? configure = null)
    {
        ServiceCollection services = new();
        services.AddLogging();
        services.AddReusableAuth(configuration, configure);
        services.AddSingleton<IUserStore<ReusableAuthUser>, StampAwareUserStore>();
        services.AddSingleton<IRoleStore<IdentityRole>, InMemoryRoleStore>();
        return services.BuildServiceProvider();
    }

    [Fact]
    public void SettingsBind_FromConfiguration()
    {
        IConfiguration configuration = ConfigurationFrom(new()
        {
            ["PasswordMinimumLength"] = "20",
            ["LockoutMaxFailedAttempts"] = "3",
            ["RequireConfirmedEmail"] = "false",
            ["AuthenticatorIssuer"] = "Contoso",
        });

        using ServiceProvider provider = Build(configuration);
        ReusableAuthOptions options = provider.GetRequiredService<IOptions<ReusableAuthOptions>>().Value;

        Assert.Equal(20, options.PasswordMinimumLength);
        Assert.Equal(3, options.LockoutMaxFailedAttempts);
        Assert.False(options.RequireConfirmedEmail);
        Assert.Equal("Contoso", options.AuthenticatorIssuer);
    }

    [Fact]
    public void TimeSpansAndEnums_Bind()
    {
        // Worth asserting: these are the types most likely to bind badly from strings, and a
        // silently-wrong session lifetime is not something you want to find in production.
        IConfiguration configuration = ConfigurationFrom(new()
        {
            ["SessionLifetime"] = "04:30:00",
            ["PasswordResetTokenLifetime"] = "00:15:00",
            ["CookieSameSite"] = "Strict",
        });

        using ServiceProvider provider = Build(configuration);
        ReusableAuthOptions options = provider.GetRequiredService<IOptions<ReusableAuthOptions>>().Value;

        Assert.Equal(TimeSpan.FromHours(4.5), options.SessionLifetime);
        Assert.Equal(TimeSpan.FromMinutes(15), options.PasswordResetTokenLifetime);
        Assert.Equal(SameSiteMode.Strict, options.CookieSameSite);
    }

    [Fact]
    public void UnsetKeys_KeepTheirSecureDefaults()
    {
        // A config file that mentions one setting must not blank out the rest.
        IConfiguration configuration = ConfigurationFrom(new() { ["PasswordMinimumLength"] = "20" });

        using ServiceProvider provider = Build(configuration);
        ReusableAuthOptions options = provider.GetRequiredService<IOptions<ReusableAuthOptions>>().Value;

        Assert.Equal("__Host-auth", options.CookieName);
        Assert.Equal(TimeSpan.FromHours(8), options.SessionLifetime);
        Assert.True(options.RequireConfirmedEmail);
        Assert.Equal(TimeSpan.FromMinutes(1), options.SecurityStampValidationInterval);
    }

    [Fact]
    public void Code_BeatsConfiguration()
    {
        IConfiguration configuration = ConfigurationFrom(new() { ["PasswordMinimumLength"] = "20" });

        using ServiceProvider provider = Build(configuration, o => o.PasswordMinimumLength = 30);

        // The delegate runs after the bind, so a host that sets something in code means it.
        Assert.Equal(30, provider.GetRequiredService<IOptions<ReusableAuthOptions>>().Value.PasswordMinimumLength);
    }

    [Fact]
    public void BoundSettings_ReachIdentity()
    {
        // Binding an options object nothing reads would prove nothing.
        IConfiguration configuration = ConfigurationFrom(new()
        {
            ["PasswordMinimumLength"] = "20",
            ["LockoutMaxFailedAttempts"] = "3",
        });

        using ServiceProvider provider = Build(configuration);
        IdentityOptions identity = provider.GetRequiredService<IOptions<IdentityOptions>>().Value;

        Assert.Equal(20, identity.Password.RequiredLength);
        Assert.Equal(3, identity.Lockout.MaxFailedAccessAttempts);
    }

    [Fact]
    public void AWeakenedConfigurationFile_FailsAtStartup()
    {
        // The same gate as code: a config file cannot smuggle in a setup that a line of code
        // would have been rejected for.
        IConfiguration configuration = ConfigurationFrom(new() { ["PasswordMinimumLength"] = "4" });

        using ServiceProvider provider = Build(configuration);

        Assert.Throws<OptionsValidationException>(
            () => provider.GetRequiredService<IOptions<ReusableAuthOptions>>().Value);
    }

    [Fact]
    public void AContradictoryConfigurationFile_FailsAtStartup()
    {
        IConfiguration configuration = ConfigurationFrom(new() { ["CookieDomain"] = "example.com" });

        using ServiceProvider provider = Build(configuration);

        // __Host- prefixed cookie plus a Domain: browsers would ignore the cookie entirely.
        Assert.Throws<OptionsValidationException>(
            () => provider.GetRequiredService<IOptions<ReusableAuthOptions>>().Value);
    }

    [Fact]
    public void NullConfiguration_Throws()
    {
        ServiceCollection services = new();

        Assert.Throws<ArgumentNullException>(
            () => services.AddReusableAuth((IConfiguration)null!));
    }

    [Fact]
    public void ChangingConfigurationAtRuntime_DoesNothing_UntilRestart()
    {
        // This is the documented limit, asserted rather than merely claimed.
        //
        // The framework reads its own options through IOptions<T>, which resolves once and
        // caches for the life of the process: UserManager captures the password and lockout
        // policy in its constructor, SecurityStampValidator captures its interval, and the
        // antiforgery service is a singleton holding a copy. Reloading configuration cannot
        // reach any of them (dotnet/aspnetcore#55162). If this test ever starts failing, the
        // framework has been fixed and the docs saying "restart required" are now wrong.
        Dictionary<string, string?> values = new() { ["PasswordMinimumLength"] = "20" };
        IConfigurationRoot configuration = new ConfigurationBuilder().AddInMemoryCollection(values).Build();

        ServiceCollection services = new();
        services.AddLogging();
        services.AddReusableAuth(configuration);
        services.AddSingleton<IUserStore<ReusableAuthUser>, StampAwareUserStore>();
        services.AddSingleton<IRoleStore<IdentityRole>, InMemoryRoleStore>();

        using ServiceProvider provider = services.BuildServiceProvider();

        Assert.Equal(20, provider.GetRequiredService<IOptions<ReusableAuthOptions>>().Value.PasswordMinimumLength);

        // Change the source and force a reload, exactly as editing appsettings.json would.
        configuration["PasswordMinimumLength"] = "25";
        configuration.Reload();

        Assert.Equal("25", configuration["PasswordMinimumLength"]);

        // ...and the auth stack neither knows nor cares.
        Assert.Equal(20, provider.GetRequiredService<IOptions<ReusableAuthOptions>>().Value.PasswordMinimumLength);
        Assert.Equal(20, provider.GetRequiredService<IOptions<IdentityOptions>>().Value.Password.RequiredLength);
    }
}
