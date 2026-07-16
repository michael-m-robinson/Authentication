using Authentication;
using Authentication.Tests.Fakes;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Authentication.Tests;

/// <summary>
/// Covers the reset/confirmation token lifetime split.
/// </summary>
/// <remarks>
/// Identity points email confirmation, password reset and change-email at one shared
/// provider with a single lifespan, so a reset link would live as long as a confirmation
/// link — a day — unless reset gets a provider of its own. These tests exist because the
/// XML docs promise callers an hour, and a promise nothing enforces is worse than no
/// promise.
/// </remarks>
public class TokenLifetimeTests
{
    private static ServiceProvider Build(Action<ReusableAuthOptions>? configure = null)
    {
        ServiceCollection services = new();
        services.AddLogging();
        services.AddDataProtection();
        services.AddReusableAuth(configure);
        services.AddSingleton<IUserStore<ReusableAuthUser>, InMemoryUserStore>();
        services.AddSingleton<IRoleStore<IdentityRole>, InMemoryRoleStore>();
        services.AddSingleton<IAuthEmailSender, RecordingEmailSender>();
        return services.BuildServiceProvider();
    }

    [Fact]
    public void ResetTokens_LiveForOneHour_NotIdentitysDay()
    {
        using ServiceProvider provider = Build();

        PasswordResetTokenProviderOptions reset =
            provider.GetRequiredService<IOptions<PasswordResetTokenProviderOptions>>().Value;

        Assert.Equal(TimeSpan.FromHours(1), reset.TokenLifespan);
    }

    [Fact]
    public void ConfirmationTokens_KeepIdentitysDay()
    {
        using ServiceProvider provider = Build();

        DataProtectionTokenProviderOptions confirmation =
            provider.GetRequiredService<IOptions<DataProtectionTokenProviderOptions>>().Value;

        Assert.Equal(TimeSpan.FromDays(1), confirmation.TokenLifespan);
    }

    [Fact]
    public void ResetAndConfirmation_ActuallyDiffer()
    {
        // The point of the whole exercise: had reset stayed on the default provider, both
        // of these would read 1 day and this test would fail.
        using ServiceProvider provider = Build();

        TimeSpan reset = provider.GetRequiredService<IOptions<PasswordResetTokenProviderOptions>>().Value.TokenLifespan;
        TimeSpan confirmation = provider.GetRequiredService<IOptions<DataProtectionTokenProviderOptions>>().Value.TokenLifespan;

        Assert.True(reset < confirmation, $"Reset ({reset}) must expire sooner than confirmation ({confirmation}).");
    }

    [Fact]
    public void ResetPurpose_UsesOurProvider_NotTheDefault()
    {
        // Lifespan on an options class nothing points at would prove nothing, so assert
        // the wiring: Identity must actually route the reset purpose through it.
        using ServiceProvider provider = Build();

        IdentityOptions identity = provider.GetRequiredService<IOptions<IdentityOptions>>().Value;

        Assert.Equal(
            ReusableAuthOptions.PasswordResetTokenProviderName,
            identity.Tokens.PasswordResetTokenProvider);
        Assert.NotEqual(TokenOptions.DefaultProvider, identity.Tokens.PasswordResetTokenProvider);

        Assert.True(
            identity.Tokens.ProviderMap.ContainsKey(ReusableAuthOptions.PasswordResetTokenProviderName),
            "The reset provider must be registered in Identity's provider map.");

        // Confirmation deliberately stays on the default provider.
        Assert.Equal(TokenOptions.DefaultProvider, identity.Tokens.EmailConfirmationTokenProvider);
    }

    [Fact]
    public void HostCanOverrideBothLifetimes()
    {
        using ServiceProvider provider = Build(o =>
        {
            o.PasswordResetTokenLifetime = TimeSpan.FromMinutes(15);
            o.EmailConfirmationTokenLifetime = TimeSpan.FromHours(12);
        });

        Assert.Equal(
            TimeSpan.FromMinutes(15),
            provider.GetRequiredService<IOptions<PasswordResetTokenProviderOptions>>().Value.TokenLifespan);
        Assert.Equal(
            TimeSpan.FromHours(12),
            provider.GetRequiredService<IOptions<DataProtectionTokenProviderOptions>>().Value.TokenLifespan);
    }

    [Fact]
    public void ResetProvider_UsesItsOwnDataProtectionPurpose()
    {
        // Name is the data-protection purpose string: a distinct one scopes the protector's
        // keys so a reset token cannot be unprotected by the default provider.
        using ServiceProvider provider = Build();

        string resetPurpose = provider.GetRequiredService<IOptions<PasswordResetTokenProviderOptions>>().Value.Name;
        string defaultPurpose = provider.GetRequiredService<IOptions<DataProtectionTokenProviderOptions>>().Value.Name;

        Assert.NotEqual(defaultPurpose, resetPurpose);
    }

    [Fact]
    public void NonPositiveTokenLifetimes_AreRejectedAtStartup()
    {
        using ServiceProvider provider = Build(o => o.PasswordResetTokenLifetime = TimeSpan.Zero);

        // A zero lifespan would expire every reset link the instant it was minted.
        Assert.Throws<OptionsValidationException>(
            () => provider.GetRequiredService<IOptions<ReusableAuthOptions>>().Value);
    }
}
