using Authentication;
using Authentication.Tests.Fakes;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Authentication.Tests;

/// <summary>
/// Covers a user changing their own account settings: email, phone, and two-factor.
/// </summary>
public sealed class AccountServiceTests : IDisposable
{
    private const string Password = "Correct-horse-9!";
    private const string Email = "person@example.com";

    private readonly ServiceProvider _provider;
    private readonly IServiceScope _scope;
    private readonly RecordingEmailSender _emails = new();
    private readonly TestBackgroundTaskQueue _queue = new();

    public AccountServiceTests()
    {
        ServiceCollection services = new();
        services.AddLogging();
        services.AddDataProtection();
        services.AddReusableAuth();
        services.AddSingleton<IUserStore<ReusableAuthUser>, InMemoryUserStore>();
        services.AddSingleton<IRoleStore<IdentityRole>, InMemoryRoleStore>();
        services.AddSingleton<IAuthEmailSender>(_emails);
        services.RemoveAll<IBackgroundTaskQueue>();
        services.AddSingleton<IBackgroundTaskQueue>(_queue);

        _provider = services.BuildServiceProvider();
        _scope = _provider.CreateScope();
    }

    private IAccountService Account => _scope.ServiceProvider.GetRequiredService<IAccountService>();

    private UserManager<ReusableAuthUser> Users =>
        _scope.ServiceProvider.GetRequiredService<UserManager<ReusableAuthUser>>();

    private async Task<ReusableAuthUser> SeedUserAsync(string email = Email)
    {
        ReusableAuthUser user = new() { UserName = email, Email = email, EmailConfirmed = true };
        IdentityResult created = await Users.CreateAsync(user, Password);
        Assert.True(created.Succeeded, string.Join(", ", created.Errors.Select(e => e.Description)));
        return user;
    }

    private async Task<string> StampOf(string userId)
        => await Users.GetSecurityStampAsync(await Users.FindByIdAsync(userId) ?? throw new InvalidOperationException());

    // ---- Change email --------------------------------------------------------------

    [Fact]
    public async Task RequestEmailChange_EmailsTheNewAddress_AndChangesNothingYet()
    {
        ReusableAuthUser user = await SeedUserAsync();

        AuthResult result = await Account.RequestEmailChangeAsync(user.Id, "new@example.com");
        await _queue.DrainAsync();

        Assert.Equal(AuthStatus.Succeeded, result.Status);
        Assert.Single(_emails.OfKind(EmailKind.Confirmation), e => e.Email == "new@example.com");

        // The address only moves once someone proves they hold the new inbox.
        Assert.Equal(Email, await Users.GetEmailAsync(await Users.FindByIdAsync(user.Id) ?? throw new InvalidOperationException()));
    }

    [Fact]
    public async Task RequestEmailChange_IsIndistinguishable_ForATakenAddress()
    {
        await SeedUserAsync("taken@example.com");
        ReusableAuthUser user = await SeedUserAsync();

        AuthResult taken = await Account.RequestEmailChangeAsync(user.Id, "taken@example.com");
        AuthResult free = await Account.RequestEmailChangeAsync(user.Id, "free@example.com");

        // This library requires unique emails, so saying "that address is taken" would let any
        // signed-in user enumerate the user base one address at a time.
        Assert.Equal(free.Status, taken.Status);
        Assert.Equal(AuthStatus.Succeeded, taken.Status);
    }

    [Fact]
    public async Task ConfirmEmailChange_MovesTheAddress_AndTheSignInIdentity()
    {
        ReusableAuthUser user = await SeedUserAsync();
        await Account.RequestEmailChangeAsync(user.Id, "new@example.com");
        await _queue.DrainAsync();
        SentEmail sent = _emails.OfKind(EmailKind.Confirmation).Single();

        AuthResult result = await Account.ConfirmEmailChangeAsync(user.Id, "new@example.com", sent.Token!);

        Assert.Equal(AuthStatus.Succeeded, result.Status);

        ReusableAuthUser updated = await Users.FindByIdAsync(user.Id) ?? throw new InvalidOperationException();
        Assert.Equal("new@example.com", await Users.GetEmailAsync(updated));

        // The user name must move too: it is the sign-in identity here, and Identity's
        // ChangeEmailAsync only touches Email. Leaving it behind means they keep signing in
        // with the old address.
        Assert.Equal("new@example.com", await Users.GetUserNameAsync(updated));
        Assert.NotNull(await Users.FindByEmailAsync("new@example.com"));
    }

    [Fact]
    public async Task ConfirmEmailChange_MarksTheNewAddressConfirmed()
    {
        ReusableAuthUser user = await SeedUserAsync();
        await Account.RequestEmailChangeAsync(user.Id, "new@example.com");
        await _queue.DrainAsync();
        SentEmail sent = _emails.OfKind(EmailKind.Confirmation).Single();

        await Account.ConfirmEmailChangeAsync(user.Id, "new@example.com", sent.Token!);

        // Clicking the link IS the proof; requiring a second confirmation would be theatre.
        Assert.True(await Users.IsEmailConfirmedAsync(await Users.FindByIdAsync(user.Id) ?? throw new InvalidOperationException()));
    }

    [Fact]
    public async Task ConfirmEmailChange_InvalidatesOtherSessions()
    {
        ReusableAuthUser user = await SeedUserAsync();
        await Account.RequestEmailChangeAsync(user.Id, "new@example.com");
        await _queue.DrainAsync();
        SentEmail sent = _emails.OfKind(EmailKind.Confirmation).Single();
        string before = await StampOf(user.Id);

        await Account.ConfirmEmailChangeAsync(user.Id, "new@example.com", sent.Token!);

        // Their sign-in identity just changed; Identity bumps the stamp itself here.
        Assert.NotEqual(before, await StampOf(user.Id));
    }

    [Fact]
    public async Task ConfirmEmailChange_Fails_WhenTheTokenIsForADifferentAddress()
    {
        ReusableAuthUser user = await SeedUserAsync();
        await Account.RequestEmailChangeAsync(user.Id, "wanted@example.com");
        await _queue.DrainAsync();
        SentEmail sent = _emails.OfKind(EmailKind.Confirmation).Single();

        // The token is purpose-bound to the address it was minted for, so it cannot be
        // replayed to claim a different one.
        AuthResult result = await Account.ConfirmEmailChangeAsync(user.Id, "other@example.com", sent.Token!);

        Assert.Equal(AuthStatus.Failed, result.Status);
    }

    [Fact]
    public async Task ConfirmEmailChange_Fails_ForATakenAddress_Generically()
    {
        await SeedUserAsync("taken@example.com");
        ReusableAuthUser user = await SeedUserAsync();
        await Account.RequestEmailChangeAsync(user.Id, "taken@example.com");
        await _queue.DrainAsync();
        SentEmail sent = _emails.OfKind(EmailKind.Confirmation).Single();

        AuthResult result = await Account.ConfirmEmailChangeAsync(user.Id, "taken@example.com", sent.Token!);

        // Refused, and refused without saying the address belongs to someone else.
        Assert.Equal(AuthStatus.Failed, result.Status);
        Assert.Empty(result.Errors);

        // Whether the change reaches the database is a store question this fake cannot
        // answer - it hands out the same object Identity mutated before validation failed,
        // so the mutation is visible here even though nothing was persisted. Asserted
        // against the real store in Authentication.EntityFrameworkCore.Tests instead.
    }

    [Fact]
    public async Task ConfirmEmailChange_Fails_OnAGarbledToken()
    {
        ReusableAuthUser user = await SeedUserAsync();

        Assert.Equal(
            AuthStatus.Failed,
            (await Account.ConfirmEmailChangeAsync(user.Id, "new@example.com", "not-a-token")).Status);
    }

    [Fact]
    public async Task RequestEmailChange_IsRejected_ForAnUnknownUserOrEmptyAddress()
    {
        ReusableAuthUser user = await SeedUserAsync();

        Assert.Equal(AuthStatus.Rejected, (await Account.RequestEmailChangeAsync("no-such-id", "new@example.com")).Status);
        Assert.Equal(AuthStatus.Rejected, (await Account.RequestEmailChangeAsync(user.Id, "  ")).Status);
    }

    // ---- Phone ---------------------------------------------------------------------

    [Fact]
    public async Task SetPhoneNumber_StoresIt_Unverified()
    {
        ReusableAuthUser user = await SeedUserAsync();

        AuthResult result = await Account.SetPhoneNumberAsync(user.Id, "+44 7700 900000");

        Assert.Equal(AuthStatus.Succeeded, result.Status);

        ReusableAuthUser updated = await Users.FindByIdAsync(user.Id) ?? throw new InvalidOperationException();
        Assert.Equal("+44 7700 900000", await Users.GetPhoneNumberAsync(updated));

        // Documented and asserted: nothing here proves the user owns this number, so it must
        // never be treated as a second factor or a recovery channel.
        Assert.False(await Users.IsPhoneNumberConfirmedAsync(updated));
    }

    [Fact]
    public async Task SetPhoneNumber_CanClearIt()
    {
        ReusableAuthUser user = await SeedUserAsync();
        await Account.SetPhoneNumberAsync(user.Id, "+44 7700 900000");

        Assert.Equal(AuthStatus.Succeeded, (await Account.SetPhoneNumberAsync(user.Id, null)).Status);
        Assert.Null(await Users.GetPhoneNumberAsync(await Users.FindByIdAsync(user.Id) ?? throw new InvalidOperationException()));
    }

    [Fact]
    public async Task SetPhoneNumber_IsRejected_ForAnUnknownUser()
    {
        Assert.Equal(AuthStatus.Rejected, (await Account.SetPhoneNumberAsync("no-such-id", "+44 7700 900000")).Status);
    }

    // ---- Two-factor setup -----------------------------------------------------------

    [Fact]
    public async Task BeginTwoFactorSetup_ReturnsAKeyAndAScannableUri()
    {
        ReusableAuthUser user = await SeedUserAsync();

        TwoFactorSetup? setup = await Account.BeginTwoFactorSetupAsync(user.Id);

        Assert.NotNull(setup);
        Assert.NotEmpty(setup.SharedKey);

        // The shape every authenticator app parses, taken from Microsoft's own setup page.
        Assert.StartsWith("otpauth://totp/", setup.AuthenticatorUri, StringComparison.Ordinal);
        Assert.Contains("secret=", setup.AuthenticatorUri, StringComparison.Ordinal);
        Assert.Contains("digits=6", setup.AuthenticatorUri, StringComparison.Ordinal);

        // Issuer appears twice by design: as the label prefix and as the issuer parameter.
        Assert.Contains($"otpauth://totp/ReusableAuth:{Email}", setup.AuthenticatorUri, StringComparison.Ordinal);
        Assert.Contains("issuer=ReusableAuth", setup.AuthenticatorUri, StringComparison.Ordinal);
    }

    [Fact]
    public async Task BeginTwoFactorSetup_UsesTheConfiguredIssuer()
    {
        // What the user reads in their authenticator app when picking which code is ours.
        ServiceCollection services = new();
        services.AddLogging();
        services.AddDataProtection();
        services.AddReusableAuth(o => o.AuthenticatorIssuer = "Contoso Bank");
        services.AddSingleton<IUserStore<ReusableAuthUser>, InMemoryUserStore>();
        services.AddSingleton<IRoleStore<IdentityRole>, InMemoryRoleStore>();
        services.AddSingleton<IAuthEmailSender>(_emails);

        using ServiceProvider provider = services.BuildServiceProvider();
        using IServiceScope scope = provider.CreateScope();

        UserManager<ReusableAuthUser> users = scope.ServiceProvider.GetRequiredService<UserManager<ReusableAuthUser>>();
        ReusableAuthUser user = new() { UserName = Email, Email = Email, EmailConfirmed = true };
        await users.CreateAsync(user, Password);

        TwoFactorSetup? setup = await scope.ServiceProvider
            .GetRequiredService<IAccountService>()
            .BeginTwoFactorSetupAsync(user.Id);

        Assert.NotNull(setup);
        Assert.Contains("issuer=Contoso%20Bank", setup.AuthenticatorUri, StringComparison.Ordinal);
    }

    [Fact]
    public async Task BeginTwoFactorSetup_IsStable_AcrossRepeatedCalls()
    {
        ReusableAuthUser user = await SeedUserAsync();

        TwoFactorSetup? first = await Account.BeginTwoFactorSetupAsync(user.Id);
        TwoFactorSetup? second = await Account.BeginTwoFactorSetupAsync(user.Id);

        // Re-issuing the key here would silently break an authenticator app the user had
        // already added while fumbling the setup page.
        Assert.Equal(first!.SharedKey, second!.SharedKey);
    }

    [Fact]
    public async Task BeginTwoFactorSetup_DoesNotEnableIt()
    {
        ReusableAuthUser user = await SeedUserAsync();

        await Account.BeginTwoFactorSetupAsync(user.Id);

        Assert.False(await Account.IsTwoFactorEnabledAsync(user.Id));
    }

    [Fact]
    public async Task BeginTwoFactorSetup_IsNull_ForAnUnknownUser()
    {
        Assert.Null(await Account.BeginTwoFactorSetupAsync("no-such-id"));
    }

    // ---- Enabling two-factor ---------------------------------------------------------

    [Fact]
    public async Task EnableTwoFactor_Works_WithARealCodeFromTheKey()
    {
        // The round-trip that matters: a code generated from the shared key we handed out
        // must actually enable two-factor. If this fails, the QR code we render is useless.
        ReusableAuthUser user = await SeedUserAsync();
        await Account.BeginTwoFactorSetupAsync(user.Id);

        string code = await GenerateAuthenticatorCodeAsync(user);
        AuthResult result = await Account.EnableTwoFactorAsync(user.Id, code);

        Assert.Equal(AuthStatus.Succeeded, result.Status);
        Assert.True(await Account.IsTwoFactorEnabledAsync(user.Id));
    }

    [Fact]
    public async Task EnableTwoFactor_AcceptsACodeWithSpacesOrDashes()
    {
        ReusableAuthUser user = await SeedUserAsync();
        await Account.BeginTwoFactorSetupAsync(user.Id);
        string code = await GenerateAuthenticatorCodeAsync(user);

        // Authenticator apps display "123 456"; people paste what they see.
        AuthResult result = await Account.EnableTwoFactorAsync(user.Id, $"{code[..3]} {code[3..]}");

        Assert.Equal(AuthStatus.Succeeded, result.Status);
    }

    [Fact]
    public async Task EnableTwoFactor_IsRejected_ForAWrongCode_AndStaysOff()
    {
        ReusableAuthUser user = await SeedUserAsync();
        await Account.BeginTwoFactorSetupAsync(user.Id);

        AuthResult result = await Account.EnableTwoFactorAsync(user.Id, "000000");

        // Enabling on an unverified app would lock the user out of their own account.
        Assert.Equal(AuthStatus.Rejected, result.Status);
        Assert.NotEmpty(result.Errors);
        Assert.False(await Account.IsTwoFactorEnabledAsync(user.Id));
    }

    [Fact]
    public async Task EnableTwoFactor_IsRejected_ForAnEmptyCodeOrUnknownUser()
    {
        ReusableAuthUser user = await SeedUserAsync();

        Assert.Equal(AuthStatus.Rejected, (await Account.EnableTwoFactorAsync(user.Id, "  ")).Status);
        Assert.Equal(AuthStatus.Rejected, (await Account.EnableTwoFactorAsync("no-such-id", "123456")).Status);
    }

    // ---- Disabling and resetting -----------------------------------------------------

    [Fact]
    public async Task DisableTwoFactor_TurnsItOff_ButKeepsTheKey()
    {
        ReusableAuthUser user = await SeedUserAsync();
        TwoFactorSetup? setup = await Account.BeginTwoFactorSetupAsync(user.Id);
        await Account.EnableTwoFactorAsync(user.Id, await GenerateAuthenticatorCodeAsync(user));

        Assert.Equal(AuthStatus.Succeeded, (await Account.DisableTwoFactorAsync(user.Id)).Status);
        Assert.False(await Account.IsTwoFactorEnabledAsync(user.Id));

        // Identity's behaviour, matched: re-enabling should work with the app they already
        // added. ResetAuthenticatorKeyAsync is the one that cuts it off.
        TwoFactorSetup? after = await Account.BeginTwoFactorSetupAsync(user.Id);
        Assert.Equal(setup!.SharedKey, after!.SharedKey);
    }

    [Fact]
    public async Task ResetAuthenticatorKey_ReplacesTheKey_AndTurnsTwoFactorOff()
    {
        ReusableAuthUser user = await SeedUserAsync();
        TwoFactorSetup? before = await Account.BeginTwoFactorSetupAsync(user.Id);
        await Account.EnableTwoFactorAsync(user.Id, await GenerateAuthenticatorCodeAsync(user));

        AuthResult result = await Account.ResetAuthenticatorKeyAsync(user.Id);

        Assert.Equal(AuthStatus.Succeeded, result.Status);

        // Off, necessarily: leaving it on with a key nobody holds would lock the account.
        Assert.False(await Account.IsTwoFactorEnabledAsync(user.Id));

        TwoFactorSetup? after = await Account.BeginTwoFactorSetupAsync(user.Id);
        Assert.NotEqual(before!.SharedKey, after!.SharedKey);
    }

    [Fact]
    public async Task ResetAuthenticatorKey_InvalidatesOtherSessions()
    {
        ReusableAuthUser user = await SeedUserAsync();
        await Account.BeginTwoFactorSetupAsync(user.Id);
        string before = await StampOf(user.Id);

        await Account.ResetAuthenticatorKeyAsync(user.Id);

        // Identity bumps the stamp on both SetTwoFactorEnabledAsync and
        // ResetAuthenticatorKeyAsync, so this needs no help from us.
        Assert.NotEqual(before, await StampOf(user.Id));
    }

    // ---- Recovery codes --------------------------------------------------------------

    [Fact]
    public async Task GenerateRecoveryCodes_IssuesTenByDefault()
    {
        ReusableAuthUser user = await SeedUserAsync();

        IReadOnlyList<string> codes = await Account.GenerateRecoveryCodesAsync(user.Id);

        Assert.Equal(10, codes.Count);
        Assert.Equal(10, codes.Distinct(StringComparer.Ordinal).Count());
        Assert.Equal(10, await Account.CountRecoveryCodesAsync(user.Id));
    }

    [Fact]
    public async Task GenerateRecoveryCodes_ReplacesAnyEarlierSet()
    {
        ReusableAuthUser user = await SeedUserAsync();
        IReadOnlyList<string> first = await Account.GenerateRecoveryCodesAsync(user.Id, 3);

        IReadOnlyList<string> second = await Account.GenerateRecoveryCodesAsync(user.Id, 3);

        // A user still holding the old list will find it dead - worth being sure of, since
        // it is what the docs promise.
        Assert.Empty(first.Intersect(second, StringComparer.Ordinal));
        Assert.Equal(3, await Account.CountRecoveryCodesAsync(user.Id));
    }

    [Fact]
    public async Task RecoveryCodes_AreEmpty_ForAnUnknownUser()
    {
        Assert.Empty(await Account.GenerateRecoveryCodesAsync("no-such-id"));
        Assert.Equal(0, await Account.CountRecoveryCodesAsync("no-such-id"));
    }

    /// <summary>
    /// Produces a code exactly as an authenticator app would, from the key we handed the user.
    /// </summary>
    /// <remarks>
    /// Not via <c>UserManager.GenerateTwoFactorTokenAsync</c>: for the authenticator provider
    /// that returns an empty string, because the server is not supposed to be able to produce
    /// these codes; only the user's device can. Verifying "" would pass for the wrong reason
    /// and prove nothing about the key we handed out.
    /// </remarks>
    private async Task<string> GenerateAuthenticatorCodeAsync(ReusableAuthUser user)
    {
        ReusableAuthUser reloaded = await Users.FindByIdAsync(user.Id) ?? throw new InvalidOperationException();
        string key = await Users.GetAuthenticatorKeyAsync(reloaded) ?? throw new InvalidOperationException();

        return TestAuthenticator.Generate(key);
    }

    public void Dispose()
    {
        _scope.Dispose();
        _provider.Dispose();
    }
}
