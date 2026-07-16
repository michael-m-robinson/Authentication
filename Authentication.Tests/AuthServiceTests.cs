using Authentication;
using Authentication.Tests.Fakes;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Authentication.Tests;

/// <summary>
/// Covers the behaviour that makes <see cref="AuthService{TUser}"/> worth having: a
/// caller must not be able to learn whether an account exists, and a privilege change
/// must invalidate sessions.
/// </summary>
public sealed class AuthServiceTests : IDisposable
{
    private const string Password = "Correct-horse-9!";
    private const string Existing = "taken@example.com";

    private readonly ServiceProvider _provider;
    private readonly IServiceScope _scope;
    private readonly RecordingEmailSender _emails = new();
    private readonly TestBackgroundTaskQueue _queue = new();

    public AuthServiceTests()
    {
        ServiceCollection services = new();
        services.AddLogging();
        services.AddDataProtection();
        services.AddReusableAuth();
        services.AddSingleton<IUserStore<ReusableAuthUser>, InMemoryUserStore>();
        services.AddSingleton<IRoleStore<IdentityRole>, InMemoryRoleStore>();
        services.AddSingleton<IAuthEmailSender>(_emails);

        // Swap the real queue for one the test drains by hand, so the background work is
        // observable without racing a hosted service.
        services.RemoveAll<IBackgroundTaskQueue>();
        services.AddSingleton<IBackgroundTaskQueue>(_queue);

        _provider = services.BuildServiceProvider();
        _scope = _provider.CreateScope();
    }

    private IAuthService Auth => _scope.ServiceProvider.GetRequiredService<IAuthService>();

    private UserManager<ReusableAuthUser> Users =>
        _scope.ServiceProvider.GetRequiredService<UserManager<ReusableAuthUser>>();

    private async Task<ReusableAuthUser> SeedConfirmedUserAsync(string email = Existing)
    {
        ReusableAuthUser user = new() { UserName = email, Email = email, EmailConfirmed = true };
        IdentityResult created = await Users.CreateAsync(user, Password);
        Assert.True(created.Succeeded, string.Join(", ", created.Errors.Select(e => e.Description)));
        return user;
    }

    // ---- Registration: must not disclose that an address is taken -------------------

    [Fact]
    public async Task Register_ReportsSuccess_ForAnAlreadyRegisteredAddress()
    {
        await SeedConfirmedUserAsync();

        AuthResult result = await Auth.RegisterAsync(Existing, "Different-pass-1!");

        // Identity would hand back DuplicateEmail here. Surfacing it would confirm the
        // account exists, so the caller sees exactly what a new registration sees.
        Assert.Equal(AuthStatus.Succeeded, result.Status);
    }

    [Fact]
    public async Task Register_IsIndistinguishable_BetweenTakenAndFreeAddresses()
    {
        await SeedConfirmedUserAsync();

        AuthResult taken = await Auth.RegisterAsync(Existing, "Different-pass-1!");
        AuthResult free = await Auth.RegisterAsync("brand-new@example.com", Password);

        Assert.Equal(free.Status, taken.Status);
        Assert.Equal(free.Errors, taken.Errors);
    }

    [Fact]
    public async Task Register_NotifiesTheOwner_RatherThanTheCaller()
    {
        await SeedConfirmedUserAsync();

        await Auth.RegisterAsync(Existing, "Different-pass-1!");
        await _queue.DrainAsync();

        // The owner is told over a channel that already proves they own the address.
        Assert.Single(_emails.OfKind(EmailKind.RegistrationAttempted), e => e.Email == Existing);
        Assert.Empty(_emails.OfKind(EmailKind.Confirmation));
    }

    [Fact]
    public async Task Register_DoesNotCreateASecondAccount_ForATakenAddress()
    {
        ReusableAuthUser original = await SeedConfirmedUserAsync();

        await Auth.RegisterAsync(Existing, "Different-pass-1!");

        // Reporting success must not mean it quietly registered a duplicate, nor that the
        // existing account's password was overwritten by the attacker's.
        Assert.Single(await FindAllByEmailAsync(Existing));
        Assert.True(await Users.CheckPasswordAsync(original, Password));
    }

    [Fact]
    public async Task Register_CreatesAccountAndSendsConfirmation_ForAFreeAddress()
    {
        AuthResult result = await Auth.RegisterAsync("fresh@example.com", Password);
        await _queue.DrainAsync();

        Assert.Equal(AuthStatus.Succeeded, result.Status);
        Assert.Single(_emails.OfKind(EmailKind.Confirmation), e => e.Email == "fresh@example.com");
    }

    [Fact]
    public async Task Register_ReportsAWeakPassword()
    {
        // A policy failure describes the password just typed, not who is registered, so
        // it leaks nothing and is worth telling the caller.
        AuthResult result = await Auth.RegisterAsync("fresh@example.com", "short");

        Assert.Equal(AuthStatus.PasswordRejected, result.Status);
        Assert.NotEmpty(result.Errors);
    }

    [Fact]
    public async Task Register_ReportsAWeakPassword_EvenForATakenAddress()
    {
        await SeedConfirmedUserAsync();

        // Still no disclosure: the answer depends on the password, not on the address.
        AuthResult result = await Auth.RegisterAsync(Existing, "short");

        Assert.Equal(AuthStatus.PasswordRejected, result.Status);
    }

    // ---- Sign-in: every failure looks the same -------------------------------------

    [Fact]
    public async Task SignIn_Fails_ForAnUnknownAddress()
    {
        AuthResult result = await Auth.SignInAsync("nobody@example.com", Password);

        Assert.Equal(AuthStatus.Failed, result.Status);
    }

    [Fact]
    public async Task SignIn_Fails_ForAWrongPassword()
    {
        await SeedConfirmedUserAsync();

        AuthResult result = await Auth.SignInAsync(Existing, "Wrong-password-1!");

        Assert.Equal(AuthStatus.Failed, result.Status);
    }

    [Fact]
    public async Task SignIn_UnknownAddressAndWrongPassword_AreIndistinguishable()
    {
        await SeedConfirmedUserAsync();

        AuthResult unknown = await Auth.SignInAsync("nobody@example.com", Password);
        AuthResult wrong = await Auth.SignInAsync(Existing, "Wrong-password-1!");

        Assert.Equal(unknown.Status, wrong.Status);
    }

    [Fact]
    public async Task SignIn_HidesLockout()
    {
        ReusableAuthUser user = await SeedConfirmedUserAsync();
        await Users.SetLockoutEndDateAsync(user, DateTimeOffset.UtcNow.AddHours(1));

        AuthResult lockedOut = await Auth.SignInAsync(Existing, Password);
        AuthResult unknown = await Auth.SignInAsync("nobody@example.com", Password);

        // Identity returns IsLockedOut here, and does so BEFORE checking the password -
        // so passing it through would tell someone who does not know the password that
        // the account exists.
        Assert.Equal(AuthStatus.Failed, lockedOut.Status);
        Assert.Equal(unknown.Status, lockedOut.Status);
    }

    [Fact]
    public async Task SignIn_HidesUnconfirmedAccounts()
    {
        ReusableAuthUser user = new() { UserName = "unconfirmed@example.com", Email = "unconfirmed@example.com" };
        await Users.CreateAsync(user, Password);

        AuthResult notAllowed = await Auth.SignInAsync("unconfirmed@example.com", Password);
        AuthResult unknown = await Auth.SignInAsync("nobody@example.com", Password);

        // Identity returns IsNotAllowed, which likewise proves the account exists.
        Assert.Equal(AuthStatus.Failed, notAllowed.Status);
        Assert.Equal(unknown.Status, notAllowed.Status);
    }

    [Fact]
    public async Task SignIn_StillLocksOut_EvenThoughItNeverSaysSo()
    {
        ReusableAuthUser user = await SeedConfirmedUserAsync();

        for (int attempt = 0; attempt < 5; attempt++)
        {
            await Auth.SignInAsync(Existing, "Wrong-password-1!");
        }

        // Silence is not inaction: the protection still applies, it is just not announced.
        Assert.True(await Users.IsLockedOutAsync(await Users.FindByIdAsync(user.Id) ?? user));
    }

    [Theory]
    [InlineData("", Password)]
    [InlineData(Existing, "")]
    [InlineData("   ", "   ")]
    public async Task SignIn_Fails_OnEmptyInput(string email, string password)
    {
        AuthResult result = await Auth.SignInAsync(email, password);

        Assert.Equal(AuthStatus.Failed, result.Status);
    }

    // ---- Password reset: the request tells the caller nothing -----------------------

    [Fact]
    public async Task RequestPasswordReset_ReportsSuccess_ForAnUnknownAddress()
    {
        AuthResult result = await Auth.RequestPasswordResetAsync("nobody@example.com");
        await _queue.DrainAsync();

        Assert.Equal(AuthStatus.Succeeded, result.Status);
        Assert.Empty(_emails.OfKind(EmailKind.PasswordReset));
    }

    [Fact]
    public async Task RequestPasswordReset_DoesNoAccountWork_OnTheCallingThread()
    {
        await SeedConfirmedUserAsync();

        AuthResult known = await Auth.RequestPasswordResetAsync(Existing);
        AuthResult unknown = await Auth.RequestPasswordResetAsync("nobody@example.com");

        // Both merely queue. If either had looked the address up or awaited an email, a
        // registered address would answer measurably slower than an unknown one - the
        // enumeration leak the identical response body is meant to prevent.
        Assert.Equal(unknown.Status, known.Status);
        Assert.Equal(2, _queue.PendingCount);
        Assert.Empty(_emails.Sent);
    }

    [Fact]
    public async Task RequestPasswordReset_SendsALink_ForAConfirmedAccount()
    {
        await SeedConfirmedUserAsync();

        await Auth.RequestPasswordResetAsync(Existing);
        await _queue.DrainAsync();

        Assert.Single(_emails.OfKind(EmailKind.PasswordReset), e => e.Email == Existing);
    }

    [Fact]
    public async Task RequestPasswordReset_SendsNothing_ForAnUnconfirmedAccount()
    {
        ReusableAuthUser user = new() { UserName = "unconfirmed@example.com", Email = "unconfirmed@example.com" };
        await Users.CreateAsync(user, Password);

        await Auth.RequestPasswordResetAsync("unconfirmed@example.com");
        await _queue.DrainAsync();

        Assert.Empty(_emails.OfKind(EmailKind.PasswordReset));
    }

    // ---- Reset round-trip, including the token encoding -----------------------------

    [Fact]
    public async Task ResetPassword_Succeeds_WithTheEmailedToken()
    {
        await SeedConfirmedUserAsync();
        await Auth.RequestPasswordResetAsync(Existing);
        await _queue.DrainAsync();

        SentEmail sent = _emails.OfKind(EmailKind.PasswordReset).Single();

        // The token goes out URL-safe and comes back in that form: the library owns both
        // halves of the encoding, so this round-trip is the contract.
        AuthResult result = await Auth.ResetPasswordAsync(sent.UserId!, sent.Token!, "Brand-new-pass-2!");

        Assert.Equal(AuthStatus.Succeeded, result.Status);
        Assert.True(await Users.CheckPasswordAsync(await Users.FindByIdAsync(sent.UserId!) ?? throw new InvalidOperationException(), "Brand-new-pass-2!"));
    }

    [Fact]
    public async Task ResetPassword_Fails_OnAGarbledToken()
    {
        ReusableAuthUser user = await SeedConfirmedUserAsync();

        AuthResult result = await Auth.ResetPasswordAsync(user.Id, "not-a-real-token", "Brand-new-pass-2!");

        // Malformed, expired and forged must be indistinguishable, and none may throw.
        Assert.Equal(AuthStatus.Failed, result.Status);
    }

    [Fact]
    public async Task ResetPassword_Fails_ForAnUnknownUser()
    {
        AuthResult result = await Auth.ResetPasswordAsync("no-such-id", "token", "Brand-new-pass-2!");

        Assert.Equal(AuthStatus.Failed, result.Status);
    }

    [Fact]
    public async Task ResetPassword_ReportsAWeakPassword_RatherThanAGenericFailure()
    {
        await SeedConfirmedUserAsync();
        await Auth.RequestPasswordResetAsync(Existing);
        await _queue.DrainAsync();
        SentEmail sent = _emails.OfKind(EmailKind.PasswordReset).Single();

        AuthResult result = await Auth.ResetPasswordAsync(sent.UserId!, sent.Token!, "short");

        // Identity blends policy errors and InvalidToken into one result; the policy is
        // pre-checked so someone holding a good link learns why their password bounced.
        Assert.Equal(AuthStatus.PasswordRejected, result.Status);
    }

    [Fact]
    public async Task ResetPassword_BurnsTheToken()
    {
        await SeedConfirmedUserAsync();
        await Auth.RequestPasswordResetAsync(Existing);
        await _queue.DrainAsync();
        SentEmail sent = _emails.OfKind(EmailKind.PasswordReset).Single();

        await Auth.ResetPasswordAsync(sent.UserId!, sent.Token!, "Brand-new-pass-2!");
        AuthResult replay = await Auth.ResetPasswordAsync(sent.UserId!, sent.Token!, "Third-password-3!");

        // A successful reset rotates the security stamp, and the stamp is baked into the
        // token - so the link cannot be replayed.
        Assert.Equal(AuthStatus.Failed, replay.Status);
    }

    // ---- Email confirmation --------------------------------------------------------

    [Fact]
    public async Task ConfirmEmail_Succeeds_WithTheEmailedToken()
    {
        await Auth.RegisterAsync("fresh@example.com", Password);
        await _queue.DrainAsync();
        SentEmail sent = _emails.OfKind(EmailKind.Confirmation).Single();

        AuthResult result = await Auth.ConfirmEmailAsync(sent.UserId!, sent.Token!);

        Assert.Equal(AuthStatus.Succeeded, result.Status);
        Assert.True(await Users.IsEmailConfirmedAsync(await Users.FindByIdAsync(sent.UserId!) ?? throw new InvalidOperationException()));
    }

    [Fact]
    public async Task ConfirmEmail_RotatesTheSecurityStamp()
    {
        await Auth.RegisterAsync("fresh@example.com", Password);
        await _queue.DrainAsync();
        SentEmail sent = _emails.OfKind(EmailKind.Confirmation).Single();
        string before = await Users.GetSecurityStampAsync(await Users.FindByIdAsync(sent.UserId!) ?? throw new InvalidOperationException());

        await Auth.ConfirmEmailAsync(sent.UserId!, sent.Token!);

        // Identity does NOT do this on its own. Confirmation changes what the account may
        // do, and PLAN.md makes rotation on a privilege change a v1 invariant, so any
        // session opened before confirmation must die.
        string after = await Users.GetSecurityStampAsync(await Users.FindByIdAsync(sent.UserId!) ?? throw new InvalidOperationException());
        Assert.NotEqual(before, after);
    }

    [Fact]
    public async Task ConfirmEmail_Fails_OnAGarbledToken()
    {
        ReusableAuthUser user = await SeedConfirmedUserAsync("someone@example.com");

        AuthResult result = await Auth.ConfirmEmailAsync(user.Id, "not-a-real-token");

        Assert.Equal(AuthStatus.Failed, result.Status);
    }

    [Fact]
    public async Task ConfirmEmail_Fails_ForAnUnknownUser()
    {
        AuthResult result = await Auth.ConfirmEmailAsync("no-such-id", "token");

        Assert.Equal(AuthStatus.Failed, result.Status);
    }

    // ---- Signed-out callers ---------------------------------------------------------

    [Fact]
    public void CurrentPrincipal_IsNull_WhenNobodyIsSignedIn()
    {
        Assert.Null(Auth.CurrentPrincipal);
    }

    [Fact]
    public async Task ChangePassword_Fails_WhenNobodyIsSignedIn()
    {
        AuthResult result = await Auth.ChangePasswordAsync(Password, "Brand-new-pass-2!");

        Assert.Equal(AuthStatus.Failed, result.Status);
    }

    [Fact]
    public async Task RotateSession_Fails_WhenNobodyIsSignedIn()
    {
        AuthResult result = await Auth.RotateSessionAsync();

        Assert.Equal(AuthStatus.Failed, result.Status);
    }

    [Fact]
    public async Task SignOut_IsANoOp_OffRequest()
    {
        // SignInManager reaches through HttpContext and throws without one; there is no
        // HttpContext in this scope, and signing out must not blow up regardless.
        await Auth.SignOutAsync();
    }

    private async Task<IReadOnlyList<ReusableAuthUser>> FindAllByEmailAsync(string email)
    {
        InMemoryUserStore store = (InMemoryUserStore)_scope.ServiceProvider
            .GetRequiredService<IUserStore<ReusableAuthUser>>();

        await Task.CompletedTask;
        return store.Users
            .Where(u => string.Equals(u.Email, email, StringComparison.OrdinalIgnoreCase))
            .ToList();
    }

    public void Dispose()
    {
        _scope.Dispose();
        _provider.Dispose();
    }
}
