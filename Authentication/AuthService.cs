using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Authentication;

/// <summary>
/// The default <see cref="IAuthService"/>, built on Identity's
/// <see cref="UserManager{TUser}"/> and <see cref="SignInManager{TUser}"/>.
/// </summary>
/// <typeparam name="TUser">The Identity user type.</typeparam>
/// <remarks>
/// Much of this class exists to undo Identity's default willingness to say whether an
/// account exists. Each such place is commented; none of them are incidental.
/// </remarks>
internal sealed class AuthService<TUser> : IAuthService
    where TUser : IdentityUser<string>, new()
{
    private readonly UserManager<TUser> _userManager;
    private readonly SignInManager<TUser> _signInManager;
    private readonly IPasswordHasher<TUser> _passwordHasher;
    private readonly IBackgroundTaskQueue _taskQueue;
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly ILogger<AuthService<TUser>> _logger;

    public AuthService(
        UserManager<TUser> userManager,
        SignInManager<TUser> signInManager,
        IPasswordHasher<TUser> passwordHasher,
        IBackgroundTaskQueue taskQueue,
        IServiceScopeFactory scopeFactory,
        IHttpContextAccessor httpContextAccessor,
        ILogger<AuthService<TUser>> logger)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _passwordHasher = passwordHasher;
        _taskQueue = taskQueue;
        _scopeFactory = scopeFactory;
        _httpContextAccessor = httpContextAccessor;
        _logger = logger;
    }

    public ClaimsPrincipal? CurrentPrincipal
    {
        get
        {
            ClaimsPrincipal? principal = _httpContextAccessor.HttpContext?.User;
            return principal?.Identity?.IsAuthenticated == true ? principal : null;
        }
    }

    public async Task<AuthResult> RegisterAsync(string email, string password)
    {
        if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(password))
        {
            return AuthResult.Failure();
        }

        TUser candidate = new() { UserName = email, Email = email };

        // Password policy is checked first and on its own, because it is the one
        // failure we are allowed to explain: it describes the password just typed and
        // says nothing about who is registered.
        AuthResult? rejected = await ValidatePasswordAsync(candidate, password);
        if (rejected is not null)
        {
            return rejected;
        }

        TUser? existing = await _userManager.FindByEmailAsync(email);
        if (existing is not null)
        {
            // The address is taken, and we must not say so. Tell the owner instead,
            // over a channel that already proves they own it, and report the same
            // success a real registration would.
            //
            // The hash burn is not busywork: the create path below spends real CPU
            // hashing the password, so returning here without it would make a taken
            // address measurably faster to probe than a free one - the same
            // enumeration leak, moved from the response body into the clock.
            BurnPasswordHashCycles(password);
            await QueueRegistrationAttemptedAsync(email);
            return AuthResult.Success();
        }

        IdentityResult created = await _userManager.CreateAsync(candidate, password);
        if (!created.Succeeded)
        {
            // Reachable if someone registered this address between the check above and
            // this call. Identity would hand back DuplicateEmail; surfacing it is
            // exactly the leak we are avoiding, so the caller sees the same success.
            _logger.LogWarning(
                "Registration did not create an account. Identity error codes: {ErrorCodes}",
                string.Join(", ", created.Errors.Select(e => e.Code)));
            return AuthResult.Success();
        }

        await SendConfirmationAsync(candidate);
        return AuthResult.Success();
    }

    public async Task<AuthResult> SignInAsync(string email, string password, bool isPersistent = false)
    {
        if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(password))
        {
            return AuthResult.Failure();
        }

        TUser? user = await _userManager.FindByEmailAsync(email);
        if (user is null)
        {
            // Identity returns SignInResult.Failed here without hashing anything, which
            // makes an unknown address answer measurably faster than a real one. That
            // timing gap is a user-existence oracle, so we pay the hash anyway.
            BurnPasswordHashCycles(password);
            return AuthResult.Failure();
        }

        SignInResult result = await _signInManager.PasswordSignInAsync(
            user, password, isPersistent, lockoutOnFailure: true);

        if (result.Succeeded)
        {
            return AuthResult.Success();
        }

        // Safe to report: only reachable once the password has been verified, so it
        // tells a guesser nothing they had not already proved.
        if (result.RequiresTwoFactor)
        {
            return AuthResult.TwoFactorRequired();
        }

        // LockedOut and NotAllowed are decided BEFORE the password is checked, so they
        // both announce that the account exists and skip the hash. Collapse them into
        // the generic failure, and pay the hash they skipped so the clock stays quiet
        // too.
        if (result.IsLockedOut || result.IsNotAllowed)
        {
            BurnPasswordHashCycles(password);
        }

        return AuthResult.Failure();
    }

    public async Task<AuthResult> TwoFactorSignInAsync(
        string code,
        bool isPersistent = false,
        bool rememberClient = false)
    {
        if (string.IsNullOrWhiteSpace(code))
        {
            return AuthResult.Failure();
        }

        // SignInManager reads the user from the short-lived cookie the first factor left
        // behind. No first factor, nothing to complete - and no hash to burn here, because
        // reaching this point at all required the password.
        TUser? user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
        if (user is null)
        {
            return AuthResult.Failure();
        }

        SignInResult result = await _signInManager.TwoFactorAuthenticatorSignInAsync(
            code, isPersistent, rememberClient);

        // Succeeded, or the same generic failure for a wrong code, an expired one, and a
        // locked-out account alike.
        return result.Succeeded ? AuthResult.Success() : AuthResult.Failure();
    }

    public async Task<AuthResult> RedeemRecoveryCodeAsync(string recoveryCode)
    {
        if (string.IsNullOrWhiteSpace(recoveryCode))
        {
            return AuthResult.Failure();
        }

        TUser? user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
        if (user is null)
        {
            return AuthResult.Failure();
        }

        // Spends the code: Identity removes it from the user's remaining set on success.
        SignInResult result = await _signInManager.TwoFactorRecoveryCodeSignInAsync(recoveryCode);

        return result.Succeeded ? AuthResult.Success() : AuthResult.Failure();
    }

    public async Task SignOutAsync()
    {
        // SignInManager reaches through HttpContext and throws without one. Signing out
        // off-request is a no-op, per the interface contract.
        if (_httpContextAccessor.HttpContext is null)
        {
            return;
        }

        await _signInManager.SignOutAsync();
    }

    public async Task<AuthResult> ConfirmEmailAsync(string userId, string token)
    {
        if (string.IsNullOrWhiteSpace(userId) || string.IsNullOrWhiteSpace(token))
        {
            return AuthResult.Failure();
        }

        TUser? user = await _userManager.FindByIdAsync(userId);
        string? decoded = AuthTokens.TryDecode(token);
        if (user is null || decoded is null)
        {
            return AuthResult.Failure();
        }

        IdentityResult result = await _userManager.ConfirmEmailAsync(user, decoded);
        if (!result.Succeeded)
        {
            return AuthResult.Failure();
        }

        // Identity does not touch the security stamp on confirmation. Confirming
        // changes what the account may do, and PLAN.md treats a privilege change as
        // requiring rotation, so any session opened before confirmation dies here.
        await _userManager.UpdateSecurityStampAsync(user);
        return AuthResult.Success();
    }

    public async Task<AuthResult> RequestPasswordResetAsync(string email)
    {
        // Nothing here may depend on whether the address is registered - not the answer,
        // and not the time taken to give it. So this method does no lookup, mints no
        // token and sends no mail: it queues the address and returns. Awaiting an SMTP
        // call for registered addresses only would answer "does this account exist" to
        // anyone holding a stopwatch, however uniform the response body looked.
        if (!string.IsNullOrWhiteSpace(email))
        {
            IServiceScopeFactory scopeFactory = _scopeFactory;
            await _taskQueue.QueueBackgroundWorkItemAsync(
                ct => SendPasswordResetAsync(scopeFactory, email, ct));
        }

        return AuthResult.Success();
    }

    public async Task<AuthResult> ResetPasswordAsync(string userId, string token, string newPassword)
    {
        if (string.IsNullOrWhiteSpace(userId) || string.IsNullOrWhiteSpace(token))
        {
            return AuthResult.Failure();
        }

        TUser? user = await _userManager.FindByIdAsync(userId);
        if (user is null)
        {
            return AuthResult.Failure();
        }

        // Checked before the token is spent so a caller with a good token and a weak
        // password is told what is wrong with the password. Identity would otherwise
        // blend policy errors and InvalidToken into one result we have to collapse.
        AuthResult? rejected = await ValidatePasswordAsync(user, newPassword);
        if (rejected is not null)
        {
            return rejected;
        }

        string? decoded = AuthTokens.TryDecode(token);
        if (decoded is null)
        {
            return AuthResult.Failure();
        }

        IdentityResult result = await _userManager.ResetPasswordAsync(user, decoded, newPassword);

        // A rejected token is never explained: expired, forged, already spent and
        // wrong-user all look the same from here.
        // On success Identity rotates the stamp itself, which kills every existing
        // session for this user. That is the point of a reset.
        return result.Succeeded ? AuthResult.Success() : AuthResult.Failure();
    }

    public async Task<AuthResult> ChangePasswordAsync(string currentPassword, string newPassword)
    {
        TUser? user = await GetCurrentUserAsync();
        if (user is null)
        {
            return AuthResult.Failure();
        }

        AuthResult? rejected = await ValidatePasswordAsync(user, newPassword);
        if (rejected is not null)
        {
            return rejected;
        }

        IdentityResult result = await _userManager.ChangePasswordAsync(user, currentPassword, newPassword);
        if (!result.Succeeded)
        {
            return AuthResult.Failure();
        }

        // Identity rotated the stamp, so every session for this user is now stale -
        // including the one that asked. Re-issue this one so changing your password
        // does not sign you out of the tab you changed it in.
        await _signInManager.RefreshSignInAsync(user);
        return AuthResult.Success();
    }

    public async Task<AuthResult> RotateSessionAsync()
    {
        TUser? user = await GetCurrentUserAsync();
        if (user is null)
        {
            return AuthResult.Failure();
        }

        // Identity refreshes the stamp for password changes but NOT for role or claim
        // changes, so this call is the whole mechanism: without it a just-revoked
        // administrator keeps administrator claims until their cookie expires.
        await _userManager.UpdateSecurityStampAsync(user);

        // Every other session is now stale; re-issue the caller's with the new stamp
        // and freshly built claims.
        await _signInManager.RefreshSignInAsync(user);
        return AuthResult.Success();
    }

    private async Task<TUser?> GetCurrentUserAsync()
    {
        ClaimsPrincipal? principal = CurrentPrincipal;
        return principal is null ? null : await _userManager.GetUserAsync(principal);
    }

    private async Task<AuthResult?> ValidatePasswordAsync(TUser user, string password)
    {
        List<string> errors = [];

        foreach (IPasswordValidator<TUser> validator in _userManager.PasswordValidators)
        {
            IdentityResult result = await validator.ValidateAsync(_userManager, user, password);
            if (!result.Succeeded)
            {
                errors.AddRange(result.Errors.Select(e => e.Description));
            }
        }

        return errors.Count == 0 ? null : AuthResult.PasswordRejected(errors);
    }

    private async Task SendConfirmationAsync(TUser user)
    {
        string? email = await _userManager.GetEmailAsync(user);
        if (email is null)
        {
            return;
        }

        // The token is minted here, where the user is already loaded; only the delivery
        // is deferred.
        string token = AuthTokens.Encode(await _userManager.GenerateEmailConfirmationTokenAsync(user));
        string userId = user.Id;
        IServiceScopeFactory scopeFactory = _scopeFactory;

        await _taskQueue.QueueBackgroundWorkItemAsync(
            ct => SendConfirmationEmailAsync(scopeFactory, email, userId, token, ct));
    }

    private async Task QueueRegistrationAttemptedAsync(string email)
    {
        IServiceScopeFactory scopeFactory = _scopeFactory;

        await _taskQueue.QueueBackgroundWorkItemAsync(
            ct => SendRegistrationAttemptedAsync(scopeFactory, email, ct));
    }

    // The work items below are static on purpose. A lambda that captured "this" would
    // hold this scoped AuthService - and the UserManager and SignInManager it was built
    // with - alive past the end of the request that queued it, and they would be disposed
    // out from under the background thread. Each item takes only the singleton scope
    // factory plus strings, and opens a scope of its own.

    private static async ValueTask SendConfirmationEmailAsync(
        IServiceScopeFactory scopeFactory,
        string email,
        string userId,
        string token,
        CancellationToken cancellationToken)
    {
        using IServiceScope scope = scopeFactory.CreateScope();
        IAuthEmailSender sender = scope.ServiceProvider.GetRequiredService<IAuthEmailSender>();

        await sender.SendEmailConfirmationAsync(email, userId, token);
    }

    private static async ValueTask SendRegistrationAttemptedAsync(
        IServiceScopeFactory scopeFactory,
        string email,
        CancellationToken cancellationToken)
    {
        using IServiceScope scope = scopeFactory.CreateScope();
        IAuthEmailSender sender = scope.ServiceProvider.GetRequiredService<IAuthEmailSender>();

        await sender.SendRegistrationAttemptedAsync(email);
    }

    /// <summary>
    /// Resolves the address, decides whether it is eligible, and sends the reset link,
    /// all off the request thread.
    /// </summary>
    /// <remarks>
    /// Every account-dependent step lives here rather than in
    /// <see cref="RequestPasswordResetAsync"/>, so nothing the request thread does
    /// depends on whether the address exists. An unknown or unconfirmed address is
    /// dropped here, out of band, where no caller can time it.
    /// </remarks>
    private static async ValueTask SendPasswordResetAsync(
        IServiceScopeFactory scopeFactory,
        string email,
        CancellationToken cancellationToken)
    {
        using IServiceScope scope = scopeFactory.CreateScope();
        UserManager<TUser> userManager = scope.ServiceProvider.GetRequiredService<UserManager<TUser>>();
        IAuthEmailSender sender = scope.ServiceProvider.GetRequiredService<IAuthEmailSender>();

        TUser? user = await userManager.FindByEmailAsync(email);
        if (user is null || !await IsEligibleForResetAsync(userManager, user))
        {
            return;
        }

        string token = AuthTokens.Encode(await userManager.GeneratePasswordResetTokenAsync(user));
        await sender.SendPasswordResetAsync(email, user.Id, token);
    }

    private static async Task<bool> IsEligibleForResetAsync(UserManager<TUser> userManager, TUser user)
    {
        // Only gate on confirmation where confirmation is actually required; otherwise a
        // host that does not use email confirmation could never reset a password.
        if (!userManager.Options.SignIn.RequireConfirmedEmail)
        {
            return true;
        }

        return await userManager.IsEmailConfirmedAsync(user);
    }

    /// <summary>
    /// Spends the same CPU a real password check would, and throws the answer away.
    /// </summary>
    /// <remarks>
    /// Called on every path that skips Identity's password verification but must stay
    /// indistinguishable from one that does not. Without it, "no such account" and
    /// "locked out" answer faster than "wrong password", and response time becomes the
    /// user-enumeration oracle that the response body no longer is.
    /// </remarks>
    private void BurnPasswordHashCycles(string password)
    {
        _ = _passwordHasher.HashPassword(new TUser(), password);
    }

}
