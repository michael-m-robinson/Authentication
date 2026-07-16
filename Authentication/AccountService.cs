// The two-factor setup below (AuthenticatorUriFormat, BuildAuthenticatorUri, FormatKey, and
// the verify-then-enable order) is adapted from the scaffolded ASP.NET Core Identity UI:
// https://github.com/dotnet/aspnetcore/blob/main/src/Identity/UI/src/Areas/Identity/Pages/V4/Account/Manage/EnableAuthenticator.cshtml.cs
// Licensed under the MIT License. Copyright (c) .NET Foundation and Contributors.
// See THIRD-PARTY-NOTICES.txt.
//
// Changes from the original: the issuer comes from ReusableAuthOptions instead of being
// hard-coded to "Microsoft.AspNetCore.Identity.UI"; the page's Razor/ModelState handling is
// replaced by AuthResult; and the flow is split so a host can render the QR code however it
// likes rather than into Microsoft's page.

using System.Globalization;
using System.Text;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Authentication;

/// <summary>
/// The default <see cref="IAccountService"/>, over Identity's
/// <see cref="UserManager{TUser}"/>.
/// </summary>
/// <typeparam name="TUser">The Identity user type.</typeparam>
internal sealed class AccountService<TUser> : IAccountService
    where TUser : IdentityUser<string>, new()
{
    /// <summary>
    /// The otpauth URI shape every authenticator app understands. Taken verbatim from
    /// Microsoft's scaffolded setup page so the QR codes we describe are the ones those apps
    /// already read.
    /// </summary>
    private const string AuthenticatorUriFormat = "otpauth://totp/{0}:{1}?secret={2}&issuer={0}&digits=6";

    private readonly UserManager<TUser> _userManager;
    private readonly IBackgroundTaskQueue _taskQueue;
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ReusableAuthOptions _options;
    private readonly ILogger<AccountService<TUser>> _logger;

    public AccountService(
        UserManager<TUser> userManager,
        IBackgroundTaskQueue taskQueue,
        IServiceScopeFactory scopeFactory,
        IOptions<ReusableAuthOptions> options,
        ILogger<AccountService<TUser>> logger)
    {
        _userManager = userManager;
        _taskQueue = taskQueue;
        _scopeFactory = scopeFactory;
        _options = options.Value;
        _logger = logger;
    }

    // ---- Email ---------------------------------------------------------------------

    public async Task<AuthResult> RequestEmailChangeAsync(string userId, string newEmail)
    {
        if (string.IsNullOrWhiteSpace(newEmail))
        {
            return AuthResult.Rejected("An email address is required.");
        }

        TUser? user = await FindAsync(userId);
        if (user is null)
        {
            return AuthResult.Rejected("No such user.");
        }

        // Deliberately no check for whether the address is already registered. This library
        // requires unique emails, so answering that question would let any signed-in user
        // enumerate the user base one address at a time. Mint the token and send it; if the
        // address belongs to someone else, ConfirmEmailChangeAsync refuses later, out of
        // band, where the caller cannot see it. Microsoft's own page behaves identically.
        string token = AuthTokens.Encode(await _userManager.GenerateChangeEmailTokenAsync(user, newEmail));

        await QueueEmailChangeConfirmationAsync(newEmail, user.Id, token);

        return AuthResult.Success();
    }

    public async Task<AuthResult> ConfirmEmailChangeAsync(string userId, string newEmail, string token)
    {
        if (string.IsNullOrWhiteSpace(newEmail) || string.IsNullOrWhiteSpace(token))
        {
            return AuthResult.Failure();
        }

        TUser? user = await FindAsync(userId);
        string? decoded = AuthTokens.TryDecode(token);
        if (user is null || decoded is null)
        {
            return AuthResult.Failure();
        }

        IdentityResult changed = await _userManager.ChangeEmailAsync(user, newEmail, decoded);
        if (!changed.Succeeded)
        {
            // Generic on purpose. Reachable for a bad token, an expired one, and - because
            // unique emails are required - an address someone else claimed since the link
            // was sent. Reporting which would answer the question the request deliberately
            // did not.
            _logger.LogWarning(
                "Email change was not applied. Identity error codes: {ErrorCodes}",
                string.Join(", ", changed.Errors.Select(e => e.Code)));

            return AuthResult.Failure();
        }

        // The user name is the sign-in identity in this library, so it has to move with the
        // address. Identity does not do this for you: ChangeEmailAsync sets Email alone, and
        // leaving UserName behind means the user still signs in with their old address.
        IdentityResult renamed = await _userManager.SetUserNameAsync(user, newEmail);

        return renamed.Succeeded ? AuthResult.Success() : AuthResult.Failure();
    }

    // ---- Phone ---------------------------------------------------------------------

    public async Task<AuthResult> SetPhoneNumberAsync(string userId, string? phoneNumber)
    {
        TUser? user = await FindAsync(userId);
        if (user is null)
        {
            return AuthResult.Rejected("No such user.");
        }

        // Unverified: nothing here proves the user owns this number, because verifying means
        // sending a code to it and this library has no way to send an SMS. Identity bumps the
        // security stamp itself on this write.
        IdentityResult result = await _userManager.SetPhoneNumberAsync(user, phoneNumber);

        return result.Succeeded ? AuthResult.Success() : Rejected(result);
    }

    // ---- Two-factor ----------------------------------------------------------------

    public async Task<bool> IsTwoFactorEnabledAsync(string userId)
    {
        TUser? user = await FindAsync(userId);

        return user is not null && await _userManager.GetTwoFactorEnabledAsync(user);
    }

    public async Task<TwoFactorSetup?> BeginTwoFactorSetupAsync(string userId)
    {
        TUser? user = await FindAsync(userId);
        if (user is null)
        {
            return null;
        }

        string? key = await _userManager.GetAuthenticatorKeyAsync(user);
        if (string.IsNullOrEmpty(key))
        {
            // First time through. Note this resets nothing for a user who already has a key:
            // re-issuing it would silently break an authenticator app they already added.
            await _userManager.ResetAuthenticatorKeyAsync(user);
            key = await _userManager.GetAuthenticatorKeyAsync(user);
        }

        if (string.IsNullOrEmpty(key))
        {
            return null;
        }

        string email = await _userManager.GetEmailAsync(user) ?? user.Id;

        return new TwoFactorSetup(FormatKey(key), BuildAuthenticatorUri(email, key));
    }

    public async Task<AuthResult> EnableTwoFactorAsync(string userId, string code)
    {
        TUser? user = await FindAsync(userId);
        if (user is null)
        {
            return AuthResult.Rejected("No such user.");
        }

        if (string.IsNullOrWhiteSpace(code))
        {
            return AuthResult.Rejected("A verification code is required.");
        }

        // Verify BEFORE enabling. Turning two-factor on for an app that was never really
        // configured locks the user out of their own account, with no way back except
        // recovery codes they have not been issued yet.
        bool valid = await _userManager.VerifyTwoFactorTokenAsync(
            user,
            _userManager.Options.Tokens.AuthenticatorTokenProvider,
            StripFormatting(code));

        if (!valid)
        {
            return AuthResult.Rejected("That code is not valid. Check your authenticator app and try again.");
        }

        IdentityResult enabled = await _userManager.SetTwoFactorEnabledAsync(user, true);

        return enabled.Succeeded ? AuthResult.Success() : Rejected(enabled);
    }

    public async Task<AuthResult> DisableTwoFactorAsync(string userId)
    {
        TUser? user = await FindAsync(userId);
        if (user is null)
        {
            return AuthResult.Rejected("No such user.");
        }

        // Leaves the authenticator key in place, matching Identity: re-enabling later should
        // work with the app the user already has. ResetAuthenticatorKeyAsync is how you cut
        // that app off.
        IdentityResult disabled = await _userManager.SetTwoFactorEnabledAsync(user, false);

        return disabled.Succeeded ? AuthResult.Success() : Rejected(disabled);
    }

    public async Task<AuthResult> ResetAuthenticatorKeyAsync(string userId)
    {
        TUser? user = await FindAsync(userId);
        if (user is null)
        {
            return AuthResult.Rejected("No such user.");
        }

        // Two-factor off first, then the new key. The order matters: a new key with two-factor
        // still on would demand codes from an app that no longer has the right secret, which
        // locks the account.
        IdentityResult disabled = await _userManager.SetTwoFactorEnabledAsync(user, false);
        if (!disabled.Succeeded)
        {
            return Rejected(disabled);
        }

        IdentityResult reset = await _userManager.ResetAuthenticatorKeyAsync(user);

        return reset.Succeeded ? AuthResult.Success() : Rejected(reset);
    }

    // ---- Recovery codes ------------------------------------------------------------

    public async Task<IReadOnlyList<string>> GenerateRecoveryCodesAsync(string userId, int count = 10)
    {
        TUser? user = await FindAsync(userId);
        if (user is null)
        {
            return [];
        }

        IEnumerable<string>? codes = await _userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, count);

        return codes is null ? [] : [.. codes];
    }

    public async Task<int> CountRecoveryCodesAsync(string userId)
    {
        TUser? user = await FindAsync(userId);

        return user is null ? 0 : await _userManager.CountRecoveryCodesAsync(user);
    }

    // ---- Internals -----------------------------------------------------------------

    private async Task<TUser?> FindAsync(string userId)
        => string.IsNullOrWhiteSpace(userId) ? null : await _userManager.FindByIdAsync(userId);

    private async Task QueueEmailChangeConfirmationAsync(string newEmail, string userId, string token)
    {
        IServiceScopeFactory scopeFactory = _scopeFactory;

        await _taskQueue.QueueBackgroundWorkItemAsync(
            ct => SendEmailChangeConfirmationAsync(scopeFactory, newEmail, userId, token, ct));
    }

    /// <summary>
    /// Static for the same reason as the work items in <see cref="AuthService{TUser}"/>:
    /// capturing <c>this</c> would keep a scoped service alive past its request, to be
    /// disposed under the background thread.
    /// </summary>
    private static async ValueTask SendEmailChangeConfirmationAsync(
        IServiceScopeFactory scopeFactory,
        string newEmail,
        string userId,
        string token,
        CancellationToken cancellationToken)
    {
        using IServiceScope scope = scopeFactory.CreateScope();
        IAuthEmailSender sender = scope.ServiceProvider.GetRequiredService<IAuthEmailSender>();

        // Reuses the confirmation channel: from the recipient's side this is the same act -
        // prove you own this address by clicking a link.
        await sender.SendEmailConfirmationAsync(newEmail, userId, token);
    }

    private string BuildAuthenticatorUri(string email, string key)
        => string.Format(
            CultureInfo.InvariantCulture,
            AuthenticatorUriFormat,
            UrlEncoder.Default.Encode(_options.AuthenticatorIssuer),
            UrlEncoder.Default.Encode(email),
            key);

    /// <summary>
    /// Groups the key in fours for manual entry. Microsoft's setup page, unchanged,
    /// including the lower-casing, so the key reads the same as everywhere else people are
    /// used to seeing it.
    /// </summary>
    private static string FormatKey(string unformattedKey)
    {
        StringBuilder result = new();
        int currentPosition = 0;

        while (currentPosition + 4 < unformattedKey.Length)
        {
            result.Append(unformattedKey.AsSpan(currentPosition, 4)).Append(' ');
            currentPosition += 4;
        }

        if (currentPosition < unformattedKey.Length)
        {
            result.Append(unformattedKey.AsSpan(currentPosition));
        }

        return result.ToString().ToLowerInvariant();
    }

    /// <summary>
    /// Drops the spaces and dashes people paste in from their authenticator app.
    /// </summary>
    private static string StripFormatting(string code)
        => code.Replace(" ", string.Empty, StringComparison.Ordinal)
               .Replace("-", string.Empty, StringComparison.Ordinal);

    private static AuthResult Rejected(IdentityResult result)
        => AuthResult.Rejected(result.Errors.Select(e => e.Description));
}
