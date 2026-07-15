using System.Security.Claims;

namespace Authentication;

/// <summary>
/// The auth operations a consuming app calls: register, sign in, sign out, inspect the
/// current user, confirm an email, and change or reset a password.
/// </summary>
/// <remarks>
/// Two contracts hold across every member here.
/// <para>
/// <strong>Expected failures are returned, not thrown.</strong> A wrong password or a
/// stale token is an ordinary outcome and comes back as
/// <see cref="AuthStatus.Failed"/>. Exceptions are reserved for programming errors and
/// broken configuration.
/// </para>
/// <para>
/// <strong>Failures never disclose why.</strong> Unknown account, wrong password,
/// locked out, unconfirmed, expired token — all return the same
/// <see cref="AuthStatus.Failed"/>, and the timing is levelled so the elapsed time does
/// not disclose it either. Anything a user genuinely needs to be told is sent over a
/// channel that already proves they own the account, i.e. email.
/// </para>
/// <para>
/// No member accepts a <see cref="System.Threading.CancellationToken"/>. ASP.NET Core
/// Identity's <c>UserManager</c> does not thread one through to the store, so accepting
/// a token here would promise a cancellation the library cannot deliver.
/// </para>
/// </remarks>
public interface IAuthService
{
    /// <summary>
    /// The signed-in user for the current request, or <see langword="null"/> when the
    /// request is anonymous.
    /// </summary>
    ClaimsPrincipal? CurrentPrincipal { get; }

    /// <summary>
    /// Registers a new account and sends a confirmation email.
    /// </summary>
    /// <param name="email">The email address, which is also the user name.</param>
    /// <param name="password">The password, checked against the configured policy.</param>
    /// <returns>
    /// <see cref="AuthStatus.Succeeded"/> if the request was accepted, or
    /// <see cref="AuthStatus.PasswordRejected"/> with the policy messages.
    /// </returns>
    /// <remarks>
    /// <strong>Success does not mean an account was created.</strong> When
    /// <paramref name="email"/> is already registered, this still reports success and
    /// instead emails the existing address to say someone tried to register with it.
    /// Reporting anything else would confirm the address has an account, which is the
    /// enumeration leak <c>rules/security.md</c> forbids — Identity's own
    /// <c>DuplicateEmail</c> error is never surfaced.
    /// <para>
    /// A rejected password is reported, because that describes the password just typed
    /// and reveals nothing about who is registered.
    /// </para>
    /// </remarks>
    Task<AuthResult> RegisterAsync(string email, string password);

    /// <summary>
    /// Verifies credentials and, on success, issues the hardened session cookie.
    /// </summary>
    /// <param name="email">The email address the account was registered with.</param>
    /// <param name="password">The password to verify.</param>
    /// <param name="isPersistent">
    /// Whether the session should survive the browser closing.
    /// </param>
    /// <returns>
    /// <see cref="AuthStatus.Succeeded"/>, <see cref="AuthStatus.RequiresTwoFactor"/>
    /// when the password was correct and a second factor is needed, or
    /// <see cref="AuthStatus.Failed"/>.
    /// </returns>
    /// <remarks>
    /// Failure is uniform: an unknown address, a wrong password, a locked-out account
    /// and an unconfirmed account are indistinguishable to the caller, and the work
    /// done is levelled so they are indistinguishable by timing too. Lockout still
    /// applies — it is simply not announced.
    /// </remarks>
    Task<AuthResult> SignInAsync(string email, string password, bool isPersistent = false);

    /// <summary>
    /// Signs the current user out and clears the session cookie.
    /// </summary>
    /// <remarks>Signing out when nobody is signed in is a no-op, not an error.</remarks>
    Task SignOutAsync();

    /// <summary>
    /// Confirms an email address using a token from a confirmation link.
    /// </summary>
    /// <param name="userId">The user id carried in the confirmation link.</param>
    /// <param name="token">The confirmation token.</param>
    /// <returns>
    /// <see cref="AuthStatus.Succeeded"/>, or <see cref="AuthStatus.Failed"/> for an
    /// unknown user, or a token that is wrong, expired, or already spent.
    /// </returns>
    /// <remarks>
    /// Confirming rotates the user's security stamp, so any session established before
    /// confirmation is invalidated. Identity does not do this on its own; the library
    /// does it because confirmation changes what the account is allowed to do, and
    /// <c>PLAN.md</c> treats a privilege change as requiring rotation.
    /// </remarks>
    Task<AuthResult> ConfirmEmailAsync(string userId, string token);

    /// <summary>
    /// Starts a password reset by emailing a reset link, if the address is eligible.
    /// </summary>
    /// <param name="email">The address to send a reset link to.</param>
    /// <returns>
    /// Always <see cref="AuthStatus.Succeeded"/>, whether or not anything was sent.
    /// </returns>
    /// <remarks>
    /// The invariable success is the security property, not sloppiness: reporting
    /// "no such account" here is the classic enumeration oracle, and this mirrors the
    /// pattern in Microsoft's own scaffolded forgot-password page. An unregistered or
    /// unconfirmed address simply receives nothing.
    /// </remarks>
    Task<AuthResult> RequestPasswordResetAsync(string email);

    /// <summary>
    /// Completes a password reset using a token from a reset link.
    /// </summary>
    /// <param name="userId">The user id carried in the reset link.</param>
    /// <param name="token">The reset token.</param>
    /// <param name="newPassword">The replacement password.</param>
    /// <returns>
    /// <see cref="AuthStatus.Succeeded"/>,
    /// <see cref="AuthStatus.PasswordRejected"/> with the policy messages, or
    /// <see cref="AuthStatus.Failed"/> for an unknown user or a bad token.
    /// </returns>
    /// <remarks>
    /// A successful reset rotates the security stamp, which invalidates every existing
    /// session for that user and burns any other outstanding reset token. This is
    /// intended: a reset is how someone recovers an account they believe is
    /// compromised, so every older session must die.
    /// </remarks>
    Task<AuthResult> ResetPasswordAsync(string userId, string token, string newPassword);

    /// <summary>
    /// Changes the signed-in user's password, having verified the current one.
    /// </summary>
    /// <param name="currentPassword">The existing password.</param>
    /// <param name="newPassword">The replacement password.</param>
    /// <returns>
    /// <see cref="AuthStatus.Succeeded"/>,
    /// <see cref="AuthStatus.PasswordRejected"/> with the policy messages, or
    /// <see cref="AuthStatus.Failed"/> if nobody is signed in or the current password
    /// is wrong.
    /// </returns>
    /// <remarks>
    /// Every other session for the user is invalidated, and the caller's own session is
    /// re-issued so the act of changing a password does not sign you out of the tab you
    /// did it in.
    /// </remarks>
    Task<AuthResult> ChangePasswordAsync(string currentPassword, string newPassword);

    /// <summary>
    /// Invalidates every other session for the signed-in user and re-issues the current
    /// session cookie. Call this after changing the user's roles or claims.
    /// </summary>
    /// <returns>
    /// <see cref="AuthStatus.Succeeded"/>, or <see cref="AuthStatus.Failed"/> if nobody
    /// is signed in.
    /// </returns>
    /// <remarks>
    /// This exists because Identity will not do it for you. <c>UserManager</c> refreshes
    /// the security stamp automatically when a password changes, but <em>not</em> when
    /// roles or claims change — so without calling this after a privilege change, the
    /// user's existing cookies keep their old claims until they expire, and a
    /// just-revoked administrator stays an administrator. <c>PLAN.md</c> makes rotation
    /// on privilege change a v1 invariant; for role and claim edits this method is how
    /// that invariant is met.
    /// </remarks>
    Task<AuthResult> RotateSessionAsync();
}
