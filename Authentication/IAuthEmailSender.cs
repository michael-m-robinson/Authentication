namespace Authentication;

/// <summary>
/// Delivers the emails the auth flows depend on. Implemented by the host.
/// </summary>
/// <remarks>
/// The library mints tokens and never sends mail: picking an SMTP provider or a
/// template engine would be exactly the app-specific assumption this library exists to
/// avoid. The host builds the link and sends the message.
/// <para>
/// <strong>Tokens arrive URL-safe.</strong> Every <c>token</c> passed here is already
/// Base64Url-encoded and can be dropped straight into a query string;
/// <see cref="IAuthService.ConfirmEmailAsync"/> and
/// <see cref="IAuthService.ResetPasswordAsync"/> expect that same encoded form back.
/// Raw Identity tokens contain characters that do not survive a URL round-trip, and
/// leaving that to each host is a reliable source of "invalid token" bugs, so the
/// library owns both halves of the encoding.
/// </para>
/// <para>
/// <strong>Never log the token.</strong> It is a bearer credential: anyone holding a
/// reset token can take the account. Log the user id if you need a trail, never the
/// token, and never the password. See <c>rules/security.md</c>.
/// </para>
/// <para>
/// <strong>Where exceptions go depends on the call.</strong>
/// <see cref="SendEmailConfirmationAsync"/> and
/// <see cref="SendRegistrationAttemptedAsync"/> run inside
/// <see cref="IAuthService.RegisterAsync"/>, so what they throw reaches its caller.
/// <see cref="SendPasswordResetAsync"/> runs on a background dispatcher, off the request
/// that asked for it — it has to, or a registered address would answer measurably slower
/// than an unknown one — so what it throws is logged and goes no further. Either way,
/// throw on a delivery failure rather than returning quietly; a silent failure is
/// indistinguishable from a completed send.
/// </para>
/// </remarks>
public interface IAuthEmailSender
{
    /// <summary>
    /// Sends a link confirming ownership of a newly registered address.
    /// </summary>
    /// <param name="email">The address to send to.</param>
    /// <param name="userId">
    /// The user id to carry in the link; pass it back to
    /// <see cref="IAuthService.ConfirmEmailAsync"/>.
    /// </param>
    /// <param name="token">The URL-safe confirmation token. Valid for 1 day.</param>
    Task SendEmailConfirmationAsync(string email, string userId, string token);

    /// <summary>
    /// Sends a link for resetting a forgotten password.
    /// </summary>
    /// <param name="email">The address to send to.</param>
    /// <param name="userId">
    /// The user id to carry in the link; pass it back to
    /// <see cref="IAuthService.ResetPasswordAsync"/>.
    /// </param>
    /// <param name="token">
    /// The URL-safe reset token. Valid for 1 hour — shorter than the confirmation
    /// token, because a reset link that leaks from an inbox hands over the account.
    /// </param>
    Task SendPasswordResetAsync(string email, string userId, string token);

    /// <summary>
    /// Tells an existing account holder that someone tried to register with their
    /// address.
    /// </summary>
    /// <param name="email">The already-registered address.</param>
    /// <remarks>
    /// This is what makes the non-enumerating registration honest rather than merely
    /// silent. <see cref="IAuthService.RegisterAsync"/> cannot tell the caller the
    /// address is taken without confirming the account exists to whoever asked — so it
    /// tells the person who actually owns the address instead, over a channel that
    /// already proves ownership.
    /// <para>
    /// A good message says a registration was attempted and points to password
    /// recovery. It carries no token and grants nothing: an attacker who triggers it
    /// learns only that mail was sent to an address they already named.
    /// </para>
    /// </remarks>
    Task SendRegistrationAttemptedAsync(string email);
}
