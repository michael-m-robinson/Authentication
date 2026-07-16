namespace Authentication;

/// <summary>
/// What a user needs to add this account to their authenticator app.
/// </summary>
/// <remarks>
/// Returned by <see cref="IAccountService.BeginTwoFactorSetupAsync"/>. Show both: the URI
/// for people who can scan, the key for people who cannot.
/// <para>
/// <strong>Neither is secret from the user, and both are secret from everyone else.</strong>
/// The key is the TOTP shared secret: anyone holding it can generate valid codes forever.
/// Render it to the user and nowhere else: not in a log, not in an analytics event, not in
/// an error report.
/// </para>
/// </remarks>
public sealed class TwoFactorSetup
{
    internal TwoFactorSetup(string sharedKey, string authenticatorUri)
    {
        SharedKey = sharedKey;
        AuthenticatorUri = authenticatorUri;
    }

    /// <summary>
    /// The shared secret, for typing into an authenticator app by hand.
    /// </summary>
    /// <remarks>
    /// Formatted in groups of four, as Microsoft's own setup page does, because people
    /// transcribe it manually.
    /// </remarks>
    public string SharedKey { get; }

    /// <summary>
    /// The <c>otpauth://</c> URI to render as a QR code.
    /// </summary>
    /// <remarks>
    /// <strong>This is a URI, not an image.</strong> ASP.NET Core Identity does not generate
    /// QR codes and neither does this library. Rendering is the host's job, typically with
    /// a client-side library. Microsoft's own scaffolded page ships an empty
    /// <c>&lt;div id="qrCode"&gt;</c> and a link to a doc explaining the same thing.
    /// </remarks>
    public string AuthenticatorUri { get; }
}
