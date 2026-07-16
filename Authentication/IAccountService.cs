namespace Authentication;

/// <summary>
/// A signed-in user's own account settings: their email address, phone number, and
/// two-factor authentication.
/// </summary>
/// <remarks>
/// Separate from <see cref="IAuthService"/>, which is about proving who someone is. This is
/// about what they change afterwards.
/// <para>
/// Identity refreshes the security stamp itself on every write here: changing an email,
/// phone or two-factor state all bump it, so unlike role changes these methods do not
/// need to force it. The effect is the same: the change reaches every session that user has
/// open within <see cref="ReusableAuthOptions.SecurityStampValidationInterval"/>.
/// </para>
/// </remarks>
public interface IAccountService
{
    /// <summary>
    /// Starts changing a user's email address by emailing a confirmation link to the
    /// <em>new</em> address.
    /// </summary>
    /// <param name="userId">The user's id.</param>
    /// <param name="newEmail">The address to change to.</param>
    /// <returns>
    /// Always <see cref="AuthStatus.Succeeded"/> when the input is well-formed, whether or
    /// not anything was sent.
    /// </returns>
    /// <remarks>
    /// Nothing is changed here. The address only moves once the person holding the new inbox
    /// clicks the link and the host calls <see cref="ConfirmEmailChangeAsync"/>, which is
    /// the point: it proves they own the address before it becomes their sign-in identity.
    /// <para>
    /// The invariable success is deliberate. This library requires unique emails, so telling
    /// the caller "that address is taken" would let any signed-in user enumerate who else is
    /// registered. An address already in use simply receives nothing, exactly as Microsoft's
    /// own scaffolded page behaves.
    /// </para>
    /// <para>
    /// The token is bound to <paramref name="newEmail"/>, so one issued for one address
    /// cannot be replayed to claim another.
    /// </para>
    /// </remarks>
    Task<AuthResult> RequestEmailChangeAsync(string userId, string newEmail);

    /// <summary>
    /// Completes an email change using the token from the confirmation link.
    /// </summary>
    /// <param name="userId">The user id carried in the link.</param>
    /// <param name="newEmail">The new address carried in the link.</param>
    /// <param name="token">The change token.</param>
    /// <returns>
    /// <see cref="AuthStatus.Succeeded"/>, or <see cref="AuthStatus.Failed"/> for an unknown
    /// user, a bad or expired token, or an address taken since the link was sent.
    /// </returns>
    /// <remarks>
    /// The new address is marked confirmed on success, since clicking the link is the proof. The
    /// user's other sessions are invalidated, since their sign-in identity just changed.
    /// </remarks>
    Task<AuthResult> ConfirmEmailChangeAsync(string userId, string newEmail, string token);

    /// <summary>
    /// Sets a user's phone number. <strong>The number is not verified.</strong>
    /// </summary>
    /// <param name="userId">The user's id.</param>
    /// <param name="phoneNumber">The number to store, or null to clear it.</param>
    /// <returns>
    /// <see cref="AuthStatus.Succeeded"/>, or <see cref="AuthStatus.Rejected"/> for an
    /// unknown user.
    /// </returns>
    /// <remarks>
    /// <strong>This stores a number; it does not prove anyone owns it.</strong> Do not treat
    /// it as a second factor or a recovery channel: a user can type anyone's number here.
    /// <para>
    /// That is a deliberate limit, not an oversight. Verifying a number means sending a code
    /// to it, ASP.NET Core Identity has no SMS sender of any kind, and this library only
    /// knows how to send email. Microsoft's own scaffolded page takes the same position and
    /// calls the same unverified API. If you need a verified number, deliver the code
    /// yourself with Identity's phone token provider.
    /// </para>
    /// </remarks>
    Task<AuthResult> SetPhoneNumberAsync(string userId, string? phoneNumber);

    /// <summary>
    /// Whether two-factor authentication is on for a user.
    /// </summary>
    /// <param name="userId">The user's id.</param>
    Task<bool> IsTwoFactorEnabledAsync(string userId);

    /// <summary>
    /// Produces the shared key and <c>otpauth://</c> URI for adding this account to an
    /// authenticator app.
    /// </summary>
    /// <param name="userId">The user's id.</param>
    /// <returns>The setup material, or <see langword="null"/> for an unknown user.</returns>
    /// <remarks>
    /// This does not turn two-factor on. Show the user the key or a QR code built from the
    /// URI, then call <see cref="EnableTwoFactorAsync"/> with a code from their app, which
    /// is what proves the app is really configured before they start depending on it.
    /// <para>
    /// A user without a key gets one here. An existing key is reused, so calling this twice
    /// while someone fumbles the setup page does not invalidate the app they just added.
    /// </para>
    /// </remarks>
    Task<TwoFactorSetup?> BeginTwoFactorSetupAsync(string userId);

    /// <summary>
    /// Turns two-factor authentication on, once a code proves the authenticator app works.
    /// </summary>
    /// <param name="userId">The user's id.</param>
    /// <param name="code">A current code from the user's authenticator app.</param>
    /// <returns>
    /// <see cref="AuthStatus.Succeeded"/>, or <see cref="AuthStatus.Rejected"/> for an
    /// unknown user or a code that does not check out.
    /// </returns>
    /// <remarks>
    /// The code is verified first, deliberately. Enabling two-factor on an app that was never
    /// really set up locks the user out of their own account with no way back except recovery
    /// codes they have not been given yet.
    /// <para>
    /// Generate recovery codes straight after with
    /// <see cref="GenerateRecoveryCodesAsync"/>. A user whose phone is lost or wiped has no
    /// other route back in.
    /// </para>
    /// </remarks>
    Task<AuthResult> EnableTwoFactorAsync(string userId, string code);

    /// <summary>
    /// Turns two-factor authentication off.
    /// </summary>
    /// <param name="userId">The user's id.</param>
    /// <returns>
    /// <see cref="AuthStatus.Succeeded"/>, or <see cref="AuthStatus.Rejected"/> for an
    /// unknown user.
    /// </returns>
    /// <remarks>
    /// This only stops the second factor being demanded. It deliberately leaves the
    /// authenticator key alone, so re-enabling later works with the app the user already
    /// has, matching Identity's own behaviour. To cut the existing app off, use
    /// <see cref="ResetAuthenticatorKeyAsync"/>.
    /// </remarks>
    Task<AuthResult> DisableTwoFactorAsync(string userId);

    /// <summary>
    /// Replaces the authenticator key, cutting off any app already holding the old one.
    /// </summary>
    /// <param name="userId">The user's id.</param>
    /// <returns>
    /// <see cref="AuthStatus.Succeeded"/>, or <see cref="AuthStatus.Rejected"/> for an
    /// unknown user.
    /// </returns>
    /// <remarks>
    /// For a user whose device is lost or compromised. Two-factor is switched off as part of
    /// this, because leaving it on with a key nobody holds would lock the account. The user
    /// must run setup again from <see cref="BeginTwoFactorSetupAsync"/>.
    /// </remarks>
    Task<AuthResult> ResetAuthenticatorKeyAsync(string userId);

    /// <summary>
    /// Issues a fresh set of recovery codes, invalidating any previous ones.
    /// </summary>
    /// <param name="userId">The user's id.</param>
    /// <param name="count">How many to issue. Defaults to 10, as Identity's own UI does.</param>
    /// <returns>The codes, or empty for an unknown user.</returns>
    /// <remarks>
    /// <strong>Show these once and store nothing.</strong> They are single-use passwords into
    /// the account; the user is meant to keep them somewhere safe. Never log them.
    /// <para>
    /// This replaces any codes already issued, so a user who still has an old list will find
    /// it dead.
    /// </para>
    /// </remarks>
    Task<IReadOnlyList<string>> GenerateRecoveryCodesAsync(string userId, int count = 10);

    /// <summary>
    /// How many unused recovery codes a user has left.
    /// </summary>
    /// <param name="userId">The user's id.</param>
    /// <remarks>
    /// Worth surfacing. Codes are spent as they are used, and someone who runs out and then
    /// loses their authenticator has lost the account.
    /// </remarks>
    Task<int> CountRecoveryCodesAsync(string userId);
}
