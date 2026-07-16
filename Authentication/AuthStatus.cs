namespace Authentication;

/// <summary>
/// The outcome of an <see cref="IAuthService"/> operation.
/// </summary>
/// <remarks>
/// This deliberately has fewer states than ASP.NET Core Identity's
/// <c>SignInResult</c>. Identity distinguishes "locked out" and "not allowed" from a
/// plain failure, and returns those <em>before</em> it verifies the password, so a
/// caller who does not know the password can still learn that an account exists just
/// by reading the result. This library collapses those cases into
/// <see cref="Failed"/> instead, per the no-user-enumeration rule in
/// <c>rules/security.md</c>.
/// </remarks>
public enum AuthStatus
{
    /// <summary>
    /// The operation succeeded.
    /// </summary>
    /// <remarks>
    /// For registration this means "the request was accepted", not necessarily "a new
    /// account was created": a registration against an already-registered address
    /// reports success and notifies the existing address out of band, because saying
    /// anything else would confirm the account exists. See
    /// <see cref="IAuthService.RegisterAsync"/>.
    /// </remarks>
    Succeeded = 0,

    /// <summary>
    /// The operation failed. Deliberately generic and carries no reason.
    /// </summary>
    /// <remarks>
    /// Returned for an unknown user, a wrong password, a locked-out account, an
    /// unconfirmed account, and a rejected or expired token alike. The cases are
    /// indistinguishable to the caller by design; distinguishing them is what leaks
    /// account existence. The host can still tell the user something useful over a
    /// channel that already proves ownership, such as email.
    /// </remarks>
    Failed = 1,

    /// <summary>
    /// The password was correct and a second factor is now required.
    /// </summary>
    /// <remarks>
    /// Safe to surface, unlike lockout: Identity only reaches this state <em>after</em>
    /// verifying the password, so a caller seeing it has already proved they hold the
    /// credentials. It reveals nothing to someone guessing.
    /// </remarks>
    RequiresTwoFactor = 2,

    /// <summary>
    /// The supplied password did not meet the configured password policy.
    /// </summary>
    /// <remarks>
    /// Distinct from <see cref="Failed"/> because it describes the password the caller
    /// just typed, not whether any account exists, so it leaks nothing, and swallowing
    /// it would leave a caller unable to tell why registration never completed.
    /// Accompanied by the policy messages in <see cref="AuthResult.Errors"/>.
    /// </remarks>
    PasswordRejected = 3,

    /// <summary>
    /// An administrative operation was refused, and <see cref="AuthResult.Errors"/> says
    /// why.
    /// </summary>
    /// <remarks>
    /// Used by role management: no such role, no such user, already a member, not a
    /// member. These are explained rather than hidden because they are not disclosures:
    /// role operations are called by your own trusted code with an id it already holds,
    /// not by an anonymous visitor probing for accounts. Hiding the reason there would
    /// buy no security and make every failure undebuggable.
    /// </remarks>
    Rejected = 4,
}
