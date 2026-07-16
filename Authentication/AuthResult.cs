namespace Authentication;

/// <summary>
/// The result of an <see cref="IAuthService"/> operation. Expected auth failures are
/// reported here rather than thrown, per <c>rules/security.md</c>.
/// </summary>
/// <remarks>
/// A failure carries no reason. That is the point: see <see cref="AuthStatus.Failed"/>.
/// </remarks>
public sealed class AuthResult
{
    private static readonly AuthResult SucceededResult = new(AuthStatus.Succeeded, []);
    private static readonly AuthResult FailedResult = new(AuthStatus.Failed, []);
    private static readonly AuthResult TwoFactorResult = new(AuthStatus.RequiresTwoFactor, []);

    private AuthResult(AuthStatus status, IReadOnlyList<string> errors)
    {
        Status = status;
        Errors = errors;
    }

    /// <summary>
    /// What happened.
    /// </summary>
    public AuthStatus Status { get; }

    /// <summary>
    /// Human-readable messages explaining a <see cref="AuthStatus.PasswordRejected"/> or
    /// <see cref="AuthStatus.Rejected"/> result. Empty for every other status.
    /// </summary>
    /// <remarks>
    /// Everything here is safe to show the caller: password-policy messages describe the
    /// password just submitted, and role-operation messages describe a request made by
    /// your own code about an id it already holds. Identity's account-disclosing errors,
    /// <c>DuplicateUserName</c> and <c>DuplicateEmail</c> above all, never appear here,
    /// and neither does the reason behind an <see cref="AuthStatus.Failed"/>.
    /// </remarks>
    public IReadOnlyList<string> Errors { get; }

    /// <summary>
    /// Whether the operation succeeded.
    /// </summary>
    public bool Succeeded => Status == AuthStatus.Succeeded;

    /// <summary>
    /// The operation succeeded.
    /// </summary>
    /// <returns>A succeeded result.</returns>
    public static AuthResult Success() => SucceededResult;

    /// <summary>
    /// The operation failed, with no reason disclosed.
    /// </summary>
    /// <returns>A generic failed result.</returns>
    public static AuthResult Failure() => FailedResult;

    /// <summary>
    /// The password was correct and a second factor is required.
    /// </summary>
    /// <returns>A two-factor-required result.</returns>
    public static AuthResult TwoFactorRequired() => TwoFactorResult;

    /// <summary>
    /// The password did not satisfy the password policy.
    /// </summary>
    /// <param name="errors">The policy messages to relay to the caller.</param>
    /// <returns>A password-rejected result carrying <paramref name="errors"/>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="errors"/> is null.</exception>
    public static AuthResult PasswordRejected(IEnumerable<string> errors)
    {
        ArgumentNullException.ThrowIfNull(errors);
        return new AuthResult(AuthStatus.PasswordRejected, [.. errors]);
    }

    /// <summary>
    /// An administrative operation was refused, with the reason given.
    /// </summary>
    /// <param name="errors">The reasons to relay to the caller.</param>
    /// <returns>A rejected result carrying <paramref name="errors"/>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="errors"/> is null.</exception>
    public static AuthResult Rejected(IEnumerable<string> errors)
    {
        ArgumentNullException.ThrowIfNull(errors);
        return new AuthResult(AuthStatus.Rejected, [.. errors]);
    }

    /// <summary>
    /// An administrative operation was refused, with a single reason.
    /// </summary>
    /// <param name="error">The reason to relay to the caller.</param>
    /// <returns>A rejected result carrying <paramref name="error"/>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="error"/> is null.</exception>
    public static AuthResult Rejected(string error)
    {
        ArgumentNullException.ThrowIfNull(error);
        return new AuthResult(AuthStatus.Rejected, [error]);
    }
}
