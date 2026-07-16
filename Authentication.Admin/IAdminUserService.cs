using Microsoft.AspNetCore.Identity;

namespace Authentication.Admin;

/// <summary>
/// The user-lifecycle operations an admin performs on other users: list, view, and the
/// account actions the core library does not wrap.
/// </summary>
/// <remarks>
/// This interface is non-generic so the admin controllers never see the user type. The
/// implementation is generic over the host's user type and closed at the mount call, exactly
/// as <see cref="IRoleService"/> is by <c>RoleService&lt;TUser&gt;</c>.
/// <para>
/// It carries only the operations that require Microsoft's <see cref="UserManager{TUser}"/>
/// directly, because the core library exposes no wrapper for them: enumerate users, read a
/// user's full detail, lock, unlock, delete, force-confirm an email, admin-reset a password,
/// and force a sign-out. Role changes stay on <see cref="IRoleService"/> and two-factor and
/// phone changes stay on <see cref="IAccountService"/>, because those seams already refresh
/// the security stamp; duplicating them here would only be a second way to get it wrong.
/// </para>
/// <para>
/// <strong>Every mutation here is complete.</strong> A raw <see cref="UserManager{TUser}"/>
/// lockout, force-confirm, or admin password reset does not always refresh the user's security
/// stamp, so a naive call would leave the target's already-issued cookies working - a locked
/// user who stays signed in. The methods here refresh the stamp where the operation is meant
/// to end the target's sessions, so the change takes effect within
/// <see cref="ReusableAuthOptions.SecurityStampValidationInterval"/> on every session that
/// user has open. <see cref="UnlockAsync"/> is the deliberate exception: it re-enables future
/// sign-in and touches no live session, so it does not rotate.
/// </para>
/// <para>
/// These are administrative operations behind the admin role gate, so failures are
/// <em>explained</em> (<see cref="AuthStatus.Rejected"/> with <see cref="AuthResult.Errors"/>),
/// the same posture as <see cref="IRoleService"/>. The non-enumeration rule protects anonymous
/// and self-service callers, not a trusted administrator.
/// </para>
/// </remarks>
public interface IAdminUserService
{
    /// <summary>
    /// Returns a page of users, optionally filtered by a search term.
    /// </summary>
    /// <param name="query">The search term and page to return.</param>
    /// <returns>The matching users and the paging metadata for the list view.</returns>
    Task<AdminUserPage> ListAsync(AdminUserQuery query);

    /// <summary>
    /// Returns one user's full detail, or <see langword="null"/> if no such user exists.
    /// </summary>
    /// <param name="userId">The Identity user id.</param>
    Task<AdminUserDetail?> GetAsync(string userId);

    /// <summary>
    /// Resolves an email address to its user id, or <see langword="null"/> if none matches.
    /// </summary>
    /// <param name="email">The email to look up.</param>
    /// <remarks>
    /// For the first-admin setup, which works from an email the operator typed and needs the
    /// stable id to grant the role. Behind the admin gate (and the setup seal), so an admin
    /// resolving an email to an id discloses nothing an anonymous caller could reach.
    /// </remarks>
    Task<string?> FindIdByEmailAsync(string email);

    /// <summary>
    /// Locks a user out until <paramref name="until"/>, and ends their live sessions.
    /// </summary>
    /// <param name="userId">The user to lock.</param>
    /// <param name="until">When the lockout ends.</param>
    /// <returns><see cref="AuthStatus.Succeeded"/>, or <see cref="AuthStatus.Rejected"/>.</returns>
    /// <remarks>Refreshes the security stamp, so an already-signed-in user is cut off.</remarks>
    Task<AuthResult> LockAsync(string userId, DateTimeOffset until);

    /// <summary>
    /// Clears a user's lockout, allowing sign-in again.
    /// </summary>
    /// <param name="userId">The user to unlock.</param>
    /// <remarks>
    /// Does not refresh the security stamp: unlocking only affects future sign-in, and the
    /// user is by definition not in a live session to end.
    /// </remarks>
    Task<AuthResult> UnlockAsync(string userId);

    /// <summary>
    /// Deletes a user. Their sessions stop working once the account is gone.
    /// </summary>
    /// <param name="userId">The user to delete.</param>
    Task<AuthResult> DeleteAsync(string userId);

    /// <summary>
    /// Marks a user's email confirmed without the emailed link, and ends their live sessions.
    /// </summary>
    /// <param name="userId">The user to confirm.</param>
    /// <remarks>Refreshes the security stamp.</remarks>
    Task<AuthResult> ForceConfirmEmailAsync(string userId);

    /// <summary>
    /// Sets a user's password directly, without the emailed reset token, and ends their live
    /// sessions.
    /// </summary>
    /// <param name="userId">The user whose password to set.</param>
    /// <param name="newPassword">
    /// The new password, or <see langword="null"/> to have one generated that satisfies the
    /// configured policy and returned once for display.
    /// </param>
    /// <remarks>Refreshes the security stamp.</remarks>
    Task<AdminPasswordResetResult> ResetPasswordAsync(string userId, string? newPassword);

    /// <summary>
    /// Ends every open session for a user, without changing anything else about the account.
    /// </summary>
    /// <param name="userId">The user to sign out everywhere.</param>
    /// <remarks>Refreshing the security stamp is the operation.</remarks>
    Task<AuthResult> ForceSignOutAsync(string userId);
}
