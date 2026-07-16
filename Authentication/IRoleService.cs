namespace Authentication;

/// <summary>
/// Role management: create and delete roles, and move users in and out of them.
/// </summary>
/// <remarks>
/// Roles are ASP.NET Core Identity roles, so <c>[Authorize(Roles = "Admins")]</c>,
/// <c>User.IsInRole("Admins")</c> and <c>RequireRole</c> all work against them with no
/// extra wiring — the role claims are put into the session cookie by Identity's own
/// claims factory.
/// <para>
/// <strong>Every method here is complete.</strong> Identity's <c>UserManager</c> does not
/// refresh the security stamp when roles change — only when a password does — so a naive
/// <c>AddToRoleAsync</c> leaves the user's existing cookies carrying their old roles until
/// those cookies expire, which for a <em>removal</em> means a revoked administrator stays
/// an administrator. The methods here refresh the stamp themselves, so a role change takes
/// effect within <see cref="ReusableAuthOptions.SecurityStampValidationInterval"/> (1
/// minute by default) on every session that user has open.
/// </para>
/// <para>
/// These are administrative operations, called by your own code with ids it already holds.
/// Unlike <see cref="IAuthService"/>, failures here <em>are</em> explained
/// (<see cref="AuthStatus.Rejected"/> with <see cref="AuthResult.Errors"/>): there is no
/// anonymous caller to disclose anything to, and hiding the reason would only make
/// failures undebuggable.
/// </para>
/// <para>
/// Role names are matched case-insensitively for lookup, but the claim written into the
/// cookie keeps the casing the role was created with — and
/// <c>[Authorize(Roles = "...")]</c> compares that claim <em>case-sensitively</em>. Create
/// "Admins" and authorise on "Admins".
/// </para>
/// </remarks>
public interface IRoleService
{
    /// <summary>
    /// Creates a role.
    /// </summary>
    /// <param name="roleName">The name, e.g. <c>Admins</c>.</param>
    /// <returns>
    /// <see cref="AuthStatus.Succeeded"/>, or <see cref="AuthStatus.Rejected"/> if the
    /// name is empty or already taken.
    /// </returns>
    Task<AuthResult> CreateRoleAsync(string roleName);

    /// <summary>
    /// Deletes a role and strips it from everyone who held it.
    /// </summary>
    /// <param name="roleName">The role to delete.</param>
    /// <returns>
    /// <see cref="AuthStatus.Succeeded"/>, or <see cref="AuthStatus.Rejected"/> if no such
    /// role exists.
    /// </returns>
    /// <remarks>
    /// Deleting a role does not, on its own, take it away from anyone signed in. The
    /// database rows go — Identity cascade-deletes the memberships — but every member's
    /// existing cookie still carries the role claim, so
    /// <c>[Authorize(Roles = "Admins")]</c> would keep letting them through until that
    /// cookie expired, for a role that no longer exists.
    /// <para>
    /// So this refreshes the security stamp of every member as part of the delete, which
    /// costs one store write per member and closes that window to
    /// <see cref="ReusableAuthOptions.SecurityStampValidationInterval"/>. Deleting a role
    /// with very many members is correspondingly expensive.
    /// </para>
    /// </remarks>
    Task<AuthResult> DeleteRoleAsync(string roleName);

    /// <summary>
    /// Whether a role exists.
    /// </summary>
    /// <param name="roleName">The role to look for.</param>
    Task<bool> RoleExistsAsync(string roleName);

    /// <summary>
    /// Every role, by name.
    /// </summary>
    Task<IReadOnlyList<string>> GetRolesAsync();

    /// <summary>
    /// Adds a user to a role.
    /// </summary>
    /// <param name="userId">The user's id.</param>
    /// <param name="roleName">The role to add them to.</param>
    /// <returns>
    /// <see cref="AuthStatus.Succeeded"/>, or <see cref="AuthStatus.Rejected"/> if the
    /// user or role does not exist, or they are already a member.
    /// </returns>
    /// <remarks>
    /// Refreshes the user's security stamp, so their open sessions pick the new role up
    /// rather than waiting for their cookie to expire.
    /// </remarks>
    Task<AuthResult> AddToRoleAsync(string userId, string roleName);

    /// <summary>
    /// Removes a user from a role.
    /// </summary>
    /// <param name="userId">The user's id.</param>
    /// <param name="roleName">The role to remove them from.</param>
    /// <returns>
    /// <see cref="AuthStatus.Succeeded"/>, or <see cref="AuthStatus.Rejected"/> if the
    /// user or role does not exist, or they were not a member.
    /// </returns>
    /// <remarks>
    /// Refreshes the user's security stamp. This is the direction that matters: without
    /// it, revoking a role would leave the user holding a cookie that still claims it, and
    /// they would keep the access you just took away until it expired.
    /// </remarks>
    Task<AuthResult> RemoveFromRoleAsync(string userId, string roleName);

    /// <summary>
    /// The roles a user holds.
    /// </summary>
    /// <param name="userId">The user's id.</param>
    /// <returns>Their roles, or empty if the user does not exist.</returns>
    Task<IReadOnlyList<string>> GetUserRolesAsync(string userId);

    /// <summary>
    /// Whether a user holds a role.
    /// </summary>
    /// <param name="userId">The user's id.</param>
    /// <param name="roleName">The role to check.</param>
    /// <returns><see langword="false"/> if the user does not exist.</returns>
    Task<bool> IsInRoleAsync(string userId, string roleName);

    /// <summary>
    /// The ids of everyone holding a role.
    /// </summary>
    /// <param name="roleName">The role.</param>
    /// <returns>Their user ids, or empty if the role does not exist.</returns>
    Task<IReadOnlyList<string>> GetUsersInRoleAsync(string roleName);
}
