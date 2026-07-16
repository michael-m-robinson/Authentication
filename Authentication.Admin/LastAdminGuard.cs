namespace Authentication.Admin;

/// <summary>
/// Answers whether an operation on a user would leave the site with no administrator.
/// </summary>
/// <remarks>
/// Deleting, locking, or removing the admin role from the <em>last</em> administrator would
/// lock everyone out of the panel with no way back through it. This guard is the single check
/// both the MVC UI and the JSON API run before those operations, so the rule lives in one place
/// and cannot drift between the two front doors.
/// </remarks>
public sealed class LastAdminGuard
{
    private readonly IRoleService _roles;
    private readonly AdminOptions _options;

    /// <summary>Creates the guard over the role service and admin options.</summary>
    public LastAdminGuard(IRoleService roles, AdminOptions options)
    {
        _roles = roles;
        _options = options;
    }

    /// <summary>
    /// Whether removing admin access from <paramref name="targetUserId"/> would leave no
    /// administrator: true only when the target is an admin and no other admin exists.
    /// </summary>
    public async Task<bool> WouldLeaveNoAdminsAsync(string targetUserId)
    {
        IReadOnlyList<string> admins = await _roles.GetUsersInRoleAsync(_options.AdminRoleName);
        return admins.Contains(targetUserId) && !admins.Any(adminId => adminId != targetUserId);
    }

    /// <summary>Whether <paramref name="roleName"/> is the configured admin role.</summary>
    public bool IsAdminRole(string roleName)
        => string.Equals(roleName, _options.AdminRoleName, StringComparison.OrdinalIgnoreCase);
}
