namespace Authentication.Admin;

/// <summary>
/// Answers the one question the first-admin setup turns on: does an administrator already
/// exist?
/// </summary>
/// <remarks>
/// The answer is read from durable state - the membership of the admin role - on every call,
/// never cached. That is what makes the setup page seal permanently: once an admin exists the
/// answer is true forever, so there is no window in which the page could reopen.
/// <para>
/// <see cref="IRoleService.GetUsersInRoleAsync"/> returns an empty list when the role does not
/// exist, so a brand-new database with no admin role reads correctly as "no admin". Shared by
/// the seal filter (which blocks the page) and the setup controller (which re-checks before it
/// creates the first admin), so the rule lives in exactly one place.
/// </para>
/// </remarks>
internal sealed class SetupState
{
    private readonly IRoleService _roles;
    private readonly AdminOptions _options;

    public SetupState(IRoleService roles, AdminOptions options)
    {
        _roles = roles;
        _options = options;
    }

    /// <summary>
    /// Whether any user currently holds the admin role.
    /// </summary>
    public async Task<bool> AnyAdminExistsAsync()
    {
        IReadOnlyList<string> admins = await _roles.GetUsersInRoleAsync(_options.AdminRoleName);
        return admins.Count > 0;
    }
}
