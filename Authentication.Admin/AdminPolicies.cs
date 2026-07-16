namespace Authentication.Admin;

/// <summary>
/// The authorization policy names the admin panel defines.
/// </summary>
public static class AdminPolicies
{
    /// <summary>
    /// Gates every admin page and API endpoint. Registered by <c>AddReusableAuthAdmin</c> as
    /// <c>RequireRole(AdminOptions.AdminRoleName)</c>, so a host that changes the role name has
    /// the gate follow it - unlike a literal <c>[Authorize(Roles = "Admin")]</c>, which only
    /// ever checks the default name.
    /// </summary>
    public const string Panel = "Authentication.Admin.Panel";
}
