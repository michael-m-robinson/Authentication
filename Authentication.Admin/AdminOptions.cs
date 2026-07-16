namespace Authentication.Admin;

/// <summary>
/// Configuration for the admin panel. Every value defaults to a safe, conventional choice,
/// so a host that mounts the admin with no configuration gets a working, secured panel at
/// <c>/admin</c> gated behind the <c>Admin</c> role.
/// </summary>
public sealed class AdminOptions
{
    /// <summary>
    /// The role a user must hold to reach the admin panel. Defaults to <c>Admin</c>.
    /// </summary>
    /// <remarks>
    /// This is the role the panel checks, the role the first-admin setup grants, and the role
    /// the bootstrapper ensures exists at startup. It is compared <em>case-sensitively</em> by
    /// <c>[Authorize(Roles = ...)]</c> even though Identity looks roles up case-insensitively,
    /// so the admin controllers carry the literal string <c>"Admin"</c>. Changing this to a
    /// different name is supported for the setup and bootstrap flows, but a host that renames
    /// it must also apply its own authorization policy, because the controllers' built-in
    /// attribute cannot read a runtime value. Keeping the default is the recommended path.
    /// </remarks>
    public string AdminRoleName { get; set; } = "Admin";

    /// <summary>
    /// The URL path the admin panel is mounted under, without a leading slash. Defaults to
    /// <c>admin</c>, so the panel lives at <c>/admin</c>.
    /// </summary>
    /// <remarks>
    /// The admin controllers declare routes relative to this prefix, and a routing convention
    /// prepends it, so changing this value moves the whole panel with one setting.
    /// </remarks>
    public string RoutePrefix { get; set; } = "admin";

    /// <summary>
    /// Whether the Social admin surface (broadcast a system announcement, view a user's
    /// alerts) is available. Auto-detected at mount time: <see langword="true"/> when the host
    /// has wired <c>Authentication.Social</c> (an <c>IAlertService</c> is registered),
    /// <see langword="false"/> otherwise.
    /// </summary>
    /// <remarks>
    /// A host may set this explicitly to force the alerts pages off even when Social is
    /// present. Setting it <see langword="true"/> without Social wired will fail when the
    /// alerts controller cannot resolve <c>IAlertService</c>, so the safe direction is to
    /// leave it auto-detected.
    /// </remarks>
    public bool EnableAlerts { get; set; }

    /// <summary>
    /// An optional shared secret the first-admin setup page requires before it will create the
    /// first administrator. Null (the default) means no secret is required.
    /// </summary>
    /// <remarks>
    /// The setup page is only reachable while no administrator exists, and it seals itself the
    /// moment one does. This token is defence-in-depth for that narrow first-run window: with
    /// it set, an attacker who reaches a freshly deployed site still cannot claim the first
    /// admin account without also knowing the secret. Supply it out of band (environment
    /// variable or secret store), never in source.
    /// </remarks>
    public string? SetupToken { get; set; }

    /// <summary>
    /// Whether to ensure the <see cref="AdminRoleName"/> role exists at startup. Defaults to
    /// <see langword="true"/>.
    /// </summary>
    /// <remarks>
    /// Neither the core library nor the EF store package seeds any role, so without this the
    /// <c>Admin</c> role would not exist until something created it, and the first-admin setup
    /// would have to create it on the fly. Leaving this on guarantees the role is present
    /// before the first setup request. The setup flow also ensures the role itself, so turning
    /// this off does not break setup; it only removes the startup guarantee.
    /// </remarks>
    public bool EnsureAdminRoleOnStartup { get; set; } = true;
}
