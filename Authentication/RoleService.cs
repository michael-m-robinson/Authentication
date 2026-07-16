using Microsoft.AspNetCore.Identity;

namespace Authentication;

/// <summary>
/// The default <see cref="IRoleService"/>, over Identity's
/// <see cref="RoleManager{TRole}"/> and <see cref="UserManager{TUser}"/>.
/// </summary>
/// <typeparam name="TUser">The Identity user type.</typeparam>
/// <remarks>
/// Microsoft's managers do the work. What this class adds is the two things they leave to
/// the caller: refusing input that would otherwise throw out of the store, and refreshing
/// the security stamp so a role change actually reaches sessions that are already open.
/// </remarks>
internal sealed class RoleService<TUser> : IRoleService
    where TUser : IdentityUser<string>, new()
{
    private readonly UserManager<TUser> _userManager;
    private readonly RoleManager<IdentityRole> _roleManager;

    public RoleService(UserManager<TUser> userManager, RoleManager<IdentityRole> roleManager)
    {
        _userManager = userManager;
        _roleManager = roleManager;
    }

    public async Task<AuthResult> CreateRoleAsync(string roleName)
    {
        if (string.IsNullOrWhiteSpace(roleName))
        {
            return AuthResult.Rejected("A role name is required.");
        }

        if (await _roleManager.RoleExistsAsync(roleName))
        {
            return AuthResult.Rejected($"The role '{roleName}' already exists.");
        }

        IdentityResult created = await _roleManager.CreateAsync(new IdentityRole(roleName));

        return created.Succeeded
            ? AuthResult.Success()
            : Rejected(created);
    }

    public async Task<AuthResult> DeleteRoleAsync(string roleName)
    {
        IdentityRole? role = await FindRoleAsync(roleName);
        if (role is null)
        {
            return AuthResult.Rejected($"No role named '{roleName}' exists.");
        }

        // Read the membership BEFORE deleting: Identity cascade-deletes the join rows, so
        // afterwards there is no record of who to tell.
        IList<TUser> members = await _userManager.GetUsersInRoleAsync(role.Name!);

        IdentityResult deleted = await _roleManager.DeleteAsync(role);
        if (!deleted.Succeeded)
        {
            return Rejected(deleted);
        }

        // Deleting the role does not take it off anyone who is signed in. Their cookie
        // still carries the role claim, so [Authorize(Roles = "...")] would keep admitting
        // them to a role that no longer exists, until the cookie expired. Refreshing each
        // member's stamp forces their sessions to be rebuilt without it.
        foreach (TUser member in members)
        {
            await _userManager.UpdateSecurityStampAsync(member);
        }

        return AuthResult.Success();
    }

    public async Task<bool> RoleExistsAsync(string roleName)
    {
        if (string.IsNullOrWhiteSpace(roleName))
        {
            return false;
        }

        return await _roleManager.RoleExistsAsync(roleName);
    }

    public Task<IReadOnlyList<string>> GetRolesAsync()
    {
        IReadOnlyList<string> roles = [.. _roleManager.Roles
            .Select(r => r.Name)
            .Where(name => name != null)
            .Select(name => name!)];

        return Task.FromResult(roles);
    }

    public async Task<AuthResult> AddToRoleAsync(string userId, string roleName)
    {
        (TUser? user, IdentityRole? role, AuthResult? rejection) = await ResolveAsync(userId, roleName);
        if (rejection is not null)
        {
            return rejection;
        }

        if (await _userManager.IsInRoleAsync(user!, role!.Name!))
        {
            return AuthResult.Rejected($"The user is already in the role '{role.Name}'.");
        }

        IdentityResult added = await _userManager.AddToRoleAsync(user!, role.Name!);
        if (!added.Succeeded)
        {
            return Rejected(added);
        }

        return await RefreshPrivilegesAsync(user!);
    }

    public async Task<AuthResult> RemoveFromRoleAsync(string userId, string roleName)
    {
        (TUser? user, IdentityRole? role, AuthResult? rejection) = await ResolveAsync(userId, roleName);
        if (rejection is not null)
        {
            return rejection;
        }

        if (!await _userManager.IsInRoleAsync(user!, role!.Name!))
        {
            return AuthResult.Rejected($"The user is not in the role '{role.Name}'.");
        }

        IdentityResult removed = await _userManager.RemoveFromRoleAsync(user!, role.Name!);
        if (!removed.Succeeded)
        {
            return Rejected(removed);
        }

        return await RefreshPrivilegesAsync(user!);
    }

    public async Task<IReadOnlyList<string>> GetUserRolesAsync(string userId)
    {
        TUser? user = await FindUserAsync(userId);
        if (user is null)
        {
            return [];
        }

        return [.. await _userManager.GetRolesAsync(user)];
    }

    public async Task<bool> IsInRoleAsync(string userId, string roleName)
    {
        if (string.IsNullOrWhiteSpace(roleName))
        {
            return false;
        }

        TUser? user = await FindUserAsync(userId);

        return user is not null && await _userManager.IsInRoleAsync(user, roleName);
    }

    public async Task<IReadOnlyList<string>> GetUsersInRoleAsync(string roleName)
    {
        if (string.IsNullOrWhiteSpace(roleName))
        {
            return [];
        }

        IList<TUser> users = await _userManager.GetUsersInRoleAsync(roleName);

        return [.. users.Select(u => u.Id)];
    }

    /// <summary>
    /// Resolves both the user and the role, or explains which one is missing.
    /// </summary>
    /// <remarks>
    /// The role lookup is not a courtesy. <c>UserManager.AddToRoleAsync</c> against a role
    /// that does not exist does not return a failed <see cref="IdentityResult"/> — the EF
    /// store throws a raw <see cref="InvalidOperationException"/> out of it, which would
    /// surface as a 500. Checking first turns a typo'd role name into an ordinary handled
    /// result, as <c>rules/security.md</c> requires.
    /// </remarks>
    private async Task<(TUser? User, IdentityRole? Role, AuthResult? Rejection)> ResolveAsync(
        string userId,
        string roleName)
    {
        if (string.IsNullOrWhiteSpace(roleName))
        {
            return (null, null, AuthResult.Rejected("A role name is required."));
        }

        TUser? user = await FindUserAsync(userId);
        if (user is null)
        {
            return (null, null, AuthResult.Rejected("No such user."));
        }

        IdentityRole? role = await FindRoleAsync(roleName);
        if (role is null)
        {
            return (null, null, AuthResult.Rejected($"No role named '{roleName}' exists."));
        }

        return (user, role, null);
    }

    /// <summary>
    /// Makes a privilege change take effect on sessions that are already open.
    /// </summary>
    /// <remarks>
    /// Identity refreshes the security stamp when a password changes but not when roles
    /// do, so without this the user keeps whatever roles their cookie was minted with —
    /// which on a removal means keeping access that was just revoked. Refreshing the stamp
    /// makes every open session for that user rebuild its claims within
    /// <see cref="ReusableAuthOptions.SecurityStampValidationInterval"/>.
    /// </remarks>
    private async Task<AuthResult> RefreshPrivilegesAsync(TUser user)
    {
        IdentityResult stamped = await _userManager.UpdateSecurityStampAsync(user);

        return stamped.Succeeded ? AuthResult.Success() : Rejected(stamped);
    }

    private async Task<TUser?> FindUserAsync(string userId)
        => string.IsNullOrWhiteSpace(userId) ? null : await _userManager.FindByIdAsync(userId);

    private async Task<IdentityRole?> FindRoleAsync(string roleName)
        => string.IsNullOrWhiteSpace(roleName) ? null : await _roleManager.FindByNameAsync(roleName);

    private static AuthResult Rejected(IdentityResult result)
        => AuthResult.Rejected(result.Errors.Select(e => e.Description));
}
