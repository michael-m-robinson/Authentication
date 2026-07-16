using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace Authentication.Admin;

/// <summary>
/// The default <see cref="IAdminUserService"/>, over Microsoft's
/// <see cref="UserManager{TUser}"/>.
/// </summary>
/// <typeparam name="TUser">The host's Identity user type.</typeparam>
/// <remarks>
/// Closed over the host's user type at the mount call, exactly as <c>RoleService&lt;TUser&gt;</c>
/// is. It does the two things Microsoft's manager leaves to the caller for these operations:
/// translate an <see cref="IdentityResult"/> into the library's <see cref="AuthResult"/>, and
/// refresh the security stamp so an action that should end a user's sessions actually does.
/// <para>
/// The async paging uses EF Core's queryable extensions, available through the Social package
/// this assembly already references. That touches the query, never a <see cref="DbContext"/>
/// type, so the admin stays store-agnostic: it works against whatever context the host wired,
/// the same way <see cref="UserManager{TUser}"/> does.
/// </para>
/// </remarks>
internal sealed class AdminUserService<TUser> : IAdminUserService
    where TUser : IdentityUser<string>, new()
{
    // A hard ceiling so a caller cannot ask for the whole table in one query.
    private const int MaxPageSize = 200;

    private readonly UserManager<TUser> _userManager;
    private readonly IAccountService _accountService;

    public AdminUserService(UserManager<TUser> userManager, IAccountService accountService)
    {
        _userManager = userManager;
        _accountService = accountService;
    }

    public async Task<AdminUserPage> ListAsync(AdminUserQuery query)
    {
        ArgumentNullException.ThrowIfNull(query);

        int page = Math.Max(1, query.Page);
        int pageSize = Math.Clamp(query.PageSize, 1, MaxPageSize);
        string? search = string.IsNullOrWhiteSpace(query.Search) ? null : query.Search.Trim();

        IQueryable<TUser> users = Filtered(search);

        int total = await users.CountAsync();

        List<TUser> pageItems = await users
            .OrderBy(u => u.Email)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync();

        List<AdminUserSummary> summaries = new(pageItems.Count);
        foreach (TUser user in pageItems)
        {
            summaries.Add(await SummaryAsync(user));
        }

        return new AdminUserPage(summaries, page, pageSize, total, search);
    }

    public async Task<AdminUserDetail?> GetAsync(string userId)
    {
        TUser? user = await FindAsync(userId);
        if (user is null)
        {
            return null;
        }

        IList<string> roles = await _userManager.GetRolesAsync(user);
        int recoveryCodes = await _accountService.CountRecoveryCodesAsync(user.Id);

        return new AdminUserDetail(
            Id: user.Id,
            Email: await _userManager.GetEmailAsync(user),
            EmailConfirmed: await _userManager.IsEmailConfirmedAsync(user),
            PhoneNumber: await _userManager.GetPhoneNumberAsync(user),
            LockoutEnabled: await _userManager.GetLockoutEnabledAsync(user),
            LockoutEnd: await _userManager.GetLockoutEndDateAsync(user),
            LockedOutNow: await _userManager.IsLockedOutAsync(user),
            TwoFactorEnabled: await _userManager.GetTwoFactorEnabledAsync(user),
            RecoveryCodesRemaining: recoveryCodes,
            Roles: roles.ToList());
    }

    public async Task<string?> FindIdByEmailAsync(string email)
    {
        if (string.IsNullOrWhiteSpace(email))
        {
            return null;
        }

        TUser? user = await _userManager.FindByEmailAsync(email);
        return user?.Id;
    }

    public async Task<AuthResult> LockAsync(string userId, DateTimeOffset until)
    {
        TUser? user = await FindAsync(userId);
        if (user is null)
        {
            return AuthResult.Rejected("No such user.");
        }

        IdentityResult enabled = await _userManager.SetLockoutEnabledAsync(user, true);
        if (!enabled.Succeeded)
        {
            return Rejected(enabled);
        }

        IdentityResult locked = await _userManager.SetLockoutEndDateAsync(user, until);
        if (!locked.Succeeded)
        {
            return Rejected(locked);
        }

        // Lockout through the raw manager does not rotate the stamp, so without this the user
        // stays signed in on every cookie they already hold. Rotating ends those sessions.
        return await RotateAsync(user);
    }

    public async Task<AuthResult> UnlockAsync(string userId)
    {
        TUser? user = await FindAsync(userId);
        if (user is null)
        {
            return AuthResult.Rejected("No such user.");
        }

        // Clearing the end date lifts the lockout. No stamp rotation on purpose: this only
        // affects future sign-in, and a locked-out user has no live session to end.
        IdentityResult unlocked = await _userManager.SetLockoutEndDateAsync(user, null);
        return unlocked.Succeeded ? AuthResult.Success() : Rejected(unlocked);
    }

    public async Task<AuthResult> DeleteAsync(string userId)
    {
        TUser? user = await FindAsync(userId);
        if (user is null)
        {
            return AuthResult.Rejected("No such user.");
        }

        // No explicit rotation is possible - the row is gone. The stamp validator can no longer
        // load the user, so it rejects the principal, and the deleted user's sessions stop
        // within the validation interval.
        IdentityResult deleted = await _userManager.DeleteAsync(user);
        return deleted.Succeeded ? AuthResult.Success() : Rejected(deleted);
    }

    public async Task<AuthResult> ForceConfirmEmailAsync(string userId)
    {
        TUser? user = await FindAsync(userId);
        if (user is null)
        {
            return AuthResult.Rejected("No such user.");
        }

        if (await _userManager.IsEmailConfirmedAsync(user))
        {
            return AuthResult.Success();
        }

        user.EmailConfirmed = true;
        IdentityResult updated = await _userManager.UpdateAsync(user);
        if (!updated.Succeeded)
        {
            return Rejected(updated);
        }

        return await RotateAsync(user);
    }

    public async Task<AdminPasswordResetResult> ResetPasswordAsync(string userId, string? newPassword)
    {
        TUser? user = await FindAsync(userId);
        if (user is null)
        {
            return new AdminPasswordResetResult(false, null, ["No such user."]);
        }

        bool generated = string.IsNullOrEmpty(newPassword);
        string password = generated
            ? AdminPasswordGenerator.Generate(_userManager.Options.Password)
            : newPassword!;

        // Mint a reset token and consume it immediately - the exact pair Microsoft's scaffolded
        // Identity UI uses (Areas/Identity/Pages/Account/ResetPassword.cshtml.cs). ResetPassword
        // validates the new password BEFORE mutating anything and rotates the security stamp in
        // one update, so a rejected password leaves the account untouched. The earlier
        // RemovePassword+AddPassword pair was non-atomic: a rejected admin-supplied password
        // could leave the account with no password at all.
        string token = await _userManager.GeneratePasswordResetTokenAsync(user);
        IdentityResult reset = await _userManager.ResetPasswordAsync(user, token, password);
        if (!reset.Succeeded)
        {
            return Failed(reset);
        }

        // ResetPasswordAsync rotated the stamp already, so no explicit rotation here. The test
        // asserts the stamp changed, so a future Identity that stopped rotating would fail it.
        return new AdminPasswordResetResult(true, generated ? password : null, []);
    }

    public async Task<AuthResult> ForceSignOutAsync(string userId)
    {
        TUser? user = await FindAsync(userId);
        if (user is null)
        {
            return AuthResult.Rejected("No such user.");
        }

        // Rotating the stamp is the operation: every open session for this user is rebuilt, and
        // fails, within the validation interval.
        return await RotateAsync(user);
    }

    private IQueryable<TUser> Filtered(string? search)
    {
        IQueryable<TUser> users = _userManager.Users;
        if (search is null)
        {
            return users;
        }

        // Match on the normalized (upper-cased) columns Identity maintains, so the search is
        // case-insensitive without depending on the database collation.
        string term = _userManager.NormalizeEmail(search);
        return users.Where(u =>
            (u.NormalizedEmail != null && u.NormalizedEmail.Contains(term))
            || (u.NormalizedUserName != null && u.NormalizedUserName.Contains(term)));
    }

    private async Task<AdminUserSummary> SummaryAsync(TUser user)
        => new(
            Id: user.Id,
            Email: await _userManager.GetEmailAsync(user),
            EmailConfirmed: await _userManager.IsEmailConfirmedAsync(user),
            LockedOut: await _userManager.IsLockedOutAsync(user),
            TwoFactorEnabled: await _userManager.GetTwoFactorEnabledAsync(user));

    private async Task<TUser?> FindAsync(string userId)
        => string.IsNullOrWhiteSpace(userId) ? null : await _userManager.FindByIdAsync(userId);

    private async Task<AuthResult> RotateAsync(TUser user)
    {
        IdentityResult stamped = await _userManager.UpdateSecurityStampAsync(user);
        return stamped.Succeeded ? AuthResult.Success() : Rejected(stamped);
    }

    private static AuthResult Rejected(IdentityResult result)
        => AuthResult.Rejected(result.Errors.Select(e => e.Description));

    private static AdminPasswordResetResult Failed(IdentityResult result)
        => new(false, null, result.Errors.Select(e => e.Description).ToList());
}
