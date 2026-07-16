using Authentication.Admin;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

// See SetupController for why controllers suppress CS1591.
#pragma warning disable CS1591

namespace Authentication.Admin.Controllers;

/// <summary>
/// The user lifecycle: list and search, view one user, and every account action an admin can
/// take on another user. Mutations go through the services that rotate the security stamp, so a
/// change reaches the target's live sessions.
/// </summary>
[Authorize(Policy = AdminPolicies.Panel)]
[Route("users")]
public sealed class UsersController : Controller
{
    private readonly IAdminUserService _users;
    private readonly IRoleService _roles;
    private readonly IAccountService _accounts;
    private readonly LastAdminGuard _guard;
    private readonly TimeProvider _clock;

    public UsersController(
        IAdminUserService users,
        IRoleService roles,
        IAccountService accounts,
        LastAdminGuard guard,
        TimeProvider clock)
    {
        _users = users;
        _roles = roles;
        _accounts = accounts;
        _guard = guard;
        _clock = clock;
    }

    // ---- Read ---------------------------------------------------------------------------

    [HttpGet("")]
    public async Task<IActionResult> Index(string? search, int page = 1)
        => View(await _users.ListAsync(new AdminUserQuery(search, page)));

    [HttpGet("{id}")]
    public async Task<IActionResult> Details(string id)
    {
        AdminUserDetail? user = await _users.GetAsync(id);
        if (user is null)
        {
            return NotFound();
        }

        return View(new UserDetailViewModel(
            User: user,
            AllRoles: await _roles.GetRolesAsync(),
            GeneratedPassword: TempData["GeneratedPassword"] as string,
            RecoveryCodes: (TempData["RecoveryCodes"] as string)?.Split('\n')));
    }

    // ---- Lockout ------------------------------------------------------------------------

    [HttpPost("{id}/lock")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Lock(string id, [FromForm] int days = 30)
    {
        if (await _guard.WouldLeaveNoAdminsAsync(id))
        {
            return BackToDetails(id, error: "You cannot lock the last administrator; the site would have no admin.");
        }

        DateTimeOffset until = _clock.GetUtcNow().AddDays(Math.Clamp(days, 1, 3650));
        return Result(id, await _users.LockAsync(id, until), $"User locked until {until:d}.");
    }

    [HttpPost("{id}/unlock")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Unlock(string id)
        => Result(id, await _users.UnlockAsync(id), "User unlocked.");

    // ---- Account ------------------------------------------------------------------------

    [HttpPost("{id}/delete")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Delete(string id)
    {
        if (await _guard.WouldLeaveNoAdminsAsync(id))
        {
            return BackToDetails(id, error: "You cannot delete the last administrator.");
        }

        AuthResult result = await _users.DeleteAsync(id);
        if (!result.Succeeded)
        {
            return BackToDetails(id, error: string.Join(" ", result.Errors));
        }

        // The user is gone, so there is no detail page to return to.
        TempData["Status"] = "User deleted.";
        return RedirectToAction(nameof(Index));
    }

    [HttpPost("{id}/confirm")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Confirm(string id)
        => Result(id, await _users.ForceConfirmEmailAsync(id), "Email confirmed.");

    [HttpPost("{id}/reset-password")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ResetPassword(string id, [FromForm] string? newPassword)
    {
        AdminPasswordResetResult result = await _users.ResetPasswordAsync(id, newPassword);
        if (!result.Succeeded)
        {
            return BackToDetails(id, error: string.Join(" ", result.Errors));
        }

        if (result.GeneratedPassword is not null)
        {
            // Carried to the detail page and shown once. Never logged.
            TempData["GeneratedPassword"] = result.GeneratedPassword;
        }

        return BackToDetails(id, status: "Password reset.");
    }

    [HttpPost("{id}/force-signout")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ForceSignOut(string id)
        => Result(id, await _users.ForceSignOutAsync(id), "User signed out of all sessions.");

    [HttpPost("{id}/phone")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> SetPhone(string id, [FromForm] string? phoneNumber)
        => Result(id, await _accounts.SetPhoneNumberAsync(id, phoneNumber), "Phone number updated.");

    // ---- Roles --------------------------------------------------------------------------

    [HttpPost("{id}/roles/add")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> AddRole(string id, [FromForm] string roleName)
        => Result(id, await _roles.AddToRoleAsync(id, roleName), $"Added to {roleName}.");

    [HttpPost("{id}/roles/remove")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> RemoveRole(string id, [FromForm] string roleName)
    {
        if (_guard.IsAdminRole(roleName) && await _guard.WouldLeaveNoAdminsAsync(id))
        {
            return BackToDetails(id, error: "You cannot remove the last administrator's admin role.");
        }

        return Result(id, await _roles.RemoveFromRoleAsync(id, roleName), $"Removed from {roleName}.");
    }

    // ---- Two-factor ---------------------------------------------------------------------

    [HttpPost("{id}/2fa/disable")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> DisableTwoFactor(string id)
        => Result(id, await _accounts.DisableTwoFactorAsync(id), "Two-factor disabled.");

    [HttpPost("{id}/2fa/reset-key")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ResetAuthenticator(string id)
        => Result(id, await _accounts.ResetAuthenticatorKeyAsync(id), "Authenticator key reset; two-factor disabled.");

    [HttpPost("{id}/2fa/recovery-codes")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> RegenerateRecoveryCodes(string id)
    {
        IReadOnlyList<string> codes = await _accounts.GenerateRecoveryCodesAsync(id);
        TempData["RecoveryCodes"] = string.Join('\n', codes);
        return BackToDetails(id, status: "Recovery codes regenerated.");
    }

    // ---- Helpers ------------------------------------------------------------------------

    private IActionResult Result(string id, AuthResult result, string success)
        => result.Succeeded
            ? BackToDetails(id, status: success)
            : BackToDetails(id, error: string.Join(" ", result.Errors));

    private IActionResult BackToDetails(string id, string? status = null, string? error = null)
    {
        if (status is not null)
        {
            TempData["Status"] = status;
        }

        if (error is not null)
        {
            TempData["Error"] = error;
        }

        return RedirectToAction(nameof(Details), new { id });
    }
}

/// <summary>The user detail page: the user, all roles to choose from, and any one-time secrets.</summary>
public sealed record UserDetailViewModel(
    AdminUserDetail User,
    IReadOnlyList<string> AllRoles,
    string? GeneratedPassword,
    IReadOnlyList<string>? RecoveryCodes);
