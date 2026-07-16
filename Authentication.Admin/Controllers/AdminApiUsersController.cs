using Microsoft.AspNetCore.Mvc;

// See SetupController for why controllers suppress CS1591.
#pragma warning disable CS1591

namespace Authentication.Admin.Controllers;

/// <summary>
/// The JSON user API: the same user-lifecycle operations as the MVC pages, for a separate
/// frontend or SPA. Calls the same services, so the behaviour - including the security-stamp
/// rotation and the last-admin guard - is identical to the UI.
/// </summary>
[Route("api/users")]
public sealed class AdminApiUsersController : AdminApiController
{
    private readonly IAdminUserService _users;
    private readonly IRoleService _roles;
    private readonly IAccountService _accounts;
    private readonly LastAdminGuard _guard;
    private readonly TimeProvider _clock;

    public AdminApiUsersController(
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

    [HttpGet("")]
    public async Task<ActionResult<AdminUserPage>> List([FromQuery] string? search, [FromQuery] int page = 1)
        => await _users.ListAsync(new AdminUserQuery(search, page));

    [HttpGet("{id}")]
    public async Task<ActionResult<AdminUserDetail>> Get(string id)
    {
        AdminUserDetail? user = await _users.GetAsync(id);
        return user is null ? NotFound() : user;
    }

    [HttpPost("{id}/lock")]
    public async Task<IActionResult> Lock(string id, [FromBody] LockRequest request)
    {
        if (await _guard.WouldLeaveNoAdminsAsync(id))
        {
            return Failure(AuthResult.Rejected("You cannot lock the last administrator."));
        }

        DateTimeOffset until = _clock.GetUtcNow().AddDays(Math.Clamp(request.Days, 1, 3650));
        return FromResult(await _users.LockAsync(id, until));
    }

    [HttpPost("{id}/unlock")]
    public async Task<IActionResult> Unlock(string id)
        => FromResult(await _users.UnlockAsync(id));

    [HttpDelete("{id}")]
    public async Task<IActionResult> Delete(string id)
    {
        if (await _guard.WouldLeaveNoAdminsAsync(id))
        {
            return Failure(AuthResult.Rejected("You cannot delete the last administrator."));
        }

        return FromResult(await _users.DeleteAsync(id));
    }

    [HttpPost("{id}/confirm-email")]
    public async Task<IActionResult> ConfirmEmail(string id)
        => FromResult(await _users.ForceConfirmEmailAsync(id));

    // no-store: the response carries a one-time generated password; keep it out of every cache
    // (browser, proxy, intermediary). See the response-caching docs.
    [HttpPost("{id}/reset-password")]
    [ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
    public async Task<IActionResult> ResetPassword(string id, [FromBody] ResetPasswordRequest request)
    {
        AdminPasswordResetResult result = await _users.ResetPasswordAsync(id, request.NewPassword);
        if (!result.Succeeded)
        {
            return Failure(AuthResult.Rejected(result.Errors));
        }

        // The generated password (if any) is returned once, over HTTPS, for the client to show.
        return Ok(new { generatedPassword = result.GeneratedPassword });
    }

    [HttpPost("{id}/force-signout")]
    public async Task<IActionResult> ForceSignOut(string id)
        => FromResult(await _users.ForceSignOutAsync(id));

    [HttpPut("{id}/phone")]
    public async Task<IActionResult> SetPhone(string id, [FromBody] PhoneRequest request)
        => FromResult(await _accounts.SetPhoneNumberAsync(id, request.PhoneNumber));

    [HttpPost("{id}/roles")]
    public async Task<IActionResult> AddRole(string id, [FromBody] RoleRequest request)
        => FromResult(await _roles.AddToRoleAsync(id, request.RoleName));

    [HttpDelete("{id}/roles/{roleName}")]
    public async Task<IActionResult> RemoveRole(string id, string roleName)
    {
        if (_guard.IsAdminRole(roleName) && await _guard.WouldLeaveNoAdminsAsync(id))
        {
            return Failure(AuthResult.Rejected("You cannot remove the last administrator's admin role."));
        }

        return FromResult(await _roles.RemoveFromRoleAsync(id, roleName));
    }

    [HttpPost("{id}/two-factor/disable")]
    public async Task<IActionResult> DisableTwoFactor(string id)
        => FromResult(await _accounts.DisableTwoFactorAsync(id));

    [HttpPost("{id}/two-factor/reset-key")]
    public async Task<IActionResult> ResetAuthenticator(string id)
        => FromResult(await _accounts.ResetAuthenticatorKeyAsync(id));

    // no-store: the response carries one-time recovery codes.
    [HttpPost("{id}/two-factor/recovery-codes")]
    [ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
    public async Task<IActionResult> RegenerateRecoveryCodes(string id)
    {
        IReadOnlyList<string> codes = await _accounts.GenerateRecoveryCodesAsync(id);
        return Ok(new { recoveryCodes = codes });
    }
}

/// <summary>Lock request: how many days to lock for.</summary>
public sealed record LockRequest(int Days = 30);

/// <summary>Admin password reset: a new password, or null to have one generated.</summary>
public sealed record ResetPasswordRequest(string? NewPassword);

/// <summary>Set-phone request.</summary>
public sealed record PhoneRequest(string? PhoneNumber);

/// <summary>Role add request.</summary>
public sealed record RoleRequest(string RoleName);
