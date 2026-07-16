using Authentication.Admin;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

// See SetupController for why controllers suppress CS1591.
#pragma warning disable CS1591

namespace Authentication.Admin.Controllers;

/// <summary>
/// The admin landing page: a few counts and the way in to each area.
/// </summary>
[Authorize(Policy = AdminPolicies.Panel)]
[Route("")]
public sealed class DashboardController : Controller
{
    private readonly IAdminUserService _users;
    private readonly IRoleService _roles;
    private readonly AdminOptions _options;

    public DashboardController(IAdminUserService users, IRoleService roles, AdminOptions options)
    {
        _users = users;
        _roles = roles;
        _options = options;
    }

    [HttpGet("")]
    public async Task<IActionResult> Index()
    {
        // One small page of users just to read the total; the list view does the real paging.
        AdminUserPage firstPage = await _users.ListAsync(new AdminUserQuery(Page: 1, PageSize: 1));
        IReadOnlyList<string> roles = await _roles.GetRolesAsync();
        IReadOnlyList<string> admins = await _roles.GetUsersInRoleAsync(_options.AdminRoleName);

        DashboardViewModel model = new(
            UserCount: firstPage.TotalCount,
            RoleCount: roles.Count,
            AdminCount: admins.Count,
            AlertsEnabled: _options.EnableAlerts);

        return View(model);
    }
}

/// <summary>The counts shown on the dashboard.</summary>
public sealed record DashboardViewModel(int UserCount, int RoleCount, int AdminCount, bool AlertsEnabled);
