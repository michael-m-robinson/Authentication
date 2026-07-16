using Authentication.Admin;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

// See SetupController for why controllers suppress CS1591.
#pragma warning disable CS1591

namespace Authentication.Admin.Controllers;

/// <summary>
/// Role management: list roles with their membership, create a role, delete one, and view a
/// role's members. Membership of a user's roles is edited from the user's detail page; this
/// controller is about the roles themselves.
/// </summary>
[Authorize(Policy = AdminPolicies.Panel)]
[Route("roles")]
public sealed class RolesController : Controller
{
    private readonly IRoleService _roles;
    private readonly IAdminUserService _users;
    private readonly AdminOptions _options;

    public RolesController(IRoleService roles, IAdminUserService users, AdminOptions options)
    {
        _roles = roles;
        _users = users;
        _options = options;
    }

    [HttpGet("")]
    public async Task<IActionResult> Index()
    {
        IReadOnlyList<string> names = await _roles.GetRolesAsync();

        List<RoleSummary> roles = new(names.Count);
        foreach (string name in names)
        {
            IReadOnlyList<string> members = await _roles.GetUsersInRoleAsync(name);
            roles.Add(new RoleSummary(name, members.Count, IsAdminRole(name)));
        }

        return View(roles);
    }

    [HttpPost("create")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Create([FromForm] string roleName)
    {
        AuthResult result = await _roles.CreateRoleAsync(roleName);
        TempData[result.Succeeded ? "Status" : "Error"] = result.Succeeded
            ? $"Role '{roleName}' created."
            : string.Join(" ", result.Errors);

        return RedirectToAction(nameof(Index));
    }

    [HttpPost("{name}/delete")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Delete(string name)
    {
        // Never delete the panel's own gate. Losing it would strip admin access from everyone at
        // once, and there is no path back through the panel.
        if (IsAdminRole(name))
        {
            TempData["Error"] = "The admin role cannot be deleted; it is what guards this panel.";
            return RedirectToAction(nameof(Index));
        }

        AuthResult result = await _roles.DeleteRoleAsync(name);
        TempData[result.Succeeded ? "Status" : "Error"] = result.Succeeded
            ? $"Role '{name}' deleted."
            : string.Join(" ", result.Errors);

        return RedirectToAction(nameof(Index));
    }

    [HttpGet("{name}/members")]
    public async Task<IActionResult> Members(string name)
    {
        if (!await _roles.RoleExistsAsync(name))
        {
            return NotFound();
        }

        IReadOnlyList<string> memberIds = await _roles.GetUsersInRoleAsync(name);

        List<MemberRow> members = new(memberIds.Count);
        foreach (string id in memberIds)
        {
            AdminUserDetail? user = await _users.GetAsync(id);
            members.Add(new MemberRow(id, user?.Email));
        }

        return View(new RoleMembersViewModel(name, members));
    }

    private bool IsAdminRole(string roleName)
        => string.Equals(roleName, _options.AdminRoleName, StringComparison.OrdinalIgnoreCase);
}

/// <summary>One role on the list, with how many users hold it.</summary>
public sealed record RoleSummary(string Name, int MemberCount, bool IsAdminRole);

/// <summary>One member of a role.</summary>
public sealed record MemberRow(string Id, string? Email);

/// <summary>A role and its members.</summary>
public sealed record RoleMembersViewModel(string RoleName, IReadOnlyList<MemberRow> Members);
