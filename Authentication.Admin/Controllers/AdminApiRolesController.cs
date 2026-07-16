using Microsoft.AspNetCore.Mvc;

// See SetupController for why controllers suppress CS1591.
#pragma warning disable CS1591

namespace Authentication.Admin.Controllers;

/// <summary>
/// The JSON roles API: list roles with member counts, create, delete, and read a role's members.
/// The same operations as the MVC roles pages, over the same services.
/// </summary>
[Route("api/roles")]
public sealed class AdminApiRolesController : AdminApiController
{
    private readonly IRoleService _roles;
    private readonly IAdminUserService _users;
    private readonly LastAdminGuard _guard;

    public AdminApiRolesController(IRoleService roles, IAdminUserService users, LastAdminGuard guard)
    {
        _roles = roles;
        _users = users;
        _guard = guard;
    }

    [HttpGet("")]
    public async Task<ActionResult<IReadOnlyList<RoleSummary>>> List()
    {
        IReadOnlyList<string> names = await _roles.GetRolesAsync();

        List<RoleSummary> roles = new(names.Count);
        foreach (string name in names)
        {
            IReadOnlyList<string> members = await _roles.GetUsersInRoleAsync(name);
            roles.Add(new RoleSummary(name, members.Count, _guard.IsAdminRole(name)));
        }

        return roles;
    }

    [HttpPost("")]
    public async Task<IActionResult> Create([FromBody] RoleRequest request)
        => FromResult(await _roles.CreateRoleAsync(request.RoleName));

    [HttpDelete("{name}")]
    public async Task<IActionResult> Delete(string name)
    {
        // Never delete the panel's own gate; it would strip admin access from everyone at once.
        if (_guard.IsAdminRole(name))
        {
            return Failure(AuthResult.Rejected("The admin role cannot be deleted; it guards this panel."));
        }

        return FromResult(await _roles.DeleteRoleAsync(name));
    }

    [HttpGet("{name}/members")]
    public async Task<ActionResult<IReadOnlyList<MemberRow>>> Members(string name)
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

        return members;
    }
}
