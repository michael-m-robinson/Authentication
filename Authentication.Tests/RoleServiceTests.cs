using Authentication;
using Authentication.Tests.Fakes;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;

namespace Authentication.Tests;

/// <summary>
/// Covers role management, and above all that removing a role actually takes the access
/// away rather than only the database row.
/// </summary>
public sealed class RoleServiceTests : IDisposable
{
    private const string Password = "Correct-horse-9!";

    private readonly ServiceProvider _provider;
    private readonly IServiceScope _scope;

    public RoleServiceTests()
    {
        ServiceCollection services = new();
        services.AddLogging();
        services.AddDataProtection();
        services.AddReusableAuth();
        services.AddSingleton<IUserStore<ReusableAuthUser>, InMemoryUserStore>();
        services.AddSingleton<IRoleStore<IdentityRole>, InMemoryRoleStore>();
        services.AddSingleton<IAuthEmailSender, RecordingEmailSender>();

        _provider = services.BuildServiceProvider();
        _scope = _provider.CreateScope();
    }

    private IRoleService Roles => _scope.ServiceProvider.GetRequiredService<IRoleService>();

    private UserManager<ReusableAuthUser> Users =>
        _scope.ServiceProvider.GetRequiredService<UserManager<ReusableAuthUser>>();

    private async Task<ReusableAuthUser> SeedUserAsync(string email = "person@example.com")
    {
        ReusableAuthUser user = new() { UserName = email, Email = email, EmailConfirmed = true };
        IdentityResult created = await Users.CreateAsync(user, Password);
        Assert.True(created.Succeeded, string.Join(", ", created.Errors.Select(e => e.Description)));
        return user;
    }

    private async Task<string> StampOf(ReusableAuthUser user)
        => await Users.GetSecurityStampAsync(await Users.FindByIdAsync(user.Id) ?? throw new InvalidOperationException());

    // ---- Removing a member ----------------------------------------------------------

    [Fact]
    public async Task RemoveFromRole_TakesTheRoleAway()
    {
        ReusableAuthUser user = await SeedUserAsync();
        await Roles.CreateRoleAsync("Admins");
        await Roles.AddToRoleAsync(user.Id, "Admins");

        AuthResult removed = await Roles.RemoveFromRoleAsync(user.Id, "Admins");

        Assert.Equal(AuthStatus.Succeeded, removed.Status);
        Assert.False(await Roles.IsInRoleAsync(user.Id, "Admins"));
        Assert.DoesNotContain("Admins", await Roles.GetUserRolesAsync(user.Id));
    }

    [Fact]
    public async Task RemoveFromRole_RefreshesTheSecurityStamp()
    {
        // The whole point. Identity does NOT refresh the stamp on a role change, so without
        // this the user keeps a cookie asserting a role you just revoked, and
        // [Authorize(Roles = "Admins")] keeps admitting them until it expires. This is the
        // regression guard for a revoked administrator staying an administrator.
        ReusableAuthUser user = await SeedUserAsync();
        await Roles.CreateRoleAsync("Admins");
        await Roles.AddToRoleAsync(user.Id, "Admins");

        string before = await StampOf(user);
        await Roles.RemoveFromRoleAsync(user.Id, "Admins");

        Assert.NotEqual(before, await StampOf(user));
    }

    [Fact]
    public async Task AddToRole_RefreshesTheSecurityStamp()
    {
        ReusableAuthUser user = await SeedUserAsync();
        await Roles.CreateRoleAsync("Admins");

        string before = await StampOf(user);
        await Roles.AddToRoleAsync(user.Id, "Admins");

        Assert.NotEqual(before, await StampOf(user));
    }

    [Fact]
    public async Task RemoveFromRole_IsRejected_WhenTheUserIsNotAMember()
    {
        ReusableAuthUser user = await SeedUserAsync();
        await Roles.CreateRoleAsync("Admins");

        AuthResult result = await Roles.RemoveFromRoleAsync(user.Id, "Admins");

        // Administrative operations explain themselves; there is no anonymous caller here
        // to disclose anything to.
        Assert.Equal(AuthStatus.Rejected, result.Status);
        Assert.NotEmpty(result.Errors);
    }

    [Fact]
    public async Task RemoveFromRole_IsRejected_ForAnUnknownRoleOrUser()
    {
        ReusableAuthUser user = await SeedUserAsync();

        Assert.Equal(AuthStatus.Rejected, (await Roles.RemoveFromRoleAsync(user.Id, "NoSuchRole")).Status);
        Assert.Equal(AuthStatus.Rejected, (await Roles.RemoveFromRoleAsync("no-such-id", "Admins")).Status);
    }

    // ---- Adding a member ------------------------------------------------------------

    [Fact]
    public async Task AddToRole_MakesTheUserAMember()
    {
        ReusableAuthUser user = await SeedUserAsync();
        await Roles.CreateRoleAsync("Admins");

        AuthResult added = await Roles.AddToRoleAsync(user.Id, "Admins");

        Assert.Equal(AuthStatus.Succeeded, added.Status);
        Assert.True(await Roles.IsInRoleAsync(user.Id, "Admins"));
        Assert.Contains(user.Id, await Roles.GetUsersInRoleAsync("Admins"));
    }

    [Fact]
    public async Task AddToRole_IsRejected_ForARoleThatDoesNotExist()
    {
        ReusableAuthUser user = await SeedUserAsync();

        // Identity would not return a failure here: its EF store throws a raw
        // InvalidOperationException, which would surface as a 500 rather than a handled
        // result. Checking the role first is what turns a typo into an ordinary rejection.
        AuthResult result = await Roles.AddToRoleAsync(user.Id, "NoSuchRole");

        Assert.Equal(AuthStatus.Rejected, result.Status);
        Assert.Contains(result.Errors, e => e.Contains("NoSuchRole", StringComparison.Ordinal));
    }

    [Fact]
    public async Task AddToRole_IsRejected_WhenAlreadyAMember()
    {
        ReusableAuthUser user = await SeedUserAsync();
        await Roles.CreateRoleAsync("Admins");
        await Roles.AddToRoleAsync(user.Id, "Admins");

        Assert.Equal(AuthStatus.Rejected, (await Roles.AddToRoleAsync(user.Id, "Admins")).Status);
    }

    [Fact]
    public async Task AddToRole_IsRejected_ForAnUnknownUser()
    {
        await Roles.CreateRoleAsync("Admins");

        Assert.Equal(AuthStatus.Rejected, (await Roles.AddToRoleAsync("no-such-id", "Admins")).Status);
    }

    // ---- Creating and deleting roles -------------------------------------------------

    [Fact]
    public async Task CreateRole_Works_AndIsRejectedTwice()
    {
        Assert.Equal(AuthStatus.Succeeded, (await Roles.CreateRoleAsync("Admins")).Status);
        Assert.True(await Roles.RoleExistsAsync("Admins"));
        Assert.Contains("Admins", await Roles.GetRolesAsync());

        Assert.Equal(AuthStatus.Rejected, (await Roles.CreateRoleAsync("Admins")).Status);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public async Task CreateRole_IsRejected_ForAnEmptyName(string name)
    {
        Assert.Equal(AuthStatus.Rejected, (await Roles.CreateRoleAsync(name)).Status);
    }

    [Fact]
    public async Task DeleteRole_Works()
    {
        await Roles.CreateRoleAsync("Admins");

        Assert.Equal(AuthStatus.Succeeded, (await Roles.DeleteRoleAsync("Admins")).Status);
        Assert.False(await Roles.RoleExistsAsync("Admins"));
    }

    [Fact]
    public async Task DeleteRole_IsRejected_ForARoleThatDoesNotExist()
    {
        Assert.Equal(AuthStatus.Rejected, (await Roles.DeleteRoleAsync("NoSuchRole")).Status);
    }

    [Fact]
    public async Task DeleteRole_RefreshesEveryMembersStamp()
    {
        // Deleting a role removes the rows, but every member's existing cookie still carries
        // the role claim - so [Authorize(Roles = "Admins")] would keep admitting them to a
        // role that no longer exists. Refreshing each member's stamp is what closes that.
        ReusableAuthUser first = await SeedUserAsync("first@example.com");
        ReusableAuthUser second = await SeedUserAsync("second@example.com");
        await Roles.CreateRoleAsync("Admins");
        await Roles.AddToRoleAsync(first.Id, "Admins");
        await Roles.AddToRoleAsync(second.Id, "Admins");

        string firstBefore = await StampOf(first);
        string secondBefore = await StampOf(second);

        await Roles.DeleteRoleAsync("Admins");

        Assert.NotEqual(firstBefore, await StampOf(first));
        Assert.NotEqual(secondBefore, await StampOf(second));
    }

    [Fact]
    public async Task DeleteRole_DoesNotTouchNonMembers()
    {
        ReusableAuthUser member = await SeedUserAsync("member@example.com");
        ReusableAuthUser bystander = await SeedUserAsync("bystander@example.com");
        await Roles.CreateRoleAsync("Admins");
        await Roles.AddToRoleAsync(member.Id, "Admins");

        string bystanderBefore = await StampOf(bystander);
        await Roles.DeleteRoleAsync("Admins");

        // Signing everyone out because one role was deleted would be a denial of service of
        // our own making.
        Assert.Equal(bystanderBefore, await StampOf(bystander));
    }

    // ---- Lookups ---------------------------------------------------------------------

    [Fact]
    public async Task RoleNamesAreMatchedCaseInsensitively()
    {
        ReusableAuthUser user = await SeedUserAsync();
        await Roles.CreateRoleAsync("Admins");

        // Identity normalises names before they reach the store, so every lookup resolves
        // to the same role regardless of how it is typed.
        Assert.True(await Roles.RoleExistsAsync("aDmInS"));
        Assert.Equal(AuthStatus.Succeeded, (await Roles.AddToRoleAsync(user.Id, "ADMINS")).Status);
        Assert.True(await Roles.IsInRoleAsync(user.Id, "admins"));

        // The casing that comes back out is a store behaviour - the real store joins to the
        // roles table and returns the original - so it is asserted against the real EF store
        // in Authentication.EntityFrameworkCore.Tests, not against this fake.
    }

    [Fact]
    public async Task Lookups_AreEmpty_ForUnknownUsersAndRoles()
    {
        Assert.Empty(await Roles.GetUserRolesAsync("no-such-id"));
        Assert.Empty(await Roles.GetUsersInRoleAsync("NoSuchRole"));
        Assert.False(await Roles.IsInRoleAsync("no-such-id", "Admins"));
        Assert.False(await Roles.RoleExistsAsync("NoSuchRole"));
    }

    public void Dispose()
    {
        _scope.Dispose();
        _provider.Dispose();
    }
}
