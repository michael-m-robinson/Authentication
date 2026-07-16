using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;

namespace Authentication.Admin.Tests;

/// <summary>
/// Covers <c>AdminUserService</c> against a real Identity store on SQLite. The heart of it is
/// the security-stamp contract: every action that should end a user's sessions rotates the
/// stamp, and unlock deliberately does not. Each rotation assertion fails if its
/// <c>UpdateSecurityStampAsync</c> line is removed.
/// </summary>
public sealed class AdminUserServiceTests : IDisposable
{
    private readonly AdminTestHost _host = new();

    public void Dispose() => _host.Dispose();

    // ---- Listing and detail -------------------------------------------------------------

    [Fact]
    public async Task ListAsync_PagesAndCounts()
    {
        for (int i = 0; i < 5; i++)
        {
            await _host.CreateUserAsync($"user{i}@example.com");
        }

        using IServiceScope scope = _host.Scope();
        AdminUserPage page = await AdminTestHost.AdminUsers(scope).ListAsync(new AdminUserQuery(Page: 1, PageSize: 2));

        Assert.Equal(2, page.Users.Count);
        Assert.Equal(5, page.TotalCount);
        Assert.Equal(3, page.TotalPages);
        Assert.True(page.HasNext);
        Assert.False(page.HasPrevious);
    }

    [Fact]
    public async Task ListAsync_SearchIsCaseInsensitive()
    {
        await _host.CreateUserAsync("Alice@example.com");
        await _host.CreateUserAsync("bob@example.com");

        using IServiceScope scope = _host.Scope();
        AdminUserPage page = await AdminTestHost.AdminUsers(scope).ListAsync(new AdminUserQuery(Search: "ALICE"));

        Assert.Equal(1, page.TotalCount);
        Assert.Equal("Alice@example.com", page.Users[0].Email);
    }

    [Fact]
    public async Task GetAsync_ReturnsDetail_AndNullForUnknown()
    {
        string id = await _host.CreateUserAsync("detail@example.com");

        using IServiceScope scope = _host.Scope();
        AdminUserService<ReusableAuthUser> admin = AdminTestHost.AdminUsers(scope);

        AdminUserDetail? detail = await admin.GetAsync(id);
        Assert.NotNull(detail);
        Assert.Equal("detail@example.com", detail!.Email);
        Assert.True(detail.EmailConfirmed);
        Assert.False(detail.TwoFactorEnabled);

        Assert.Null(await admin.GetAsync("does-not-exist"));
    }

    // ---- The stamp contract -------------------------------------------------------------

    [Fact]
    public async Task LockAsync_RotatesTheStamp_AndLocksOut()
    {
        string id = await _host.CreateUserAsync("lock@example.com");
        string? before = await _host.SecurityStampAsync(id);

        AuthResult result;
        using (IServiceScope scope = _host.Scope())
        {
            result = await AdminTestHost.AdminUsers(scope).LockAsync(id, DateTimeOffset.UtcNow.AddYears(1));
        }

        Assert.True(result.Succeeded);
        Assert.NotEqual(before, await _host.SecurityStampAsync(id));

        using IServiceScope check = _host.Scope();
        UserManager<ReusableAuthUser> users = check.ServiceProvider.GetRequiredService<UserManager<ReusableAuthUser>>();
        Assert.True(await users.IsLockedOutAsync((await users.FindByIdAsync(id))!));
    }

    [Fact]
    public async Task UnlockAsync_DoesNotRotateTheStamp_AndClearsLockout()
    {
        string id = await _host.CreateUserAsync("unlock@example.com");
        using (IServiceScope lockScope = _host.Scope())
        {
            await AdminTestHost.AdminUsers(lockScope).LockAsync(id, DateTimeOffset.UtcNow.AddYears(1));
        }

        string? afterLock = await _host.SecurityStampAsync(id);

        using (IServiceScope scope = _host.Scope())
        {
            await AdminTestHost.AdminUsers(scope).UnlockAsync(id);
        }

        // The deliberate exception: unlock touches no live session, so it must NOT rotate.
        Assert.Equal(afterLock, await _host.SecurityStampAsync(id));

        using IServiceScope check = _host.Scope();
        UserManager<ReusableAuthUser> users = check.ServiceProvider.GetRequiredService<UserManager<ReusableAuthUser>>();
        Assert.False(await users.IsLockedOutAsync((await users.FindByIdAsync(id))!));
    }

    [Fact]
    public async Task ForceConfirmEmailAsync_RotatesTheStamp_AndConfirms()
    {
        string id = await _host.CreateUserAsync("unconfirmed@example.com", emailConfirmed: false);
        string? before = await _host.SecurityStampAsync(id);

        using (IServiceScope scope = _host.Scope())
        {
            Assert.True((await AdminTestHost.AdminUsers(scope).ForceConfirmEmailAsync(id)).Succeeded);
        }

        Assert.NotEqual(before, await _host.SecurityStampAsync(id));

        using IServiceScope check = _host.Scope();
        UserManager<ReusableAuthUser> users = check.ServiceProvider.GetRequiredService<UserManager<ReusableAuthUser>>();
        Assert.True(await users.IsEmailConfirmedAsync((await users.FindByIdAsync(id))!));
    }

    [Fact]
    public async Task ResetPasswordAsync_RotatesTheStamp_AndSetsTheGivenPassword()
    {
        string id = await _host.CreateUserAsync("reset@example.com");
        string? before = await _host.SecurityStampAsync(id);

        AdminPasswordResetResult result;
        using (IServiceScope scope = _host.Scope())
        {
            result = await AdminTestHost.AdminUsers(scope).ResetPasswordAsync(id, "Brand-new-pass1!");
        }

        Assert.True(result.Succeeded);
        Assert.Null(result.GeneratedPassword);   // admin supplied one, so nothing to show
        Assert.NotEqual(before, await _host.SecurityStampAsync(id));

        using IServiceScope check = _host.Scope();
        UserManager<ReusableAuthUser> users = check.ServiceProvider.GetRequiredService<UserManager<ReusableAuthUser>>();
        Assert.True(await users.CheckPasswordAsync((await users.FindByIdAsync(id))!, "Brand-new-pass1!"));
    }

    [Fact]
    public async Task ResetPasswordAsync_GeneratesAWorkingPassword_WhenNoneGiven()
    {
        string id = await _host.CreateUserAsync("gen-reset@example.com");

        AdminPasswordResetResult result;
        using (IServiceScope scope = _host.Scope())
        {
            result = await AdminTestHost.AdminUsers(scope).ResetPasswordAsync(id, null);
        }

        Assert.True(result.Succeeded);
        Assert.NotNull(result.GeneratedPassword);

        using IServiceScope check = _host.Scope();
        UserManager<ReusableAuthUser> users = check.ServiceProvider.GetRequiredService<UserManager<ReusableAuthUser>>();
        Assert.True(await users.CheckPasswordAsync((await users.FindByIdAsync(id))!, result.GeneratedPassword!));
    }

    [Fact]
    public async Task ResetPasswordAsync_WithAnInvalidPassword_LeavesTheExistingOneIntact()
    {
        // The bug the token-based reset fixed: the old RemovePassword+AddPassword pair committed
        // the removal first, so a rejected admin-supplied password left the account with NO
        // password - locked out. The token-based ResetPasswordAsync validates first, so a
        // rejected password must leave the original working.
        string id = await _host.CreateUserAsync("keep-pass@example.com", "Original-pass1!");

        AdminPasswordResetResult result;
        using (IServiceScope scope = _host.Scope())
        {
            result = await AdminTestHost.AdminUsers(scope).ResetPasswordAsync(id, "short");   // fails policy
        }

        Assert.False(result.Succeeded);

        using IServiceScope check = _host.Scope();
        UserManager<ReusableAuthUser> users = check.ServiceProvider.GetRequiredService<UserManager<ReusableAuthUser>>();
        ReusableAuthUser user = (await users.FindByIdAsync(id))!;
        Assert.True(await users.HasPasswordAsync(user));                          // still has a password
        Assert.True(await users.CheckPasswordAsync(user, "Original-pass1!"));     // the original one
    }

    [Fact]
    public async Task ForceSignOutAsync_RotatesTheStamp()
    {
        string id = await _host.CreateUserAsync("signout@example.com");
        string? before = await _host.SecurityStampAsync(id);

        using (IServiceScope scope = _host.Scope())
        {
            Assert.True((await AdminTestHost.AdminUsers(scope).ForceSignOutAsync(id)).Succeeded);
        }

        Assert.NotEqual(before, await _host.SecurityStampAsync(id));
    }

    [Fact]
    public async Task DeleteAsync_RemovesTheUser()
    {
        string id = await _host.CreateUserAsync("delete@example.com");

        using (IServiceScope scope = _host.Scope())
        {
            Assert.True((await AdminTestHost.AdminUsers(scope).DeleteAsync(id)).Succeeded);
        }

        using IServiceScope check = _host.Scope();
        UserManager<ReusableAuthUser> users = check.ServiceProvider.GetRequiredService<UserManager<ReusableAuthUser>>();
        Assert.Null(await users.FindByIdAsync(id));
    }

    // ---- Missing user is a clean rejection, never a 500 ---------------------------------

    [Fact]
    public async Task Mutations_OnAMissingUser_RejectCleanly()
    {
        using IServiceScope scope = _host.Scope();
        AdminUserService<ReusableAuthUser> admin = AdminTestHost.AdminUsers(scope);

        Assert.False((await admin.LockAsync("nope", DateTimeOffset.UtcNow.AddDays(1))).Succeeded);
        Assert.False((await admin.UnlockAsync("nope")).Succeeded);
        Assert.False((await admin.DeleteAsync("nope")).Succeeded);
        Assert.False((await admin.ForceConfirmEmailAsync("nope")).Succeeded);
        Assert.False((await admin.ForceSignOutAsync("nope")).Succeeded);
        Assert.False((await admin.ResetPasswordAsync("nope", "Whatever-pass1!")).Succeeded);
    }
}
