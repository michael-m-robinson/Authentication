using Authentication;
using Authentication.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Authentication.EntityFrameworkCore.Tests;

/// <summary>
/// Covers the EF Core storage package: that it wires Microsoft's store correctly, that the
/// store satisfies the core package's startup guard, and that a misconfigured context is
/// reported at startup rather than deep in EF later.
/// </summary>
public sealed class EntityFrameworkStoreTests : IDisposable
{
    private readonly SqliteConnection _connection;

    public EntityFrameworkStoreTests()
    {
        // A real relational provider, kept in memory. The InMemory provider enforces no
        // constraints, so it would pass on a schema a real database rejects.
        _connection = new SqliteConnection("DataSource=:memory:");
        _connection.Open();
    }

    private ServiceProvider Build()
    {
        ServiceCollection services = new();
        services.AddLogging();
        services.AddDataProtection();
        services.AddDbContext<ReusableAuthDbContext>(o => o.UseSqlite(_connection));
        services.AddReusableAuth();
        services.AddReusableAuthEntityFrameworkStores<ReusableAuthDbContext>();
        services.AddSingleton<IAuthEmailSender, NoopEmailSender>();

        ServiceProvider provider = services.BuildServiceProvider();

        using (IServiceScope scope = provider.CreateScope())
        {
            scope.ServiceProvider.GetRequiredService<ReusableAuthDbContext>().Database.EnsureCreated();
        }

        return provider;
    }

    [Fact]
    public void Store_SatisfiesTheSecurityStampGuard()
    {
        // The premise of this whole package. The core library refuses to boot on a store
        // without IUserSecurityStampStore, because Identity silently treats every stamp
        // check as valid without it. Microsoft's store implements it; that is precisely
        // why we wire theirs instead of writing one.
        using ServiceProvider provider = Build();
        using IServiceScope scope = provider.CreateScope();

        UserManager<ReusableAuthUser> users =
            scope.ServiceProvider.GetRequiredService<UserManager<ReusableAuthUser>>();

        Assert.True(users.SupportsUserSecurityStamp);
        SecurityStampStoreGuard<ReusableAuthUser>.Verify(users);
    }

    [Fact]
    public void RegistersMicrosoftsRoleAwareStores()
    {
        using ServiceProvider provider = Build();
        using IServiceScope scope = provider.CreateScope();

        IUserStore<ReusableAuthUser> userStore =
            scope.ServiceProvider.GetRequiredService<IUserStore<ReusableAuthUser>>();
        IRoleStore<IdentityRole> roleStore =
            scope.ServiceProvider.GetRequiredService<IRoleStore<IdentityRole>>();

        // UserStore, not UserOnlyStore: passing the role type is what makes Microsoft's
        // wiring pick the role-aware store AND register a role store. Get that wrong and
        // RoleManager cannot resolve, so the host fails to build its container.
        Assert.StartsWith("UserStore", userStore.GetType().Name, StringComparison.Ordinal);
        Assert.Equal("Microsoft.AspNetCore.Identity.EntityFrameworkCore", userStore.GetType().Namespace);
        Assert.Equal("Microsoft.AspNetCore.Identity.EntityFrameworkCore", roleStore.GetType().Namespace);
    }

    [Fact]
    public void UserStore_SupportsRoles()
    {
        using ServiceProvider provider = Build();
        using IServiceScope scope = provider.CreateScope();

        UserManager<ReusableAuthUser> users =
            scope.ServiceProvider.GetRequiredService<UserManager<ReusableAuthUser>>();

        // SupportsUserRole gates whether Identity's claims factory writes role claims into
        // the cookie at all. False here would mean [Authorize(Roles = "...")] silently
        // never matches, with nothing to show why.
        Assert.True(users.SupportsUserRole);
    }

    [Fact]
    public async Task Store_RoundTripsAUser()
    {
        using ServiceProvider provider = Build();
        using IServiceScope scope = provider.CreateScope();
        UserManager<ReusableAuthUser> users =
            scope.ServiceProvider.GetRequiredService<UserManager<ReusableAuthUser>>();

        ReusableAuthUser user = new() { UserName = "person@example.com", Email = "person@example.com" };
        IdentityResult created = await users.CreateAsync(user, "Correct-horse-9!");

        Assert.True(created.Succeeded, string.Join(", ", created.Errors.Select(e => e.Description)));

        ReusableAuthUser? found = await users.FindByEmailAsync("person@example.com");
        Assert.NotNull(found);
        Assert.True(await users.CheckPasswordAsync(found, "Correct-horse-9!"));
    }

    [Fact]
    public async Task Store_PersistsSecurityStampChanges()
    {
        using ServiceProvider provider = Build();
        using IServiceScope scope = provider.CreateScope();
        UserManager<ReusableAuthUser> users =
            scope.ServiceProvider.GetRequiredService<UserManager<ReusableAuthUser>>();

        ReusableAuthUser user = new() { UserName = "person@example.com", Email = "person@example.com" };
        await users.CreateAsync(user, "Correct-horse-9!");
        string before = await users.GetSecurityStampAsync(user);

        await users.UpdateSecurityStampAsync(user);

        // Session invalidation depends on the new stamp actually reaching the database; if
        // it only changed in memory, revocation would not survive the request.
        ReusableAuthUser reloaded = await users.FindByIdAsync(user.Id) ?? throw new InvalidOperationException();
        Assert.NotEqual(before, await users.GetSecurityStampAsync(reloaded));
    }

    [Fact]
    public void Schema_HasTheRoleTables()
    {
        using ServiceProvider provider = Build();
        using IServiceScope scope = provider.CreateScope();

        List<string> tables = [];
        using (SqliteCommand command = _connection.CreateCommand())
        {
            command.CommandText = "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name";
            using SqliteDataReader reader = command.ExecuteReader();
            while (reader.Read())
            {
                tables.Add(reader.GetString(0));
            }
        }

        Assert.Contains("AspNetUsers", tables);

        // Role support needs these. An earlier version of this package based the context on
        // IdentityUserContext, which has no role tables - and Microsoft's wiring does not
        // complain about that, it just registers a store that reaches for entities the model
        // has never heard of and throws from inside EF on the first role call.
        Assert.Contains("AspNetRoles", tables);
        Assert.Contains("AspNetUserRoles", tables);
    }

    [Fact]
    public async Task RoleNames_ComeBackWithTheirOriginalCasing()
    {
        // Asserted against the real store because it is the store's doing: Identity hands it
        // a normalised name to write, and it joins back to the roles table on read to
        // recover the original. That matters — the claim written into the cookie is this
        // value, and [Authorize(Roles = "Admins")] compares it CASE-SENSITIVELY. If this
        // ever returned "ADMINS", every role check written the obvious way would silently
        // stop matching.
        using ServiceProvider provider = Build();
        using IServiceScope scope = provider.CreateScope();
        IRoleService roles = scope.ServiceProvider.GetRequiredService<IRoleService>();
        UserManager<ReusableAuthUser> users =
            scope.ServiceProvider.GetRequiredService<UserManager<ReusableAuthUser>>();

        ReusableAuthUser user = new() { UserName = "person@example.com", Email = "person@example.com" };
        await users.CreateAsync(user, "Correct-horse-9!");

        await roles.CreateRoleAsync("Admins");
        await roles.AddToRoleAsync(user.Id, "ADMINS");   // matched case-insensitively

        Assert.Contains("Admins", await roles.GetUserRolesAsync(user.Id));
    }

    [Fact]
    public async Task RemovingARole_RefreshesTheStamp_AgainstTheRealStore()
    {
        // The core suite proves this against a fake. This proves the same thing survives
        // Microsoft's actual store and a real database, which is where a revoked
        // administrator would otherwise keep their access.
        using ServiceProvider provider = Build();
        using IServiceScope scope = provider.CreateScope();
        IRoleService roles = scope.ServiceProvider.GetRequiredService<IRoleService>();
        UserManager<ReusableAuthUser> users =
            scope.ServiceProvider.GetRequiredService<UserManager<ReusableAuthUser>>();

        ReusableAuthUser user = new() { UserName = "person@example.com", Email = "person@example.com" };
        await users.CreateAsync(user, "Correct-horse-9!");
        await roles.CreateRoleAsync("Admins");
        await roles.AddToRoleAsync(user.Id, "Admins");

        string before = await users.GetSecurityStampAsync(
            await users.FindByIdAsync(user.Id) ?? throw new InvalidOperationException());

        await roles.RemoveFromRoleAsync(user.Id, "Admins");

        string after = await users.GetSecurityStampAsync(
            await users.FindByIdAsync(user.Id) ?? throw new InvalidOperationException());

        Assert.NotEqual(before, after);
        Assert.False(await roles.IsInRoleAsync(user.Id, "Admins"));
    }

    [Fact]
    public void ContextThatIsNotAnIdentityContext_FailsAtStartup()
    {
        ServiceCollection services = new();

        // Microsoft's AddEntityFrameworkStores accepts any DbContext and quietly falls back
        // to a store bound to the default POCOs, which then fails later inside EF with an
        // error about entity types rather than about the real mistake. Ours says so now.
        InvalidOperationException error = Assert.Throws<InvalidOperationException>(
            () => services.AddReusableAuthEntityFrameworkStores<PlainDbContext>());

        Assert.Contains(nameof(PlainDbContext), error.Message, StringComparison.Ordinal);
        Assert.Contains("IdentityDbContext", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ContextForADifferentUserType_FailsAtStartup()
    {
        ServiceCollection services = new();

        // A context built for another user type is accepted by Microsoft's wiring and
        // breaks at first use.
        InvalidOperationException error = Assert.Throws<InvalidOperationException>(
            () => services.AddReusableAuthEntityFrameworkStores<OtherUser, ReusableAuthDbContext>());

        Assert.Contains(nameof(OtherUser), error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void NullServices_Throws()
    {
        Assert.Throws<ArgumentNullException>(
            () => ReusableAuthEntityFrameworkServiceCollectionExtensions
                .AddReusableAuthEntityFrameworkStores<ReusableAuthDbContext>(null!));
    }

    public void Dispose() => _connection.Dispose();

    private sealed class PlainDbContext : DbContext
    {
        public PlainDbContext(DbContextOptions<PlainDbContext> options) : base(options)
        {
        }
    }

    private sealed class OtherUser : IdentityUser
    {
    }

    private sealed class NoopEmailSender : IAuthEmailSender
    {
        public Task SendEmailConfirmationAsync(string email, string userId, string token) => Task.CompletedTask;

        public Task SendPasswordResetAsync(string email, string userId, string token) => Task.CompletedTask;

        public Task SendRegistrationAttemptedAsync(string email) => Task.CompletedTask;
    }
}
