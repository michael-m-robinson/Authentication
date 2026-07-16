using Authentication;
using Authentication.EntityFrameworkCore;
using Authentication.Social;
using Microsoft.AspNetCore.Identity;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Authentication.Admin.Tests;

/// <summary>
/// A host context wired the way the README tells a consumer to wire one: the auth tables and
/// the social tables on the host's own context. The admin tests run against a real Identity
/// store, not a fake.
/// </summary>
internal sealed class AdminTestDbContext : ReusableAuthDbContext
{
    public AdminTestDbContext(DbContextOptions<AdminTestDbContext> options)
        : base(options)
    {
    }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);
        modelBuilder.AddReusableAuthSocial();
    }
}

/// <summary>
/// Builds a real DI container over a private SQLite database, exactly as a host would, so a
/// test can resolve <see cref="UserManager{TUser}"/>, <see cref="IAccountService"/> and the
/// rest and construct the internal admin services directly against them.
/// </summary>
/// <remarks>
/// SQLite over a kept-open in-memory connection, not the EF InMemory provider: security-stamp
/// and lockout behaviour are only faithful over a real database. Each host owns its connection
/// and disposes it, so tests do not share state.
/// </remarks>
internal sealed class AdminTestHost : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly ServiceProvider _provider;

    public AdminTestHost()
    {
        _connection = new SqliteConnection("DataSource=:memory:");
        _connection.Open();

        ServiceCollection services = new();
        services.AddLogging();
        services.AddDataProtection();
        services.AddDbContext<AdminTestDbContext>(options => options.UseSqlite(_connection));
        services.AddReusableAuth<ReusableAuthUser>();
        services.AddReusableAuthEntityFrameworkStores<ReusableAuthUser, AdminTestDbContext>();
        services.AddReusableAuthSocial<AdminTestDbContext>();
        services.AddSingleton<IAuthEmailSender, NoopEmailSender>();

        _provider = services.BuildServiceProvider();

        using IServiceScope scope = _provider.CreateScope();
        scope.ServiceProvider.GetRequiredService<AdminTestDbContext>().Database.EnsureCreated();
    }

    /// <summary>Opens a scope. Identity's managers are scoped, so every unit of work needs one.</summary>
    public IServiceScope Scope() => _provider.CreateScope();

    /// <summary>The admin user service, closed over the built-in user, over a fresh scope's manager.</summary>
    public static AdminUserService<ReusableAuthUser> AdminUsers(IServiceScope scope)
        => new(
            scope.ServiceProvider.GetRequiredService<UserManager<ReusableAuthUser>>(),
            scope.ServiceProvider.GetRequiredService<IAccountService>());

    /// <summary>Creates a user and returns its id. Confirmed by default.</summary>
    public async Task<string> CreateUserAsync(
        string email,
        string password = "Test-passw0rd!",
        bool emailConfirmed = true)
    {
        using IServiceScope scope = Scope();
        UserManager<ReusableAuthUser> users = scope.ServiceProvider.GetRequiredService<UserManager<ReusableAuthUser>>();

        ReusableAuthUser user = new() { UserName = email, Email = email, EmailConfirmed = emailConfirmed };
        IdentityResult created = await users.CreateAsync(user, password);
        Assert.True(created.Succeeded, string.Join("; ", created.Errors.Select(e => e.Description)));

        return user.Id;
    }

    /// <summary>Reads a user's current security stamp, for before/after rotation assertions.</summary>
    public async Task<string?> SecurityStampAsync(string userId)
    {
        using IServiceScope scope = Scope();
        UserManager<ReusableAuthUser> users = scope.ServiceProvider.GetRequiredService<UserManager<ReusableAuthUser>>();
        ReusableAuthUser user = (await users.FindByIdAsync(userId))!;
        return await users.GetSecurityStampAsync(user);
    }

    public void Dispose()
    {
        _provider.Dispose();
        _connection.Dispose();
    }

    private sealed class NoopEmailSender : IAuthEmailSender
    {
        public Task SendEmailConfirmationAsync(string email, string userId, string token) => Task.CompletedTask;

        public Task SendPasswordResetAsync(string email, string userId, string token) => Task.CompletedTask;

        public Task SendRegistrationAttemptedAsync(string email) => Task.CompletedTask;
    }
}
