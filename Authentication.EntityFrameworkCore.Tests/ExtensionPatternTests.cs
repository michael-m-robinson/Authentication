using Authentication;
using Authentication.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Authentication.EntityFrameworkCore.Tests;

/// <summary>
/// Runs the README's "Adding your own data" pattern for real: the one hosts are pointed at
/// for anything the library does not model.
/// </summary>
/// <remarks>
/// Documentation that has never been executed is a guess. The README previously carried an
/// example that compiled and threw at runtime, so the examples are tested rather than
/// eyeballed.
/// </remarks>
public sealed class ExtensionPatternTests : IDisposable
{
    private readonly SqliteConnection _connection;

    public ExtensionPatternTests()
    {
        _connection = new SqliteConnection("DataSource=:memory:");
        _connection.Open();
    }

    private ServiceProvider Build()
    {
        ServiceCollection services = new();
        services.AddLogging();
        services.AddDataProtection();
        services.AddDbContext<AppDbContext>(o => o.UseSqlite(_connection));
        services.AddReusableAuth<AppUser>();
        services.AddReusableAuthEntityFrameworkStores<AppUser, AppDbContext>();
        services.AddSingleton<IAuthEmailSender, NoopEmailSender>();

        ServiceProvider provider = services.BuildServiceProvider();

        using (IServiceScope scope = provider.CreateScope())
        {
            scope.ServiceProvider.GetRequiredService<AppDbContext>().Database.EnsureCreated();
        }

        return provider;
    }

    [Fact]
    public async Task CustomUserFields_RoundTrip()
    {
        using ServiceProvider provider = Build();
        using IServiceScope scope = provider.CreateScope();
        UserManager<AppUser> users = scope.ServiceProvider.GetRequiredService<UserManager<AppUser>>();

        AppUser user = new()
        {
            UserName = "person@example.com",
            Email = "person@example.com",
            DisplayName = "A Person",
            TimeZoneId = "Europe/London",
        };
        await users.CreateAsync(user, "Correct-horse-9!");

        AppUser? found = await users.FindByEmailAsync("person@example.com");

        Assert.NotNull(found);
        Assert.Equal("A Person", found.DisplayName);
        Assert.Equal("Europe/London", found.TimeZoneId);
    }

    [Fact]
    public async Task AHostsOwnTable_KeyedToTheUserId_RoundTrips()
    {
        using ServiceProvider provider = Build();
        using IServiceScope scope = provider.CreateScope();
        AppDbContext db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        UserManager<AppUser> users = scope.ServiceProvider.GetRequiredService<UserManager<AppUser>>();

        AppUser user = new() { UserName = "a@example.com", Email = "a@example.com" };
        await users.CreateAsync(user, "Correct-horse-9!");

        db.AuditEntries.Add(new AuditEntry
        {
            UserId = user.Id,
            Action = "SignedIn",
            OccurredAt = DateTimeOffset.UnixEpoch,
        });
        await db.SaveChangesAsync();

        Assert.Equal("SignedIn", (await db.AuditEntries.SingleAsync(e => e.UserId == user.Id)).Action);
    }

    [Fact]
    public async Task AKeyOfUserId_SurvivesTheUserChangingTheirEmail()
    {
        // Why the README says to key rows to user.Id and not to a username or an email
        // address: both are things a user can change, and a row keyed to one is a row that
        // belongs to whoever holds that name next.
        using ServiceProvider provider = Build();
        using IServiceScope scope = provider.CreateScope();
        AppDbContext db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        UserManager<AppUser> users = scope.ServiceProvider.GetRequiredService<UserManager<AppUser>>();

        AppUser user = new() { UserName = "old@example.com", Email = "old@example.com" };
        await users.CreateAsync(user, "Correct-horse-9!");

        db.AuditEntries.Add(new AuditEntry
        {
            UserId = user.Id,
            Action = "SignedIn",
            OccurredAt = DateTimeOffset.UnixEpoch,
        });
        await db.SaveChangesAsync();

        await users.SetUserNameAsync(user, "new@example.com");
        await users.SetEmailAsync(user, "new@example.com");

        Assert.Single(await db.AuditEntries.Where(e => e.UserId == user.Id).ToListAsync());
    }

    [Fact]
    public async Task AppTablesAndAuthTables_LiveInTheSameContext()
    {
        using ServiceProvider provider = Build();
        using IServiceScope scope = provider.CreateScope();
        AppDbContext db = scope.ServiceProvider.GetRequiredService<AppDbContext>();

        // Both the library's tables and the host's are on one context, so a host's write
        // and its auth data share a transaction.
        Assert.NotNull(await db.Users.ToListAsync());
        Assert.NotNull(await db.AuditEntries.ToListAsync());
    }

    public void Dispose() => _connection.Dispose();

    // ---- Exactly what the README tells hosts to write --------------------------------

    private sealed class AppUser : IdentityUser
    {
        public string? DisplayName { get; set; }

        public string? TimeZoneId { get; set; }
    }

    private sealed class AuditEntry
    {
        public int Id { get; set; }

        public string UserId { get; set; } = "";

        public string Action { get; set; } = "";

        public DateTimeOffset OccurredAt { get; set; }
    }

    private sealed class AppDbContext : ReusableAuthDbContext<AppUser>
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
        {
        }

        public DbSet<AuditEntry> AuditEntries => Set<AuditEntry>();

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            // The auth tables' own configuration. Skipping this silently loses the Identity
            // schema, so a host adding its own entities must chain up.
            base.OnModelCreating(modelBuilder);

            modelBuilder.Entity<AuditEntry>()
                .HasIndex(e => new { e.UserId, e.OccurredAt });
        }
    }

    private sealed class NoopEmailSender : IAuthEmailSender
    {
        public Task SendEmailConfirmationAsync(string email, string userId, string token) => Task.CompletedTask;

        public Task SendPasswordResetAsync(string email, string userId, string token) => Task.CompletedTask;

        public Task SendRegistrationAttemptedAsync(string email) => Task.CompletedTask;
    }
}
