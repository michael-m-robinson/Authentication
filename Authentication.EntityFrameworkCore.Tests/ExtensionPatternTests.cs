using System.Security.Claims;
using Authentication;
using Authentication.EntityFrameworkCore;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;

namespace Authentication.EntityFrameworkCore.Tests;

/// <summary>
/// Runs the README's "Adding your own data" pattern for real — the one hosts are pointed
/// at for alerts, likes, or anything else the library deliberately does not model.
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
            AlertsEnabled = true,
        };
        await users.CreateAsync(user, "Correct-horse-9!");

        AppUser? found = await users.FindByEmailAsync("person@example.com");

        Assert.NotNull(found);
        Assert.Equal("A Person", found.DisplayName);
        Assert.True(found.AlertsEnabled);
    }

    [Fact]
    public async Task AlertsPattern_SplitsTheEventFromTheDelivery()
    {
        using ServiceProvider provider = Build();
        using IServiceScope scope = provider.CreateScope();
        AppDbContext db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        UserManager<AppUser> users = scope.ServiceProvider.GetRequiredService<UserManager<AppUser>>();

        AppUser first = new() { UserName = "a@example.com", Email = "a@example.com" };
        AppUser second = new() { UserName = "b@example.com", Email = "b@example.com" };
        await users.CreateAsync(first, "Correct-horse-9!");
        await users.CreateAsync(second, "Correct-horse-9!");

        // One event, fanned out to two recipients.
        Notification alert = new() { Message = "Scheduled downtime", RaisedAt = DateTimeOffset.UtcNow };
        db.Notifications.Add(alert);
        db.UserNotifications.Add(new UserNotification { Notification = alert, UserId = first.Id });
        db.UserNotifications.Add(new UserNotification { Notification = alert, UserId = second.Id });
        await db.SaveChangesAsync();

        // The point of the split: read state is per person, not per event.
        UserNotification firstsCopy = await db.UserNotifications.SingleAsync(n => n.UserId == first.Id);
        firstsCopy.Read = true;
        firstsCopy.ReadAt = DateTimeOffset.UtcNow;
        await db.SaveChangesAsync();

        Assert.Single(await db.Notifications.ToListAsync());
        Assert.True(await db.UserNotifications.SingleAsync(n => n.UserId == first.Id) is { Read: true });
        Assert.False((await db.UserNotifications.SingleAsync(n => n.UserId == second.Id)).Read);
    }

    [Fact]
    public async Task LikesPattern_UniqueIndexMakesADoubleLikeIdempotent()
    {
        using ServiceProvider provider = Build();
        using IServiceScope scope = provider.CreateScope();
        AppDbContext db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        UserManager<AppUser> users = scope.ServiceProvider.GetRequiredService<UserManager<AppUser>>();

        AppUser user = new() { UserName = "a@example.com", Email = "a@example.com" };
        await users.CreateAsync(user, "Correct-horse-9!");

        db.Likes.Add(new Like { UserId = user.Id, EntityType = "Article", EntityId = "42" });
        await db.SaveChangesAsync();

        // The README claims the unique index gives idempotency for free. Prove it: a
        // second like is a constraint violation to catch, not a silent double-count.
        db.Likes.Add(new Like { UserId = user.Id, EntityType = "Article", EntityId = "42" });

        await Assert.ThrowsAsync<DbUpdateException>(() => db.SaveChangesAsync());
    }

    [Fact]
    public async Task LikesPattern_AllowsTheSameUserToLikeDifferentThings()
    {
        using ServiceProvider provider = Build();
        using IServiceScope scope = provider.CreateScope();
        AppDbContext db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        UserManager<AppUser> users = scope.ServiceProvider.GetRequiredService<UserManager<AppUser>>();

        AppUser user = new() { UserName = "a@example.com", Email = "a@example.com" };
        await users.CreateAsync(user, "Correct-horse-9!");

        db.Likes.Add(new Like { UserId = user.Id, EntityType = "Article", EntityId = "42" });
        db.Likes.Add(new Like { UserId = user.Id, EntityType = "Article", EntityId = "43" });
        db.Likes.Add(new Like { UserId = user.Id, EntityType = "Comment", EntityId = "42" });

        // The index is on all three columns; scoping it to UserId alone would let someone
        // like exactly one thing, ever.
        await db.SaveChangesAsync();

        Assert.Equal(3, await db.Likes.CountAsync());
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
        Assert.NotNull(await db.Likes.ToListAsync());
    }

    public void Dispose() => _connection.Dispose();

    // ---- Exactly what the README tells hosts to write --------------------------------

    private sealed class AppUser : IdentityUser
    {
        public bool AlertsEnabled { get; set; } = true;
        public string? DisplayName { get; set; }
    }

    private sealed class Notification
    {
        public int Id { get; set; }
        public string Message { get; set; } = "";
        public DateTimeOffset RaisedAt { get; set; }
    }

    private sealed class UserNotification
    {
        public int Id { get; set; }
        public int NotificationId { get; set; }
        public Notification? Notification { get; set; }
        public string UserId { get; set; } = "";
        public bool Read { get; set; }
        public DateTimeOffset? ReadAt { get; set; }
    }

    private sealed class Like
    {
        public int Id { get; set; }
        public string UserId { get; set; } = "";
        public string EntityType { get; set; } = "";
        public string EntityId { get; set; } = "";
    }

    private sealed class AppDbContext : ReusableAuthDbContext<AppUser>
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
        {
        }

        public DbSet<Notification> Notifications => Set<Notification>();

        public DbSet<UserNotification> UserNotifications => Set<UserNotification>();

        public DbSet<Like> Likes => Set<Like>();

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            // The auth tables' own configuration. Skipping this silently loses the Identity
            // schema, so a host adding its own entities must chain up.
            base.OnModelCreating(modelBuilder);

            modelBuilder.Entity<Like>()
                .HasIndex(l => new { l.UserId, l.EntityType, l.EntityId })
                .IsUnique();
        }
    }

    private sealed class NoopEmailSender : IAuthEmailSender
    {
        public Task SendEmailConfirmationAsync(string email, string userId, string token) => Task.CompletedTask;

        public Task SendPasswordResetAsync(string email, string userId, string token) => Task.CompletedTask;

        public Task SendRegistrationAttemptedAsync(string email) => Task.CompletedTask;
    }
}
