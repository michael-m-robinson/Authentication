using Authentication.EntityFrameworkCore;
using Authentication.Social;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace Authentication.Social.Tests;

/// <summary>
/// Covers <see cref="AlertService{TContext}"/>: that a user reads and changes only their own
/// alerts, and that paging a feed which is still moving does not lose any.
/// </summary>
public sealed class AlertServiceTests : IDisposable
{
    private const string Recipient = "user-1";
    private const string Actor = "user-2";
    private const string Stranger = "user-3";

    private readonly SqliteConnection _connection;

    public AlertServiceTests()
    {
        _connection = new SqliteConnection("DataSource=:memory:");
        _connection.Open();

        using SocialDbContext db = NewContext();
        db.Database.EnsureCreated();
    }

    private SocialDbContext NewContext()
        => new(new DbContextOptionsBuilder<SocialDbContext>().UseSqlite(_connection).Options);

    private static AlertService<SocialDbContext> ServiceOver(SocialDbContext db)
        => new(db, new AlertWriter<SocialDbContext>(db, TimeProvider.System), TimeProvider.System);

    private static CreateAlertRequest LikedRequest(string recipient = Recipient, string? actor = Actor, long contentId = 42)
        => new(recipient, AlertTypes.ContentLiked, actor, "Article", contentId);

    // ---- Creating ---------------------------------------------------------------------

    [Fact]
    public async Task CreateAsync_StoresAnAlert()
    {
        using SocialDbContext db = NewContext();

        await ServiceOver(db).CreateAsync(LikedRequest(), default);

        UserAlert stored = await db.Set<UserAlert>().SingleAsync();
        Assert.Equal(Recipient, stored.RecipientUserId);
        Assert.Equal(Actor, stored.ActorUserId);
        Assert.Equal(AlertTypes.ContentLiked, stored.AlertType);
        Assert.Equal("Article", stored.RelatedContentType);
        Assert.Equal(42, stored.RelatedContentId);
        Assert.False(stored.IsRead);
        Assert.Null(stored.ReadAt);
    }

    [Fact]
    public async Task CreateAsync_RaisesNothing_WhenTheActorIsTheRecipient()
    {
        using SocialDbContext db = NewContext();

        await ServiceOver(db).CreateAsync(LikedRequest(recipient: Recipient, actor: Recipient), default);

        // Nobody needs telling what they just did.
        Assert.Equal(0, await db.Set<UserAlert>().CountAsync());
    }

    [Fact]
    public async Task CreateAsync_AllowsASystemAlertWithNoActor()
    {
        using SocialDbContext db = NewContext();

        await ServiceOver(db).CreateAsync(
            new CreateAlertRequest(Recipient, AlertTypes.SystemAnnouncement), default);

        UserAlert stored = await db.Set<UserAlert>().SingleAsync();
        Assert.Null(stored.ActorUserId);
    }

    [Fact]
    public async Task CreateAsync_StoresAMessage_WhenGiven()
    {
        using SocialDbContext db = NewContext();

        await ServiceOver(db).CreateAsync(
            new CreateAlertRequest(Recipient, AlertTypes.SystemAnnouncement, Message: "Down for maintenance at 5pm."),
            default);

        UserAlert stored = await db.Set<UserAlert>().SingleAsync();
        Assert.Equal("Down for maintenance at 5pm.", stored.Message);
    }

    [Fact]
    public async Task CreateAsync_LeavesMessageNull_ForAnOrdinaryTypedAlert()
    {
        using SocialDbContext db = NewContext();

        await ServiceOver(db).CreateAsync(LikedRequest(), default);

        UserAlert stored = await db.Set<UserAlert>().SingleAsync();
        Assert.Null(stored.Message);
    }

    [Theory]
    [InlineData("", AlertTypes.ContentLiked)]
    [InlineData("   ", AlertTypes.ContentLiked)]
    [InlineData(Recipient, "")]
    [InlineData(Recipient, "   ")]
    public async Task CreateAsync_RaisesNothing_ForEmptyInput(string recipient, string alertType)
    {
        using SocialDbContext db = NewContext();

        await ServiceOver(db).CreateAsync(new CreateAlertRequest(recipient, alertType, Actor), default);

        Assert.Equal(0, await db.Set<UserAlert>().CountAsync());
    }

    // ---- Ownership --------------------------------------------------------------------

    [Fact]
    public async Task AUserSeesOnlyTheirOwnAlerts()
    {
        using SocialDbContext db = NewContext();
        AlertService<SocialDbContext> alerts = ServiceOver(db);
        await alerts.CreateAsync(LikedRequest(recipient: Recipient), default);
        await alerts.CreateAsync(LikedRequest(recipient: Stranger), default);

        AlertPage page = await alerts.GetAsync(Recipient, null, 20, default);

        Assert.Single(page.Alerts);
        Assert.Equal(Recipient, page.Alerts[0].RecipientUserId);
    }

    [Fact]
    public async Task OneUserCannotMarkAnothersAlertAsRead()
    {
        using SocialDbContext db = NewContext();
        AlertService<SocialDbContext> alerts = ServiceOver(db);
        await alerts.CreateAsync(LikedRequest(recipient: Recipient), default);
        long alertId = (await db.Set<UserAlert>().SingleAsync()).Id;

        // The stranger knows the id and asks anyway.
        await alerts.MarkAsReadAsync(Stranger, alertId, default);

        // Not found for them, so nothing happened - and no error either, because "no such
        // alert of yours" is not worth an exception.
        db.ChangeTracker.Clear();
        Assert.False((await db.Set<UserAlert>().SingleAsync()).IsRead);
    }

    [Fact]
    public async Task MarkAllAsRead_TouchesOnlyTheCallersAlerts()
    {
        using SocialDbContext db = NewContext();
        AlertService<SocialDbContext> alerts = ServiceOver(db);
        await alerts.CreateAsync(LikedRequest(recipient: Recipient), default);
        await alerts.CreateAsync(LikedRequest(recipient: Stranger), default);

        await alerts.MarkAllAsReadAsync(Recipient, default);

        db.ChangeTracker.Clear();
        Assert.True((await db.Set<UserAlert>().SingleAsync(a => a.RecipientUserId == Recipient)).IsRead);
        Assert.False((await db.Set<UserAlert>().SingleAsync(a => a.RecipientUserId == Stranger)).IsRead);
    }

    [Fact]
    public async Task UnreadCount_IsPerUser()
    {
        using SocialDbContext db = NewContext();
        AlertService<SocialDbContext> alerts = ServiceOver(db);
        await alerts.CreateAsync(LikedRequest(recipient: Recipient, contentId: 1), default);
        await alerts.CreateAsync(LikedRequest(recipient: Recipient, contentId: 2), default);
        await alerts.CreateAsync(LikedRequest(recipient: Stranger, contentId: 3), default);

        Assert.Equal(2, await alerts.CountUnreadAsync(Recipient, default));
        Assert.Equal(1, await alerts.CountUnreadAsync(Stranger, default));
    }

    // ---- Reading ----------------------------------------------------------------------

    [Fact]
    public async Task MarkAsRead_SetsReadAt_AndDropsTheUnreadCount()
    {
        using SocialDbContext db = NewContext();
        AlertService<SocialDbContext> alerts = ServiceOver(db);
        await alerts.CreateAsync(LikedRequest(), default);
        long alertId = (await db.Set<UserAlert>().SingleAsync()).Id;

        await alerts.MarkAsReadAsync(Recipient, alertId, default);

        db.ChangeTracker.Clear();
        UserAlert stored = await db.Set<UserAlert>().SingleAsync();
        Assert.True(stored.IsRead);
        Assert.NotNull(stored.ReadAt);
        Assert.Equal(0, await alerts.CountUnreadAsync(Recipient, default));
    }

    [Fact]
    public async Task MarkAsRead_IsIdempotent_AndKeepsTheFirstReadAt()
    {
        using SocialDbContext db = NewContext();
        AlertService<SocialDbContext> alerts = ServiceOver(db);
        await alerts.CreateAsync(LikedRequest(), default);
        long alertId = (await db.Set<UserAlert>().SingleAsync()).Id;

        await alerts.MarkAsReadAsync(Recipient, alertId, default);
        DateTimeOffset? first = (await db.Set<UserAlert>().SingleAsync()).ReadAt;

        await alerts.MarkAsReadAsync(Recipient, alertId, default);

        // Reading twice does not move when it was read.
        db.ChangeTracker.Clear();
        Assert.Equal(first, (await db.Set<UserAlert>().SingleAsync()).ReadAt);
    }

    [Fact]
    public async Task MarkAsRead_OnAnAlertThatDoesNotExist_IsNotAnError()
    {
        using SocialDbContext db = NewContext();

        await ServiceOver(db).MarkAsReadAsync(Recipient, 9999, default);
    }

    [Fact]
    public async Task MarkAllAsRead_SetsReadAtOnEveryUnreadAlert()
    {
        using SocialDbContext db = NewContext();
        AlertService<SocialDbContext> alerts = ServiceOver(db);
        for (int i = 0; i < 5; i++)
        {
            await alerts.CreateAsync(LikedRequest(contentId: i), default);
        }

        await alerts.MarkAllAsReadAsync(Recipient, default);

        db.ChangeTracker.Clear();
        Assert.Equal(0, await alerts.CountUnreadAsync(Recipient, default));
        Assert.All(await db.Set<UserAlert>().ToListAsync(), a => Assert.NotNull(a.ReadAt));
    }

    // ---- Pagination -------------------------------------------------------------------

    [Fact]
    public async Task AlertsComeBackNewestFirst()
    {
        using SocialDbContext db = NewContext();
        AlertService<SocialDbContext> alerts = ServiceOver(db);
        for (int i = 1; i <= 3; i++)
        {
            await alerts.CreateAsync(LikedRequest(contentId: i), default);
        }

        AlertPage page = await alerts.GetAsync(Recipient, null, 20, default);

        Assert.Equal([3, 2, 1], page.Alerts.Select(a => a.RelatedContentId));
    }

    [Fact]
    public async Task TheCursorWalksTheWholeFeed_WithoutRepeatingOrSkipping()
    {
        using SocialDbContext db = NewContext();
        AlertService<SocialDbContext> alerts = ServiceOver(db);
        for (int i = 1; i <= 10; i++)
        {
            await alerts.CreateAsync(LikedRequest(contentId: i), default);
        }

        List<long?> seen = [];
        long? cursor = null;
        do
        {
            AlertPage page = await alerts.GetAsync(Recipient, cursor, 3, default);
            seen.AddRange(page.Alerts.Select(a => a.RelatedContentId));
            cursor = page.NextCursor;
        }
        while (cursor is not null);

        Assert.Equal(10, seen.Count);
        Assert.Equal(10, seen.Distinct().Count());
    }

    [Fact]
    public async Task NewAlertsArrivingMidRead_DoNotPushOldOnesOutOfSight()
    {
        // The reason for a cursor rather than a page number. With an offset, an alert arriving
        // between page 1 and page 2 shifts everything down one, and the alert that was last on
        // page 1 becomes first on page 2 - or worse, one is skipped entirely and never seen.
        using SocialDbContext db = NewContext();
        AlertService<SocialDbContext> alerts = ServiceOver(db);
        for (int i = 1; i <= 6; i++)
        {
            await alerts.CreateAsync(LikedRequest(contentId: i), default);
        }

        AlertPage first = await alerts.GetAsync(Recipient, null, 3, default);

        // Three more arrive while the user is still reading page one.
        for (int i = 7; i <= 9; i++)
        {
            await alerts.CreateAsync(LikedRequest(contentId: i), default);
        }

        AlertPage second = await alerts.GetAsync(Recipient, first.NextCursor, 3, default);

        // Page two carries on from where page one stopped. The newcomers are above the cursor
        // and simply are not in it; nothing from page one repeats, and nothing is lost.
        Assert.Equal([6, 5, 4], first.Alerts.Select(a => a.RelatedContentId));
        Assert.Equal([3, 2, 1], second.Alerts.Select(a => a.RelatedContentId));
    }

    [Fact]
    public async Task TheLastPage_HasNoCursor()
    {
        using SocialDbContext db = NewContext();
        AlertService<SocialDbContext> alerts = ServiceOver(db);
        await alerts.CreateAsync(LikedRequest(contentId: 1), default);
        await alerts.CreateAsync(LikedRequest(contentId: 2), default);

        AlertPage page = await alerts.GetAsync(Recipient, null, 20, default);

        // A cursor here would invite a round trip that returns nothing.
        Assert.Null(page.NextCursor);
        Assert.Equal(2, page.Alerts.Count);
    }

    [Fact]
    public async Task ThePageSizeIsCapped_SoNoOneCanAskForEverything()
    {
        using SocialDbContext db = NewContext();
        AlertService<SocialDbContext> alerts = ServiceOver(db);
        for (int i = 0; i < IAlertService.MaxPageSize + 10; i++)
        {
            await alerts.CreateAsync(LikedRequest(contentId: i), default);
        }

        AlertPage page = await alerts.GetAsync(Recipient, null, int.MaxValue, default);

        Assert.Equal(IAlertService.MaxPageSize, page.Alerts.Count);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-5)]
    public async Task ANonPositiveLimit_FallsBackToTheDefault(int limit)
    {
        using SocialDbContext db = NewContext();
        AlertService<SocialDbContext> alerts = ServiceOver(db);
        for (int i = 0; i < IAlertService.DefaultPageSize + 5; i++)
        {
            await alerts.CreateAsync(LikedRequest(contentId: i), default);
        }

        AlertPage page = await alerts.GetAsync(Recipient, null, limit, default);

        Assert.Equal(IAlertService.DefaultPageSize, page.Alerts.Count);
    }

    [Fact]
    public async Task AnUnknownUserHasNoAlerts()
    {
        using SocialDbContext db = NewContext();
        await ServiceOver(db).CreateAsync(LikedRequest(), default);

        AlertPage page = await ServiceOver(db).GetAsync("nobody", null, 20, default);

        Assert.Empty(page.Alerts);
        Assert.Null(page.NextCursor);
        Assert.Equal(0, await ServiceOver(db).CountUnreadAsync("nobody", default));
    }

    public void Dispose() => _connection.Dispose();
}
