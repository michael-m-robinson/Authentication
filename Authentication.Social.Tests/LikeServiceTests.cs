using Authentication.EntityFrameworkCore;
using Authentication.Social;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;

namespace Authentication.Social.Tests;

/// <summary>
/// Covers <c>LikeAsync</c>, and the entity and constraint it stands on.
/// </summary>
/// <remarks>
/// Against real Sqlite rather than the InMemory provider. InMemory enforces no unique
/// constraints, and the constraint is the whole mechanism here: on InMemory the duplicate
/// tests would pass while proving the exact opposite of what they claim.
/// </remarks>
public sealed class LikeServiceTests : IDisposable
{
    private const string Liker = "user-1";
    private const string Owner = "user-2";

    private readonly SqliteConnection _connection;

    public LikeServiceTests()
    {
        _connection = new SqliteConnection("DataSource=:memory:");
        _connection.Open();

        using SocialDbContext db = NewContext();
        db.Database.EnsureCreated();
    }

    private SocialDbContext NewContext()
        => new(new DbContextOptionsBuilder<SocialDbContext>().UseSqlite(_connection).Options);

    private static LikeService<SocialDbContext> ServiceOver(SocialDbContext db, IContentSource content)
        => new(
            db,
            content,
            new AlertWriter<SocialDbContext>(db, TimeProvider.System),
            TimeProvider.System,
            NullLogger<LikeService<SocialDbContext>>.Instance);

    // ---- The entity and its constraint (deferred from step 1) --------------------------

    [Fact]
    public async Task TheUniqueConstraint_RejectsASecondIdenticalLike()
    {
        // The one the whole design rests on. If this ever stops throwing, LikeAsync's
        // concurrency handling is dead code and duplicates get through.
        using SocialDbContext db = NewContext();
        db.Set<ContentLike>().Add(NewLike(Liker, "Article", 42));
        await db.SaveChangesAsync();

        db.Set<ContentLike>().Add(NewLike(Liker, "Article", 42));

        await Assert.ThrowsAsync<DbUpdateException>(() => db.SaveChangesAsync());
    }

    [Fact]
    public async Task TheConstraint_AllowsDifferentUsersAndItemsAndTypes()
    {
        using SocialDbContext db = NewContext();

        db.Set<ContentLike>().Add(NewLike(Liker, "Article", 42));
        db.Set<ContentLike>().Add(NewLike(Owner, "Article", 42));    // another user, same item
        db.Set<ContentLike>().Add(NewLike(Liker, "Article", 43));    // same user, another item
        db.Set<ContentLike>().Add(NewLike(Liker, "Comment", 42));    // same id, another TYPE

        await db.SaveChangesAsync();

        // The last one is the point: without ContentType in the key, Comment 42 and
        // Article 42 would collide into one like.
        Assert.Equal(4, await db.Set<ContentLike>().CountAsync());
    }

    [Fact]
    public async Task CreatedAt_RoundTripsWithoutChangingMeaning()
    {
        DateTimeOffset when = new(2026, 7, 16, 12, 30, 0, TimeSpan.Zero);

        using (SocialDbContext db = NewContext())
        {
            ContentLike like = NewLike(Liker, "Article", 42);
            like.CreatedAt = when;
            db.Set<ContentLike>().Add(like);
            await db.SaveChangesAsync();
        }

        using (SocialDbContext fresh = NewContext())
        {
            ContentLike stored = await fresh.Set<ContentLike>().SingleAsync();

            // A DateTime would come back Unspecified through Sqlite and quietly become local.
            Assert.Equal(when, stored.CreatedAt);
            Assert.Equal(TimeSpan.Zero, stored.CreatedAt.Offset);
        }
    }

    [Fact]
    public void TheIndexes_TheAccessPatternsNeed_Exist()
    {
        List<string> indexes = [];
        using (SqliteCommand command = _connection.CreateCommand())
        {
            command.CommandText = "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='ContentLikes'";
            using SqliteDataReader reader = command.ExecuteReader();
            while (reader.Read())
            {
                indexes.Add(reader.GetString(0));
            }
        }

        Assert.Contains(ContentLikeConfiguration.UniqueIndexName, indexes);
        Assert.Contains("IX_ContentLikes_ContentType_ContentId_CreatedAt", indexes);
        Assert.Contains("IX_ContentLikes_UserId_CreatedAt", indexes);
    }

    // ---- Liking -----------------------------------------------------------------------

    [Fact]
    public async Task AnAuthenticatedUser_CanLikeValidContent()
    {
        using SocialDbContext db = NewContext();
        LikeService<SocialDbContext> likes = ServiceOver(db, Content.Likeable(Owner));

        LikeResult result = await likes.LikeAsync(Liker, "Article", 42, default);

        Assert.True(result.IsLiked);
        Assert.Equal(1, result.LikeCount);
        Assert.True(result.ContentAvailable);
        Assert.Equal(1, await db.Set<ContentLike>().CountAsync());
    }

    [Fact]
    public async Task LikingTwice_IsIdempotent_AndStoresOneRow()
    {
        using SocialDbContext db = NewContext();
        LikeService<SocialDbContext> likes = ServiceOver(db, Content.Likeable(Owner));

        await likes.LikeAsync(Liker, "Article", 42, default);
        LikeResult again = await likes.LikeAsync(Liker, "Article", 42, default);

        // A double-submitted button is not an error. It is a request for a state that
        // already holds.
        Assert.True(again.IsLiked);
        Assert.Equal(1, again.LikeCount);
        Assert.Equal(1, await db.Set<ContentLike>().CountAsync());
    }

    [Fact]
    public async Task ConcurrentLikes_DoNotCreateDuplicates()
    {
        // The race the unique index exists for: separate contexts, so neither sees the
        // other's tracked entity, and both genuinely find no like before inserting.
        using SocialDbContext first = NewContext();
        using SocialDbContext second = NewContext();

        Task<LikeResult> a = ServiceOver(first, Content.Likeable(Owner)).LikeAsync(Liker, "Article", 42, default);
        Task<LikeResult> b = ServiceOver(second, Content.Likeable(Owner)).LikeAsync(Liker, "Article", 42, default);

        LikeResult[] results = await Task.WhenAll(a, b);

        // Both callers are told the like is in place, because it is. Neither sees an error:
        // the loser of the race asked for a state that now holds.
        Assert.All(results, r => Assert.True(r.IsLiked));

        using SocialDbContext check = NewContext();
        Assert.Equal(1, await check.Set<ContentLike>().CountAsync());
    }

    [Fact]
    public async Task TheLikeCount_CountsEveryonesLikes_NotJustTheCallers()
    {
        using SocialDbContext db = NewContext();
        IContentSource content = Content.Likeable(Owner);

        await ServiceOver(db, content).LikeAsync("user-a", "Article", 42, default);
        await ServiceOver(db, content).LikeAsync("user-b", "Article", 42, default);
        LikeResult result = await ServiceOver(db, content).LikeAsync("user-c", "Article", 42, default);

        Assert.Equal(3, result.LikeCount);
    }

    [Fact]
    public async Task TheLikeCount_IsScopedToTheItem()
    {
        using SocialDbContext db = NewContext();
        IContentSource content = Content.Likeable(Owner);

        await ServiceOver(db, content).LikeAsync(Liker, "Article", 42, default);
        await ServiceOver(db, content).LikeAsync(Liker, "Article", 43, default);
        LikeResult result = await ServiceOver(db, content).LikeAsync(Owner, "Article", 42, default);

        // Article 42 has two likers; 43 has one. A count that ignored the item would say 3.
        Assert.Equal(2, result.LikeCount);
    }

    [Fact]
    public async Task AUserMayLikeTheirOwnContent()
    {
        using SocialDbContext db = NewContext();
        LikeService<SocialDbContext> likes = ServiceOver(db, Content.Likeable(Owner));

        LikeResult result = await likes.LikeAsync(Owner, "Article", 42, default);

        // Decided explicitly: allowed, and counts like any other. The alert is what gets
        // suppressed, in step 6.
        Assert.True(result.IsLiked);
        Assert.Equal(1, result.LikeCount);
    }

    // ---- Refusal ----------------------------------------------------------------------

    [Fact]
    public async Task MissingContent_IsRefused_WithNoCount()
    {
        using SocialDbContext db = NewContext();
        LikeService<SocialDbContext> likes = ServiceOver(db, Content.Unavailable());

        LikeResult result = await likes.LikeAsync(Liker, "Article", 42, default);

        Assert.False(result.ContentAvailable);
        Assert.Null(result.LikeCount);
        Assert.False(result.IsLiked);
        Assert.Equal(0, await db.Set<ContentLike>().CountAsync());
    }

    [Fact]
    public async Task InaccessibleContent_IsRefusedIdentically_ToMissingContent()
    {
        // The heart of it. The host returns null for both, so these two results must be the
        // same value - not merely both failures. If they ever differ, liking becomes a way to
        // ask which ids exist.
        using SocialDbContext db = NewContext();

        LikeResult missing = await ServiceOver(db, Content.Unavailable()).LikeAsync(Liker, "Article", 42, default);
        LikeResult forbidden = await ServiceOver(db, Content.Unavailable()).LikeAsync(Liker, "Article", 99, default);

        Assert.Equal(missing, forbidden);
    }

    [Fact]
    public async Task ContentThatDoesNotSupportLikes_IsRefused()
    {
        using SocialDbContext db = NewContext();
        LikeService<SocialDbContext> likes = ServiceOver(db, Content.NotLikeable(Owner));

        LikeResult result = await likes.LikeAsync(Liker, "Article", 42, default);

        Assert.False(result.ContentAvailable);
        Assert.Equal(0, await db.Set<ContentLike>().CountAsync());
    }

    [Fact]
    public async Task SupportsLikes_DefaultsToFalse_SoContentIsNotLikeableByAccident()
    {
        // A host writing `new ContentInfo(ownerId)` has not opted in, and gets refused.
        using SocialDbContext db = NewContext();
        LikeService<SocialDbContext> likes = ServiceOver(db, new StubContent(new ContentInfo(Owner)));

        Assert.False((await likes.LikeAsync(Liker, "Article", 42, default)).ContentAvailable);
    }

    [Theory]
    [InlineData("", "Article")]
    [InlineData("   ", "Article")]
    [InlineData(Liker, "")]
    [InlineData(Liker, "   ")]
    public async Task EmptyInput_IsRefused_WithoutTroublingTheHost(string userId, string contentType)
    {
        using SocialDbContext db = NewContext();
        StubContent content = new(new ContentInfo(Owner, SupportsLikes: true));

        LikeResult result = await ServiceOver(db, content).LikeAsync(userId, contentType, 42, default);

        Assert.False(result.ContentAvailable);
        Assert.False(content.WasAsked);
    }

    [Fact]
    public async Task TheHostIsAsked_BeforeAnythingIsStored()
    {
        using SocialDbContext db = NewContext();
        StubContent content = new(new ContentInfo(Owner, SupportsLikes: true));

        await ServiceOver(db, content).LikeAsync(Liker, "Article", 42, default);

        Assert.True(content.WasAsked);
        Assert.Equal(Liker, content.AskedForUser);
        Assert.Equal("Article", content.AskedForType);
        Assert.Equal(42, content.AskedForId);
    }

    [Fact]
    public async Task AFailureThatIsNotADuplicate_Propagates()
    {
        // The other half of the catch. A like must never be reported as stored when it was
        // not, so a failure that is not a duplicate has to surface.
        //
        // A trigger that aborts inserts, because the failure has to be reachable: reads still
        // work, so the pre-check finds no like and the insert is attempted, which is what puts
        // us in the catch with something that is not a duplicate. (Dropping the table would
        // fail the pre-check instead and never reach the code under test.)
        using SocialDbContext db = NewContext();
        LikeService<SocialDbContext> likes = ServiceOver(db, Content.Likeable(Owner));

        using (SqliteCommand trigger = _connection.CreateCommand())
        {
            trigger.CommandText =
                "CREATE TRIGGER refuse_likes BEFORE INSERT ON ContentLikes " +
                "BEGIN SELECT RAISE(ABORT, 'refused'); END;";
            trigger.ExecuteNonQuery();
        }

        DbUpdateException error = await Assert.ThrowsAsync<DbUpdateException>(
            () => likes.LikeAsync(Liker, "Article", 42, default));

        // The insert's own failure, surfaced rather than mistaken for a duplicate.
        Assert.IsType<SqliteException>(error.InnerException);
        Assert.Equal(0, await db.Set<ContentLike>().CountAsync());
    }

    // ---- Unliking ---------------------------------------------------------------------

    [Fact]
    public async Task AUserCanRemoveTheirOwnLike()
    {
        using SocialDbContext db = NewContext();
        LikeService<SocialDbContext> likes = ServiceOver(db, Content.Likeable(Owner));
        await likes.LikeAsync(Liker, "Article", 42, default);

        LikeResult result = await likes.UnlikeAsync(Liker, "Article", 42, default);

        Assert.False(result.IsLiked);
        Assert.Equal(0, result.LikeCount);
        Assert.Equal(0, await db.Set<ContentLike>().CountAsync());
    }

    [Fact]
    public async Task UnlikingWhatWasNeverLiked_IsNotAnError()
    {
        using SocialDbContext db = NewContext();
        LikeService<SocialDbContext> likes = ServiceOver(db, Content.Likeable(Owner));

        LikeResult result = await likes.UnlikeAsync(Liker, "Article", 42, default);

        // A request for a state that already holds, not a failure.
        Assert.False(result.IsLiked);
        Assert.Equal(0, result.LikeCount);
    }

    [Fact]
    public async Task UnlikingTwice_IsIdempotent()
    {
        using SocialDbContext db = NewContext();
        LikeService<SocialDbContext> likes = ServiceOver(db, Content.Likeable(Owner));
        await likes.LikeAsync(Liker, "Article", 42, default);

        await likes.UnlikeAsync(Liker, "Article", 42, default);
        LikeResult again = await likes.UnlikeAsync(Liker, "Article", 42, default);

        Assert.False(again.IsLiked);
        Assert.Equal(0, again.LikeCount);
    }

    [Fact]
    public async Task OneUserCannotRemoveAnothersLike()
    {
        using SocialDbContext db = NewContext();
        IContentSource content = Content.Likeable(Owner);
        await ServiceOver(db, content).LikeAsync(Liker, "Article", 42, default);

        // Owner unliking the same article touches nothing of Liker's: the row is found by
        // (user, type, id), so there is no id Owner could pass to reach it.
        LikeResult result = await ServiceOver(db, content).UnlikeAsync(Owner, "Article", 42, default);

        Assert.False(result.IsLiked);      // Owner has no like
        Assert.Equal(1, result.LikeCount); // Liker's survives
        Assert.True(await db.Set<ContentLike>().AnyAsync(l => l.UserId == Liker));
    }

    [Fact]
    public async Task UnlikeRemovesTheLike_EvenWhenTheContentIsNoLongerAvailable()
    {
        // Nobody should be stuck holding a like on an article that has since been hidden.
        using SocialDbContext db = NewContext();
        await ServiceOver(db, Content.Likeable(Owner)).LikeAsync(Liker, "Article", 42, default);

        // ...and now the host says they cannot have it.
        LikeResult result = await ServiceOver(db, Content.Unavailable()).UnlikeAsync(Liker, "Article", 42, default);

        // The row is gone: the removal does not depend on the host's answer.
        Assert.Equal(0, await db.Set<ContentLike>().CountAsync());

        // But the count is withheld, because a count would describe content they may not see.
        Assert.False(result.ContentAvailable);
        Assert.Null(result.LikeCount);
    }

    [Fact]
    public async Task Unlike_DoesNotLeakACount_ForContentTheUserCannotSee()
    {
        // Without this, unlike would be the oracle like refuses to be: name any id and read
        // the count back to learn whether it exists.
        using SocialDbContext db = NewContext();
        await ServiceOver(db, Content.Likeable(Owner)).LikeAsync("someone-else", "Article", 42, default);

        LikeResult result = await ServiceOver(db, Content.Unavailable()).UnlikeAsync(Liker, "Article", 42, default);

        Assert.Null(result.LikeCount);
    }

    // ---- Reading state ----------------------------------------------------------------

    [Fact]
    public async Task Get_ReportsTheLikedState_AndTheCount()
    {
        using SocialDbContext db = NewContext();
        IContentSource content = Content.Likeable(Owner);
        await ServiceOver(db, content).LikeAsync(Liker, "Article", 42, default);
        await ServiceOver(db, content).LikeAsync(Owner, "Article", 42, default);

        LikeResult liker = await ServiceOver(db, content).GetAsync(Liker, "Article", 42, default);
        LikeResult bystander = await ServiceOver(db, content).GetAsync("user-3", "Article", 42, default);

        // Same content, same count, different answer to "have I liked it".
        Assert.True(liker.IsLiked);
        Assert.Equal(2, liker.LikeCount);
        Assert.False(bystander.IsLiked);
        Assert.Equal(2, bystander.LikeCount);
    }

    [Fact]
    public async Task Get_ChangesNothing()
    {
        using SocialDbContext db = NewContext();
        LikeService<SocialDbContext> likes = ServiceOver(db, Content.Likeable(Owner));

        await likes.GetAsync(Liker, "Article", 42, default);
        await likes.GetAsync(Liker, "Article", 42, default);

        // Reading the button's state must not create the like it is reporting on.
        Assert.Equal(0, await db.Set<ContentLike>().CountAsync());
    }

    [Fact]
    public async Task Get_RefusesContentTheUserCannotSee()
    {
        using SocialDbContext db = NewContext();
        await ServiceOver(db, Content.Likeable(Owner)).LikeAsync("someone-else", "Article", 42, default);

        LikeResult result = await ServiceOver(db, Content.Unavailable()).GetAsync(Liker, "Article", 42, default);

        // The article has a like. Saying so would prove it exists.
        Assert.False(result.ContentAvailable);
        Assert.Null(result.LikeCount);
    }

    [Fact]
    public async Task Get_ReportsZero_ForAvailableContentNobodyHasLiked()
    {
        // The distinction the nullable count exists for: 0 is an ordinary number, and content
        // nobody has liked is perfectly available.
        using SocialDbContext db = NewContext();

        LikeResult result = await ServiceOver(db, Content.Likeable(Owner)).GetAsync(Liker, "Article", 42, default);

        Assert.True(result.ContentAvailable);
        Assert.Equal(0, result.LikeCount);
        Assert.False(result.IsLiked);
    }

    // ---- The alert a like raises --------------------------------------------------------

    [Fact]
    public async Task LikingSomeoneElsesContent_TellsTheOwner()
    {
        using SocialDbContext db = NewContext();

        await ServiceOver(db, Content.Likeable(Owner)).LikeAsync(Liker, "Article", 42, default);

        UserAlert alert = await db.Set<UserAlert>().SingleAsync();
        Assert.Equal(Owner, alert.RecipientUserId);
        Assert.Equal(Liker, alert.ActorUserId);
        Assert.Equal(AlertTypes.ContentLiked, alert.AlertType);
        Assert.Equal("Article", alert.RelatedContentType);
        Assert.Equal(42, alert.RelatedContentId);
        Assert.False(alert.IsRead);
    }

    [Fact]
    public async Task LikingYourOwnContent_TellsNobody()
    {
        using SocialDbContext db = NewContext();

        LikeResult result = await ServiceOver(db, Content.Likeable(Owner)).LikeAsync(Owner, "Article", 42, default);

        // The like counts; the bell does not ring.
        Assert.True(result.IsLiked);
        Assert.Equal(1, result.LikeCount);
        Assert.Equal(0, await db.Set<UserAlert>().CountAsync());
    }

    [Fact]
    public async Task LikingTwice_RaisesOneAlert()
    {
        using SocialDbContext db = NewContext();
        LikeService<SocialDbContext> likes = ServiceOver(db, Content.Likeable(Owner));

        await likes.LikeAsync(Liker, "Article", 42, default);
        await likes.LikeAsync(Liker, "Article", 42, default);
        await likes.LikeAsync(Liker, "Article", 42, default);

        Assert.Equal(1, await db.Set<UserAlert>().CountAsync());
    }

    [Fact]
    public async Task UnlikingAndReliking_DoesNotRingTheBellAgain()
    {
        // Without this, a like button is a way to notify someone as many times as you can
        // click it.
        using SocialDbContext db = NewContext();
        LikeService<SocialDbContext> likes = ServiceOver(db, Content.Likeable(Owner));

        for (int i = 0; i < 5; i++)
        {
            await likes.LikeAsync(Liker, "Article", 42, default);
            await likes.UnlikeAsync(Liker, "Article", 42, default);
        }

        await likes.LikeAsync(Liker, "Article", 42, default);

        Assert.Equal(1, await db.Set<UserAlert>().CountAsync());
    }

    [Fact]
    public async Task TheAlertOutlivesTheLike()
    {
        using SocialDbContext db = NewContext();
        LikeService<SocialDbContext> likes = ServiceOver(db, Content.Likeable(Owner));
        await likes.LikeAsync(Liker, "Article", 42, default);

        await likes.UnlikeAsync(Liker, "Article", 42, default);

        // It is a record that something happened, and it did. Deleting it would rewrite the
        // owner's history; the spec is explicit that an expiring alert must not take the like
        // with it, and the same reasoning runs the other way.
        Assert.Equal(0, await db.Set<ContentLike>().CountAsync());
        Assert.Equal(1, await db.Set<UserAlert>().CountAsync());
    }

    [Fact]
    public async Task DifferentPeopleLikingTheSameThing_EachRingTheBell()
    {
        using SocialDbContext db = NewContext();
        IContentSource content = Content.Likeable(Owner);

        await ServiceOver(db, content).LikeAsync("user-a", "Article", 42, default);
        await ServiceOver(db, content).LikeAsync("user-b", "Article", 42, default);

        // One alert per person, not one per item: the owner wants to know who.
        Assert.Equal(2, await db.Set<UserAlert>().CountAsync());
    }

    [Fact]
    public async Task TheSamePersonLikingDifferentThings_RingsTheBellForEach()
    {
        using SocialDbContext db = NewContext();
        LikeService<SocialDbContext> likes = ServiceOver(db, Content.Likeable(Owner));

        await likes.LikeAsync(Liker, "Article", 42, default);
        await likes.LikeAsync(Liker, "Article", 43, default);

        Assert.Equal(2, await db.Set<UserAlert>().CountAsync());
    }

    [Fact]
    public async Task ARefusedLike_RaisesNoAlert()
    {
        using SocialDbContext db = NewContext();

        await ServiceOver(db, Content.Unavailable()).LikeAsync(Liker, "Article", 42, default);

        Assert.Equal(0, await db.Set<UserAlert>().CountAsync());
    }

    [Fact]
    public async Task AnAlertNeverSurvivesALikeThatFailed()
    {
        // The reason the like and the alert share one SaveChanges. If they did not, a rejected
        // insert could leave the alert behind, announcing something that never happened.
        using SocialDbContext db = NewContext();
        LikeService<SocialDbContext> likes = ServiceOver(db, Content.Likeable(Owner));

        using (SqliteCommand trigger = _connection.CreateCommand())
        {
            trigger.CommandText =
                "CREATE TRIGGER refuse_likes2 BEFORE INSERT ON ContentLikes " +
                "BEGIN SELECT RAISE(ABORT, 'refused'); END;";
            trigger.ExecuteNonQuery();
        }

        await Assert.ThrowsAsync<DbUpdateException>(() => likes.LikeAsync(Liker, "Article", 42, default));

        // What the host does next, in the same request, on the same context. If LikeAsync left
        // the alert tracked, this saves it - and the owner is told about a like that does not
        // exist. Clearing the tracker here instead would drop the alert either way and prove
        // nothing.
        await db.SaveChangesAsync();

        using SocialDbContext check = NewContext();
        Assert.Equal(0, await check.Set<ContentLike>().CountAsync());
        Assert.Equal(0, await check.Set<UserAlert>().CountAsync());
    }

    [Fact]
    public async Task ConcurrentLikes_RaiseOneAlert()
    {
        // The loser of the race must not raise a second alert on its way through the catch.
        using SocialDbContext first = NewContext();
        using SocialDbContext second = NewContext();

        await Task.WhenAll(
            ServiceOver(first, Content.Likeable(Owner)).LikeAsync(Liker, "Article", 42, default),
            ServiceOver(second, Content.Likeable(Owner)).LikeAsync(Liker, "Article", 42, default));

        using SocialDbContext check = NewContext();
        Assert.Equal(1, await check.Set<ContentLike>().CountAsync());
        Assert.Equal(1, await check.Set<UserAlert>().CountAsync());
    }

    [Fact]
    public async Task ContentWithNoOwner_RaisesNoAlert()
    {
        using SocialDbContext db = NewContext();
        LikeService<SocialDbContext> likes = ServiceOver(db, new StubContent(new ContentInfo("", SupportsLikes: true)));

        LikeResult result = await likes.LikeAsync(Liker, "Announcement", 1, default);

        // An announcement, say. The like counts; there is nobody to tell.
        Assert.True(result.IsLiked);
        Assert.Equal(0, await db.Set<UserAlert>().CountAsync());
    }

    public void Dispose() => _connection.Dispose();

    private static ContentLike NewLike(string userId, string contentType, long contentId) => new()
    {
        UserId = userId,
        ContentType = contentType,
        ContentId = contentId,
        CreatedAt = DateTimeOffset.UtcNow,
    };

    private static class Content
    {
        internal static IContentSource Likeable(string ownerId) => new StubContent(new ContentInfo(ownerId, SupportsLikes: true));

        internal static IContentSource NotLikeable(string ownerId) => new StubContent(new ContentInfo(ownerId, SupportsLikes: false));

        internal static IContentSource Unavailable() => new StubContent(null);
    }

    private sealed class StubContent : IContentSource
    {
        private readonly ContentInfo? _info;

        public StubContent(ContentInfo? info) => _info = info;

        public bool WasAsked { get; private set; }

        public string? AskedForUser { get; private set; }

        public string? AskedForType { get; private set; }

        public long AskedForId { get; private set; }

        public Task<ContentInfo?> GetAsync(string userId, string contentType, long contentId, CancellationToken ct)
        {
            WasAsked = true;
            AskedForUser = userId;
            AskedForType = contentType;
            AskedForId = contentId;

            return Task.FromResult(_info);
        }
    }
}
