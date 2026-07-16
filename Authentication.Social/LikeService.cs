using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace Authentication.Social;

/// <summary>
/// The default <see cref="ILikeService"/>, storing likes on the host's own
/// <typeparamref name="TContext"/>.
/// </summary>
/// <typeparam name="TContext">
/// The host's <see cref="DbContext"/>: the same one carrying the auth tables, so a like and
/// the alert it raises commit together.
/// </typeparam>
internal sealed class LikeService<TContext> : ILikeService
    where TContext : DbContext
{
    private readonly TContext _db;
    private readonly IContentSource _content;
    private readonly AlertWriter<TContext> _alerts;
    private readonly TimeProvider _clock;
    private readonly ILogger<LikeService<TContext>> _logger;

    public LikeService(
        TContext db,
        IContentSource content,
        AlertWriter<TContext> alerts,
        TimeProvider clock,
        ILogger<LikeService<TContext>> logger)
    {
        _db = db;
        _content = content;
        _alerts = alerts;
        _clock = clock;
        _logger = logger;
    }

    public async Task<LikeResult> LikeAsync(
        string userId,
        string contentType,
        long contentId,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(userId) || string.IsNullOrWhiteSpace(contentType))
        {
            return LikeResult.Unavailable();
        }

        // The host decides whether this user may have this content, and whether it takes
        // likes at all. Both answers collapse to the same unavailable result: see LikeResult.
        ContentInfo? content = await _content.GetAsync(userId, contentType, contentId, cancellationToken);
        if (content is null || !content.SupportsLikes)
        {
            return LikeResult.Unavailable();
        }

        // Already liked? Then there is nothing to store and nobody to tell. The unique index
        // is still what makes one-like-per-item true - this check cannot, since another
        // request can slip in behind it - but it means the ordinary case of a double-tapped
        // button costs a read instead of a failed insert and a rolled-back alert.
        if (await IsLikedAsync(userId, contentType, contentId, cancellationToken))
        {
            return LikeResult.Liked(await CountAsync(contentType, contentId, cancellationToken));
        }

        ContentLike like = new()
        {
            UserId = userId,
            ContentType = contentType,
            ContentId = contentId,
            CreatedAt = _clock.GetUtcNow(),
        };

        _db.Set<ContentLike>().Add(like);

        UserAlert? alert = await AddLikeAlertIfNewAsync(
            content.OwnerUserId, userId, contentType, contentId, cancellationToken);

        try
        {
            // The like and the alert about it, in one write. Either both land or neither does:
            // an alert about a like that was rolled back is a lie, and a like whose alert was
            // lost is silent.
            await _db.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateException)
        {
            // Detach both: they are still tracked as Added, so the next SaveChanges on this
            // context - the host's own, later in the same request - would retry them. The
            // alert especially: it would announce a like that does not exist.
            _db.Entry(like).State = EntityState.Detached;

            if (alert is not null)
            {
                _db.Entry(alert).State = EntityState.Detached;
            }

            if (!await WasStoredByAnotherRequestAsync(userId, contentType, contentId, cancellationToken))
            {
                // Not a duplicate: the insert failed for some other reason. Bare throw, so the
                // original exception carries on with its stack trace intact. Swallowing it
                // would report a like that was never stored.
                throw;
            }

            // Someone else stored the same like first. That is the state the caller asked for,
            // so there is nothing to undo and nothing to report - and no alert, because the
            // request that won the race raised it.
            _logger.LogDebug(
                "A concurrent like for {ContentType} {ContentId} was already stored; treating as liked.",
                contentType,
                contentId);
        }

        return LikeResult.Liked(await CountAsync(contentType, contentId, cancellationToken));
    }

    public async Task<LikeResult> UnlikeAsync(
        string userId,
        string contentType,
        long contentId,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(userId) || string.IsNullOrWhiteSpace(contentType))
        {
            return LikeResult.Unavailable();
        }

        // Remove the like first, and without asking the host anything. It is this user's own
        // row, so removing it can harm nobody, and gating it on the content still being
        // visible would trap someone who liked an article that has since been hidden, holding
        // a like they can never take back.
        //
        // Found by (user, type, id), which is why "only the owner may remove it" needs no
        // check: there is no id a caller could pass to reach anyone else's like.
        ContentLike? like = await _db.Set<ContentLike>()
            .SingleOrDefaultAsync(
                l => l.UserId == userId && l.ContentType == contentType && l.ContentId == contentId,
                cancellationToken);

        if (like is not null)
        {
            _db.Set<ContentLike>().Remove(like);
            await _db.SaveChangesAsync(cancellationToken);
        }

        // Nothing above cares whether the like existed. Unliking what you have not liked is a
        // request for a state that already holds, not an error.

        // The count is a different question: it describes the content rather than this user's
        // own row, so it is only for people who may see the content. Withholding it is what
        // stops unlike becoming the oracle that like refuses to be - "5 likes" for an id you
        // guessed would prove it exists.
        ContentInfo? content = await _content.GetAsync(userId, contentType, contentId, cancellationToken);
        if (content is null || !content.SupportsLikes)
        {
            return LikeResult.Unavailable();
        }

        return LikeResult.NotLiked(await CountAsync(contentType, contentId, cancellationToken));
    }

    public async Task<LikeResult> GetAsync(
        string userId,
        string contentType,
        long contentId,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(userId) || string.IsNullOrWhiteSpace(contentType))
        {
            return LikeResult.Unavailable();
        }

        // Only a read, but an unguarded one would answer the question the like path refuses
        // to: a count for content this user cannot see proves the content is there.
        ContentInfo? content = await _content.GetAsync(userId, contentType, contentId, cancellationToken);
        if (content is null || !content.SupportsLikes)
        {
            return LikeResult.Unavailable();
        }

        bool isLiked = await _db.Set<ContentLike>()
            .AnyAsync(
                l => l.UserId == userId && l.ContentType == contentType && l.ContentId == contentId,
                cancellationToken);

        int count = await CountAsync(contentType, contentId, cancellationToken);

        return isLiked ? LikeResult.Liked(count) : LikeResult.NotLiked(count);
    }

    /// <summary>
    /// Adds a <see cref="AlertTypes.ContentLiked"/> alert, unless this actor has already been
    /// reported liking this content. Saves nothing.
    /// </summary>
    /// <returns>The alert added, or <see langword="null"/> if none was.</returns>
    /// <remarks>
    /// One alert per person per item, ever. A user who likes, unlikes and likes again does not
    /// ring the owner's bell twice, which is a thing people do idly and a thing they can do
    /// deliberately: without this, a like button is a way to notify someone as many times as
    /// you can click.
    /// <para>
    /// The alert stays after the like is removed. It is a record that something happened, and
    /// it did; deleting it would rewrite the owner's history, and re-raising it on the next
    /// like is the spam this prevents.
    /// </para>
    /// <para>
    /// Self-likes are suppressed by <see cref="AlertWriter{TContext}"/>, so there is nothing
    /// about them here.
    /// </para>
    /// </remarks>
    private async Task<UserAlert?> AddLikeAlertIfNewAsync(
        string ownerUserId,
        string actorUserId,
        string contentType,
        long contentId,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(ownerUserId))
        {
            // Content with no owner - an announcement, say. Nobody to tell.
            return null;
        }

        bool alreadyTold = await _db.Set<UserAlert>()
            .AnyAsync(
                a => a.RecipientUserId == ownerUserId
                    && a.ActorUserId == actorUserId
                    && a.AlertType == AlertTypes.ContentLiked
                    && a.RelatedContentType == contentType
                    && a.RelatedContentId == contentId,
                cancellationToken);

        if (alreadyTold)
        {
            return null;
        }

        return _alerts.Add(new CreateAlertRequest(
            ownerUserId,
            AlertTypes.ContentLiked,
            actorUserId,
            contentType,
            contentId));
    }

    /// <summary>
    /// Whether this user's like of this content is stored.
    /// </summary>
    private async Task<bool> IsLikedAsync(
        string userId,
        string contentType,
        long contentId,
        CancellationToken cancellationToken)
        => await _db.Set<ContentLike>()
            .AnyAsync(
                l => l.UserId == userId && l.ContentType == contentType && l.ContentId == contentId,
                cancellationToken);

    /// <summary>
    /// Whether the like turned out to be stored anyway, after our own insert was rejected.
    /// </summary>
    /// <remarks>
    /// This is what distinguishes the harmless failure from the real one. Two requests can
    /// both find no like and both go on to insert; checking first cannot close that window,
    /// so the unique index is what actually enforces one-like-per-item, and the insert above
    /// expects to be rejected by it.
    /// <para>
    /// Asking the database beats decoding the error. "Duplicate key" is a different exception
    /// type and a different number on every provider - 2627 on SQL Server, 23505 on
    /// PostgreSQL, 2067 on SQLite - so recognizing it by code would mean this package knowing
    /// which database it is running on, and being wrong on the one nobody tested. "Is the like
    /// there now?" needs no such knowledge, and answers the question that actually matters.
    /// </para>
    /// <para>
    /// It swallows its own failures on purpose. This runs inside a catch, against the very
    /// database that just refused the insert, so whatever broke that will usually break this
    /// too - and an exception thrown from here would replace the original with a second copy
    /// of the same cause, reported from the wrong place. Answering "no" instead lets the
    /// caller rethrow the failure that actually matters.
    /// </para>
    /// </remarks>
    private async Task<bool> WasStoredByAnotherRequestAsync(
        string userId,
        string contentType,
        long contentId,
        CancellationToken cancellationToken)
    {
        try
        {
            return await _db.Set<ContentLike>()
                .AnyAsync(
                    l => l.UserId == userId && l.ContentType == contentType && l.ContentId == contentId,
                    cancellationToken);
        }
#pragma warning disable CA1031 // Deliberately broad: see the remarks above.
        catch (Exception ex)
#pragma warning restore CA1031
        {
            _logger.LogDebug(
                ex,
                "Could not confirm whether a like for {ContentType} {ContentId} was already stored; " +
                "treating the original insert failure as real.",
                contentType,
                contentId);

            return false;
        }
    }

    /// <summary>
    /// Counts the likes on a piece of content, from the database.
    /// </summary>
    /// <remarks>
    /// Always counted, never taken from the caller and never cached. The spec's aggregate
    /// column is a performance answer to a problem no measurement here has shown, and a
    /// stored count is a second source of truth that can drift from the rows it claims to
    /// summarize.
    /// </remarks>
    private async Task<int> CountAsync(string contentType, long contentId, CancellationToken cancellationToken)
        => await _db.Set<ContentLike>()
            .CountAsync(l => l.ContentType == contentType && l.ContentId == contentId, cancellationToken);
}
