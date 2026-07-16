namespace Authentication.Social;

/// <summary>
/// Raises alerts, and lets a user read their own.
/// </summary>
/// <remarks>
/// Every method takes the recipient's id and filters on it in the query itself, never after.
/// A user's alerts are theirs alone: there is no method here that reads or changes an alert
/// without naming whose it must be, so there is no id a caller could pass to reach someone
/// else's.
/// <para>
/// Pass that id from the authenticated request - <c>IAuthService.CurrentPrincipal</c>, or the
/// <c>NameIdentifier</c> claim. Never from the request body: a caller who supplies their own
/// recipient id can read anyone's alerts.
/// </para>
/// <para>
/// This package raises <see cref="AlertTypes.ContentLiked"/> itself, when
/// <see cref="ILikeService"/> stores a like on someone else's content. Everything else is the
/// host's to raise through <see cref="CreateAsync"/>.
/// </para>
/// </remarks>
public interface IAlertService
{
    /// <summary>
    /// Raises an alert.
    /// </summary>
    /// <param name="request">Who to tell, what happened, and what it concerns.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <remarks>
    /// Does nothing when the recipient and the actor are the same person. Nobody needs telling
    /// what they just did, and this is where that is decided rather than at each call site, so
    /// no caller can forget.
    /// </remarks>
    Task CreateAsync(CreateAlertRequest request, CancellationToken cancellationToken);

    /// <summary>
    /// Reads a page of a user's own alerts, newest first.
    /// </summary>
    /// <param name="recipientUserId">Whose alerts. From the authenticated request.</param>
    /// <param name="beforeId">
    /// Read alerts older than this one. Pass <see cref="AlertPage.NextCursor"/> from the
    /// previous page, or null to start at the newest.
    /// </param>
    /// <param name="limit">
    /// How many to return. Capped at <see cref="MaxPageSize"/>: an unbounded history in one
    /// request is a page nobody reads and a query that gets slower every year.
    /// </param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The page, and a cursor for the next.</returns>
    /// <remarks>
    /// A cursor, not a page number. An alert feed changes while it is being read, and offsets
    /// shift under it: a new alert arriving between page 1 and page 2 pushes one alert down
    /// into a page the reader has already seen, so it never gets shown. A cursor names a
    /// position rather than a distance, so new arrivals do not move it.
    /// <para>
    /// <strong>Recheck access before you render.</strong> This returns the ids an alert refers
    /// to, not the content. Content the recipient could see when the alert was raised may have
    /// been deleted, hidden or moderated since, so ask <see cref="IContentSource"/> at render
    /// time and show something generic when it says no.
    /// </para>
    /// </remarks>
    Task<AlertPage> GetAsync(
        string recipientUserId,
        long? beforeId,
        int limit,
        CancellationToken cancellationToken);

    /// <summary>
    /// How many alerts a user has not read.
    /// </summary>
    /// <param name="recipientUserId">Whose alerts. From the authenticated request.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <remarks>The badge. Asked on every page load, so it is a count and nothing more.</remarks>
    Task<int> CountUnreadAsync(string recipientUserId, CancellationToken cancellationToken);

    /// <summary>
    /// Marks one of a user's own alerts as read.
    /// </summary>
    /// <param name="recipientUserId">Whose alert it must be. From the authenticated request.</param>
    /// <param name="alertId">Which alert.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <remarks>
    /// An alert belonging to someone else is not found, and nothing happens. No error either:
    /// "no such alert of yours" and "already read" are both requests for a state that already
    /// holds, and neither is worth an exception.
    /// </remarks>
    Task MarkAsReadAsync(string recipientUserId, long alertId, CancellationToken cancellationToken);

    /// <summary>
    /// Marks all of a user's own alerts as read.
    /// </summary>
    /// <param name="recipientUserId">Whose alerts. From the authenticated request.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <remarks>Touches only this user's alerts.</remarks>
    Task MarkAllAsReadAsync(string recipientUserId, CancellationToken cancellationToken);

    /// <summary>
    /// The most alerts <see cref="GetAsync"/> will return at once: 100.
    /// </summary>
    public const int MaxPageSize = 100;

    /// <summary>
    /// What <see cref="GetAsync"/> returns when asked for a non-positive limit: 20.
    /// </summary>
    public const int DefaultPageSize = 20;
}

/// <summary>
/// An alert to raise.
/// </summary>
/// <param name="RecipientUserId">The Identity user to tell.</param>
/// <param name="AlertType">What happened. See <see cref="AlertTypes"/>.</param>
/// <param name="ActorUserId">
/// The Identity user who caused it, or null if the system did. When this equals
/// <paramref name="RecipientUserId"/> the alert is not raised at all.
/// </param>
/// <param name="RelatedContentType">The content it concerns, if any.</param>
/// <param name="RelatedContentId">The id of that content.</param>
public sealed record CreateAlertRequest(
    string RecipientUserId,
    string AlertType,
    string? ActorUserId = null,
    string? RelatedContentType = null,
    long? RelatedContentId = null);

/// <summary>
/// A page of alerts.
/// </summary>
/// <param name="Alerts">The alerts, newest first.</param>
/// <param name="NextCursor">
/// Pass as <c>beforeId</c> to read the next page, or null when there are no more.
/// </param>
public sealed record AlertPage(IReadOnlyList<UserAlert> Alerts, long? NextCursor);
