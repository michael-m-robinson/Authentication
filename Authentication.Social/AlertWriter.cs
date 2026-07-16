using Microsoft.EntityFrameworkCore;

namespace Authentication.Social;

/// <summary>
/// Puts an alert into the context, without saving it.
/// </summary>
/// <typeparam name="TContext">The host's context.</typeparam>
/// <remarks>
/// Separate from <see cref="IAlertService"/> so that raising an alert can join work already
/// in flight. <c>ILikeService</c> needs the like and the alert about it to reach the database
/// together or not at all: an alert about a like that was rolled back is a lie, and a like
/// whose alert was lost is silent. Neither is possible if both are in one
/// <c>SaveChangesAsync</c>, and that is only possible if adding the alert does not save.
/// <para>
/// The suppression rule lives here rather than at each call site, so nobody can forget it.
/// </para>
/// </remarks>
internal sealed class AlertWriter<TContext>
    where TContext : DbContext
{
    private readonly TContext _db;
    private readonly TimeProvider _clock;

    public AlertWriter(TContext db, TimeProvider clock)
    {
        _db = db;
        _clock = clock;
    }

    /// <summary>
    /// Adds an alert to the context, unless it should not exist. Saves nothing.
    /// </summary>
    /// <returns>
    /// The alert added, or <see langword="null"/> if it was suppressed.
    /// </returns>
    /// <remarks>
    /// The entity comes back so a caller whose own write then fails can detach it. An alert
    /// left tracked after the thing it announces was rolled back would be saved by whatever
    /// called <c>SaveChanges</c> next, announcing something that never happened.
    /// </remarks>
    internal UserAlert? Add(CreateAlertRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (string.IsNullOrWhiteSpace(request.RecipientUserId) || string.IsNullOrWhiteSpace(request.AlertType))
        {
            return null;
        }

        // Nobody needs telling what they just did. Deciding it here rather than at each call
        // site means a host raising its own alert types gets the rule for free.
        if (string.Equals(request.RecipientUserId, request.ActorUserId, StringComparison.Ordinal))
        {
            return null;
        }

        UserAlert alert = new()
        {
            RecipientUserId = request.RecipientUserId,
            ActorUserId = request.ActorUserId,
            AlertType = request.AlertType,
            Message = request.Message,
            RelatedContentType = request.RelatedContentType,
            RelatedContentId = request.RelatedContentId,
            IsRead = false,
            CreatedAt = _clock.GetUtcNow(),
        };

        _db.Set<UserAlert>().Add(alert);

        return alert;
    }
}
