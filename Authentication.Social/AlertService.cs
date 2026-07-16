using Microsoft.EntityFrameworkCore;

namespace Authentication.Social;

/// <summary>
/// The default <see cref="IAlertService"/>, storing alerts on the host's own
/// <typeparamref name="TContext"/>.
/// </summary>
/// <typeparam name="TContext">The host's context, the same one carrying the auth tables.</typeparam>
internal sealed class AlertService<TContext> : IAlertService
    where TContext : DbContext
{
    private readonly TContext _db;
    private readonly AlertWriter<TContext> _writer;
    private readonly TimeProvider _clock;

    public AlertService(TContext db, AlertWriter<TContext> writer, TimeProvider clock)
    {
        _db = db;
        _writer = writer;
        _clock = clock;
    }

    public async Task CreateAsync(CreateAlertRequest request, CancellationToken cancellationToken)
    {
        // Add decides whether the alert should exist at all, and saving nothing when it
        // should not is the whole point: a suppressed self-alert must not cost a round trip.
        if (_writer.Add(request) is not null)
        {
            await _db.SaveChangesAsync(cancellationToken);
        }
    }

    public async Task<AlertPage> GetAsync(
        string recipientUserId,
        long? beforeId,
        int limit,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(recipientUserId))
        {
            return new AlertPage([], null);
        }

        int take = limit <= 0
            ? IAlertService.DefaultPageSize
            : Math.Min(limit, IAlertService.MaxPageSize);

        // The recipient filter is in the query, not applied to the results. Whose alerts these
        // are is the first thing the database is told, so there is no moment at which another
        // user's row is in hand.
        IQueryable<UserAlert> query = _db.Set<UserAlert>()
            .Where(a => a.RecipientUserId == recipientUserId);

        if (beforeId is not null)
        {
            query = query.Where(a => a.Id < beforeId);
        }

        // One more than asked for, to learn whether another page exists without a second
        // query and without a count over the whole history.
        List<UserAlert> alerts = await query
            .OrderByDescending(a => a.Id)
            .Take(take + 1)
            .ToListAsync(cancellationToken);

        if (alerts.Count <= take)
        {
            // Fewer than we asked for: this is the last page, and a cursor would invite a
            // pointless round trip that returns nothing.
            return new AlertPage(alerts, null);
        }

        alerts.RemoveAt(take);

        return new AlertPage(alerts, alerts[^1].Id);
    }

    public async Task<int> CountUnreadAsync(string recipientUserId, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(recipientUserId))
        {
            return 0;
        }

        return await _db.Set<UserAlert>()
            .CountAsync(a => a.RecipientUserId == recipientUserId && !a.IsRead, cancellationToken);
    }

    public async Task MarkAsReadAsync(string recipientUserId, long alertId, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(recipientUserId))
        {
            return;
        }

        // Both halves of the key at once. An alert belonging to someone else simply is not
        // found, so "may I mark this?" is answered by the query rather than by a check that
        // could be forgotten.
        UserAlert? alert = await _db.Set<UserAlert>()
            .SingleOrDefaultAsync(
                a => a.Id == alertId && a.RecipientUserId == recipientUserId,
                cancellationToken);

        if (alert is null || alert.IsRead)
        {
            // Not yours, or already read. Both are requests for a state that already holds.
            return;
        }

        alert.IsRead = true;
        alert.ReadAt = _clock.GetUtcNow();

        await _db.SaveChangesAsync(cancellationToken);
    }

    public async Task MarkAllAsReadAsync(string recipientUserId, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(recipientUserId))
        {
            return;
        }

        DateTimeOffset now = _clock.GetUtcNow();

        // One UPDATE rather than loading every alert to set a flag on it. A user who has
        // ignored their alerts for a year should not have that year pulled into memory to
        // dismiss it.
        await _db.Set<UserAlert>()
            .Where(a => a.RecipientUserId == recipientUserId && !a.IsRead)
            .ExecuteUpdateAsync(
                setters => setters
                    .SetProperty(a => a.IsRead, true)
                    .SetProperty(a => a.ReadAt, now),
                cancellationToken);
    }
}
