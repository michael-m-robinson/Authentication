namespace Authentication.Admin;

/// <summary>
/// One recorded admin action: who did what to whom, when, and how it turned out.
/// </summary>
/// <remarks>
/// Deliberately carries identifiers and outcomes, never secrets. A password reset is recorded
/// as having happened and to which user; the generated or supplied password is never part of
/// the entry, per the library's no-secrets-in-logs rule.
/// </remarks>
/// <param name="OccurredAt">When the action completed.</param>
/// <param name="ActorUserId">The signed-in administrator's user id, or null if unresolved.</param>
/// <param name="ActorName">The administrator's name or email, for a readable trail.</param>
/// <param name="Action">
/// What was done, as <c>Controller.Action</c> (e.g. <c>Users.Lock</c>), so the trail reads
/// the same whether the action came through the MVC UI or the JSON API.
/// </param>
/// <param name="TargetUserId">The user the action was aimed at, when there is one.</param>
/// <param name="Succeeded">Whether the action completed without an error result.</param>
/// <param name="StatusCode">The HTTP status the action returned.</param>
public sealed record AdminAuditEntry(
    DateTimeOffset OccurredAt,
    string? ActorUserId,
    string? ActorName,
    string Action,
    string? TargetUserId,
    bool Succeeded,
    int StatusCode);

/// <summary>
/// Records administrator actions to an audit trail.
/// </summary>
/// <remarks>
/// The default implementation writes structured log events, which keeps the admin package
/// store-agnostic - it forces no table or migration on a host. A host that needs a durable,
/// queryable trail (a database table, a SIEM, an append-only store) registers its own
/// implementation; the admin registers the default with <c>TryAdd</c>, so the host's wins.
/// <para>
/// Every admin action is recorded through the <c>AdminAuditFilter</c>, which is attached to
/// every admin controller, so neither the MVC UI nor the JSON API can perform an action that
/// escapes the trail.
/// </para>
/// </remarks>
public interface IAdminAuditLog
{
    /// <summary>
    /// Records one action. Should not throw: a failure to write the trail must not turn a
    /// completed admin action into an error, so an implementation swallows or logs its own
    /// failures rather than propagating them.
    /// </summary>
    /// <param name="entry">The action to record.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    Task RecordAsync(AdminAuditEntry entry, CancellationToken cancellationToken);
}
