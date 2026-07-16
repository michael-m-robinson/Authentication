using Microsoft.Extensions.Logging;

namespace Authentication.Admin;

/// <summary>
/// The default <see cref="IAdminAuditLog"/>, which writes each action as a structured log event.
/// </summary>
/// <remarks>
/// This is what keeps audit always-on without forcing storage on a host: the trail goes wherever
/// the host's logging already goes (console, file, a log aggregator), with named fields so it can
/// be queried there. A host that needs a durable, first-class audit store registers its own
/// <see cref="IAdminAuditLog"/> instead, and the admin's <c>TryAdd</c> registration steps aside.
/// <para>
/// Logged at <see cref="LogLevel.Information"/>, because an admin action is a normal, expected
/// event worth keeping, not a warning. The fields are identifiers and outcomes only - never a
/// password, token, or recovery code.
/// </para>
/// </remarks>
internal sealed class LoggerAdminAuditLog : IAdminAuditLog
{
    private readonly ILogger<LoggerAdminAuditLog> _logger;

    public LoggerAdminAuditLog(ILogger<LoggerAdminAuditLog> logger)
    {
        _logger = logger;
    }

    public Task RecordAsync(AdminAuditEntry entry, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(entry);

        _logger.LogInformation(
            "Admin audit: {ActorName} ({ActorUserId}) performed {Action} on target {TargetUserId}; "
            + "outcome {Outcome} (status {StatusCode}) at {OccurredAt:o}.",
            entry.ActorName ?? "unknown",
            entry.ActorUserId ?? "unknown",
            entry.Action,
            entry.TargetUserId ?? "none",
            entry.Succeeded ? "success" : "failure",
            entry.StatusCode,
            entry.OccurredAt);

        return Task.CompletedTask;
    }
}
