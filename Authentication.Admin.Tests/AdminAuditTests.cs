using Microsoft.Extensions.Logging;

namespace Authentication.Admin.Tests;

/// <summary>
/// Covers the default audit sink. The filter that feeds it - that every state-changing admin
/// action is recorded, with actor and target - is proven end to end in the HTTP tests, where a
/// real request runs through the real filter pipeline.
/// </summary>
public sealed class AdminAuditTests
{
    [Fact]
    public async Task LoggerSink_WritesOneInformationEntry_WithActorActionAndOutcome()
    {
        CapturingLogger<LoggerAdminAuditLog> logger = new();
        LoggerAdminAuditLog sink = new(logger);

        AdminAuditEntry entry = new(
            OccurredAt: DateTimeOffset.UnixEpoch,
            ActorUserId: "admin-1",
            ActorName: "alice@example.com",
            Action: "Users.Lock",
            TargetUserId: "user-2",
            Succeeded: true,
            StatusCode: 302);

        await sink.RecordAsync(entry, default);

        (LogLevel level, string message) = Assert.Single(logger.Entries);
        Assert.Equal(LogLevel.Information, level);
        Assert.Contains("alice@example.com", message);
        Assert.Contains("Users.Lock", message);
        Assert.Contains("user-2", message);
        Assert.Contains("success", message);
    }

    private sealed class CapturingLogger<T> : ILogger<T>
    {
        public List<(LogLevel Level, string Message)> Entries { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
            => Entries.Add((logLevel, formatter(state, exception)));
    }
}
