using System.Collections.Concurrent;
using Authentication;

namespace Authentication.Tests.Fakes;

/// <summary>
/// An <see cref="IBackgroundTaskQueue"/> the test drains on demand.
/// </summary>
/// <remarks>
/// Substituted for the real queue so queued work runs deterministically instead of racing
/// the hosted service. It also lets a test observe that a call queued work <em>without</em>
/// running it — which is the whole point of
/// <see cref="IAuthService.RequestPasswordResetAsync"/>: it must do no account-dependent
/// work on the calling thread.
/// </remarks>
internal sealed class TestBackgroundTaskQueue : IBackgroundTaskQueue
{
    private readonly ConcurrentQueue<Func<CancellationToken, ValueTask>> _items = new();

    public int PendingCount => _items.Count;

    public ValueTask QueueBackgroundWorkItemAsync(Func<CancellationToken, ValueTask> workItem)
    {
        ArgumentNullException.ThrowIfNull(workItem);
        _items.Enqueue(workItem);
        return ValueTask.CompletedTask;
    }

    public ValueTask<Func<CancellationToken, ValueTask>> DequeueAsync(CancellationToken cancellationToken)
    {
        if (_items.TryDequeue(out Func<CancellationToken, ValueTask>? workItem))
        {
            return ValueTask.FromResult(workItem);
        }

        throw new InvalidOperationException("The queue is empty.");
    }

    /// <summary>
    /// Runs everything queued so far, exactly as the real hosted service would.
    /// </summary>
    public async Task DrainAsync()
    {
        while (_items.TryDequeue(out Func<CancellationToken, ValueTask>? workItem))
        {
            await workItem(CancellationToken.None);
        }
    }
}
