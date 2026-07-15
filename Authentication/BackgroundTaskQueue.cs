// Adapted from the ASP.NET Core documentation sample "Queued background tasks":
// https://github.com/dotnet/AspNetCore.Docs/blob/main/aspnetcore/fundamentals/host/hosted-services/samples/8.0/BackgroundTasksSample/Services/BackgroundTaskQueue.cs
// Licensed under the MIT License. Copyright (c) Microsoft Corporation.
// See THIRD-PARTY-NOTICES.txt.
//
// Changes from the original: internal rather than public, so this cannot collide with a
// host's own IBackgroundTaskQueue; capacity comes from ReusableAuthOptions instead of a
// constructor int; file-scoped namespace and ArgumentNullException.ThrowIfNull to satisfy
// this repo's analyzers.

using System.Threading.Channels;
using Microsoft.Extensions.Options;

namespace Authentication;

/// <summary>
/// A queue of background work items.
/// </summary>
/// <remarks>
/// Used to keep email delivery off the request thread. That matters most for
/// <see cref="IAuthService.RequestPasswordResetAsync"/>: awaiting an SMTP call only for
/// addresses that turn out to be registered would answer "does this account exist" to
/// anyone timing the response, however uniform the response body is.
/// </remarks>
internal interface IBackgroundTaskQueue
{
    /// <summary>
    /// Queues a work item.
    /// </summary>
    /// <remarks>
    /// Completes once the item is queued. When the queue is full this waits for room
    /// rather than discarding the item — see <see cref="BackgroundTaskQueue"/>.
    /// </remarks>
    ValueTask QueueBackgroundWorkItemAsync(Func<CancellationToken, ValueTask> workItem);

    /// <summary>
    /// Waits for and removes the next work item.
    /// </summary>
    ValueTask<Func<CancellationToken, ValueTask>> DequeueAsync(CancellationToken cancellationToken);
}

/// <inheritdoc cref="IBackgroundTaskQueue"/>
internal sealed class BackgroundTaskQueue : IBackgroundTaskQueue
{
    private readonly Channel<Func<CancellationToken, ValueTask>> _queue;

    public BackgroundTaskQueue(IOptions<ReusableAuthOptions> options)
    {
        ArgumentNullException.ThrowIfNull(options);

        // Capacity should be set based on the expected application load and
        // number of concurrent threads accessing the queue.
        // BoundedChannelFullMode.Wait will cause calls to WriteAsync() to return a task,
        // which completes only when space became available. This leads to backpressure,
        // in case too many publishers/calls start accumulating.
        BoundedChannelOptions channelOptions = new(options.Value.BackgroundEmailQueueCapacity)
        {
            FullMode = BoundedChannelFullMode.Wait,
        };

        _queue = Channel.CreateBounded<Func<CancellationToken, ValueTask>>(channelOptions);
    }

    public async ValueTask QueueBackgroundWorkItemAsync(Func<CancellationToken, ValueTask> workItem)
    {
        ArgumentNullException.ThrowIfNull(workItem);

        await _queue.Writer.WriteAsync(workItem);
    }

    public async ValueTask<Func<CancellationToken, ValueTask>> DequeueAsync(CancellationToken cancellationToken)
    {
        Func<CancellationToken, ValueTask> workItem = await _queue.Reader.ReadAsync(cancellationToken);

        return workItem;
    }
}
