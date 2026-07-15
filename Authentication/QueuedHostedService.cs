// Adapted from the ASP.NET Core documentation sample "Queued background tasks":
// https://github.com/dotnet/AspNetCore.Docs/blob/main/aspnetcore/fundamentals/host/hosted-services/samples/8.0/BackgroundTasksSample/Services/QueuedHostedService.cs
// Licensed under the MIT License. Copyright (c) Microsoft Corporation.
// See THIRD-PARTY-NOTICES.txt.
//
// Changes from the original: internal rather than public; the console-demo logging is
// dropped (it used interpolated log templates, which this repo's analyzers reject); and
// OperationCanceledException from DequeueAsync is caught so an ordinary shutdown does not
// surface as a faulted background service. The original's general catch around the work
// item is kept as-is, and matters here for the reason given below.

using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Authentication;

/// <summary>
/// Runs the work items queued on <see cref="IBackgroundTaskQueue"/>, one at a time.
/// </summary>
internal sealed class QueuedHostedService : BackgroundService
{
    private readonly ILogger<QueuedHostedService> _logger;

    public QueuedHostedService(IBackgroundTaskQueue taskQueue, ILogger<QueuedHostedService> logger)
    {
        TaskQueue = taskQueue;
        _logger = logger;
    }

    public IBackgroundTaskQueue TaskQueue { get; }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await BackgroundProcessing(stoppingToken);
    }

    private async Task BackgroundProcessing(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            Func<CancellationToken, ValueTask> workItem;

            try
            {
                workItem = await TaskQueue.DequeueAsync(stoppingToken);
            }
            catch (OperationCanceledException)
            {
                // The host is stopping. Not a fault: leave quietly, rather than letting
                // it escape ExecuteAsync, where the default BackgroundServiceException-
                // Behavior would treat it as a reason to bring the host down.
                break;
            }

            try
            {
                await workItem(stoppingToken);
            }
#pragma warning disable CA1031 // Deliberately broad: see below.
            catch (Exception ex)
#pragma warning restore CA1031
            {
                // The work items call the host's IAuthEmailSender, which is arbitrary
                // code talking to a mail provider and can fail in ways this library
                // cannot enumerate. One bad send must not take the loop down and stop
                // every future auth email silently.
                //
                // Nothing identifying is logged: the work items close over email
                // addresses (PII) and tokens (bearer credentials), and neither belongs
                // in a log. See rules/security.md.
                _logger.LogError(ex, "Error occurred executing a queued auth email.");
            }
        }
    }
}
