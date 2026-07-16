using Authentication.Social;
using Microsoft.Extensions.DependencyInjection;

namespace Authentication.Admin.Tests;

/// <summary>
/// Covers the broadcaster: it raises one alert per user, across pages, carrying the type and any
/// message the caller gave.
/// </summary>
public sealed class AdminAlertBroadcasterTests : IDisposable
{
    private readonly AdminTestHost _host = new();

    public void Dispose() => _host.Dispose();

    private static AdminAlertBroadcaster BroadcasterOver(IServiceScope scope)
        => new(
            AdminTestHost.AdminUsers(scope),
            scope.ServiceProvider.GetRequiredService<IAlertService>());

    [Fact]
    public async Task Broadcast_RaisesOneAlertPerUser_WithTypeAndMessage()
    {
        for (int i = 0; i < 3; i++)
        {
            await _host.CreateUserAsync($"u{i}@example.com");
        }

        int sent;
        using (IServiceScope scope = _host.Scope())
        {
            sent = await BroadcasterOver(scope).BroadcastAsync(
                "MaintenanceTonight", "Down at 5pm.", relatedContentType: null, relatedContentId: null, default);
        }

        Assert.Equal(3, sent);

        using IServiceScope check = _host.Scope();
        AdminTestDbContext db = check.ServiceProvider.GetRequiredService<AdminTestDbContext>();
        List<UserAlert> alerts = await ToListAsync(db);

        Assert.Equal(3, alerts.Count);
        Assert.All(alerts, a => Assert.Equal("MaintenanceTonight", a.AlertType));
        Assert.All(alerts, a => Assert.Equal("Down at 5pm.", a.Message));
        Assert.All(alerts, a => Assert.Null(a.ActorUserId));   // a system broadcast has no actor
    }

    [Fact]
    public async Task Broadcast_LeavesMessageNull_WhenNoneGiven()
    {
        await _host.CreateUserAsync("only@example.com");

        using (IServiceScope scope = _host.Scope())
        {
            await BroadcasterOver(scope).BroadcastAsync(
                AlertTypes.SystemAnnouncement, message: null, relatedContentType: null, relatedContentId: null, default);
        }

        using IServiceScope check = _host.Scope();
        AdminTestDbContext db = check.ServiceProvider.GetRequiredService<AdminTestDbContext>();
        UserAlert alert = (await ToListAsync(db))[0];
        Assert.Null(alert.Message);
        Assert.Equal(AlertTypes.SystemAnnouncement, alert.AlertType);
    }

    private static async Task<List<UserAlert>> ToListAsync(AdminTestDbContext db)
        => await Microsoft.EntityFrameworkCore.EntityFrameworkQueryableExtensions
            .ToListAsync(db.Set<UserAlert>());
}
