using Authentication.Social;

namespace Authentication.Admin;

/// <summary>
/// Sends an alert to every user, as a fan-out of one alert per recipient.
/// </summary>
/// <remarks>
/// Only registered when the host wired <c>Authentication.Social</c>. Separated from the
/// controller so the fan-out is testable and the controller stays thin.
/// </remarks>
public interface IAdminAlertBroadcaster
{
    /// <summary>
    /// Raises an alert of <paramref name="alertType"/> for every user, and returns how many were
    /// sent.
    /// </summary>
    /// <param name="alertType">
    /// The type to send: a built-in <see cref="AlertTypes"/> value, or any constant the host
    /// defines. The host renders the wording from this, unless <paramref name="message"/> is
    /// given.
    /// </param>
    /// <param name="message">
    /// Optional literal text, for an announcement whose wording is not derivable from the type.
    /// </param>
    /// <param name="relatedContentType">
    /// Optional host content type the announcement points at, so the host can render a link.
    /// </param>
    /// <param name="relatedContentId">Optional id within that content type.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    Task<int> BroadcastAsync(
        string alertType,
        string? message,
        string? relatedContentType,
        long? relatedContentId,
        CancellationToken cancellationToken);
}

/// <summary>
/// The default <see cref="IAdminAlertBroadcaster"/>: pages through all users and raises one
/// alert each.
/// </summary>
/// <remarks>
/// Fan-out-on-write, which is Social's own model for a broadcast (see the library's alerts
/// guidance): one <c>UserAlert</c> per recipient, so each person has their own read state.
/// <para>
/// The alert type is whatever the caller passes - a built-in <c>AlertTypes</c> value or a host
/// constant - so a host can send any of its announcement kinds. For a type with a fixed meaning
/// the host renders the wording; for a genuinely one-off announcement the caller passes literal
/// text as the message. This is synchronous and suited to modest user bases; a very large site
/// should drive a broadcast from its own background job instead.
/// </para>
/// </remarks>
internal sealed class AdminAlertBroadcaster : IAdminAlertBroadcaster
{
    private const int PageSize = 200;

    private readonly IAdminUserService _users;
    private readonly IAlertService _alerts;

    public AdminAlertBroadcaster(IAdminUserService users, IAlertService alerts)
    {
        _users = users;
        _alerts = alerts;
    }

    public async Task<int> BroadcastAsync(
        string alertType,
        string? message,
        string? relatedContentType,
        long? relatedContentId,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(alertType);

        int sent = 0;
        int page = 1;

        while (true)
        {
            AdminUserPage users = await _users.ListAsync(new AdminUserQuery(Page: page, PageSize: PageSize));

            foreach (AdminUserSummary user in users.Users)
            {
                await _alerts.CreateAsync(
                    new CreateAlertRequest(
                        RecipientUserId: user.Id,
                        AlertType: alertType,
                        ActorUserId: null,
                        RelatedContentType: relatedContentType,
                        RelatedContentId: relatedContentId,
                        Message: message),
                    cancellationToken);
                sent++;
            }

            if (!users.HasNext)
            {
                return sent;
            }

            page++;
        }
    }
}
