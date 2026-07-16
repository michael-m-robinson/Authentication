using Authentication.Social;
using Microsoft.AspNetCore.Mvc;

// See SetupController for why controllers suppress CS1591.
#pragma warning disable CS1591

namespace Authentication.Admin.Controllers;

/// <summary>
/// The JSON alerts API: broadcast an alert to every user, and read one user's alerts. Present
/// only when the host wired <c>Authentication.Social</c>; the feature provider removes it
/// otherwise, alongside its MVC twin.
/// </summary>
[Route("api/alerts")]
public sealed class AdminApiAlertsController : AdminApiController
{
    private const int PageSize = 30;

    private readonly IAdminAlertBroadcaster _broadcaster;
    private readonly IAlertService _alerts;

    public AdminApiAlertsController(IAdminAlertBroadcaster broadcaster, IAlertService alerts)
    {
        _broadcaster = broadcaster;
        _alerts = alerts;
    }

    [HttpPost("broadcast")]
    public async Task<IActionResult> Broadcast([FromBody] BroadcastRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.AlertType))
        {
            return Failure(AuthResult.Rejected("An alert type is required."));
        }

        int sent = await _broadcaster.BroadcastAsync(
            request.AlertType.Trim(),
            string.IsNullOrWhiteSpace(request.Message) ? null : request.Message.Trim(),
            string.IsNullOrWhiteSpace(request.RelatedContentType) ? null : request.RelatedContentType.Trim(),
            request.RelatedContentId,
            HttpContext.RequestAborted);

        return Ok(new { sent });
    }

    [HttpGet("user/{id}")]
    public async Task<ActionResult<AlertPage>> UserAlerts(string id, [FromQuery] long? before)
        => await _alerts.GetAsync(id, before, PageSize, HttpContext.RequestAborted);
}

/// <summary>Broadcast request: the alert type, optional message, and optional content reference.</summary>
public sealed record BroadcastRequest(
    string AlertType,
    string? Message = null,
    string? RelatedContentType = null,
    long? RelatedContentId = null);
