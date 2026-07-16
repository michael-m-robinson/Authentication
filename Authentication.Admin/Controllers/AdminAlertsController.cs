using Authentication.Admin;
using Authentication.Admin.ViewModels;
using Authentication.Social;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

// See SetupController for why controllers suppress CS1591.
#pragma warning disable CS1591

namespace Authentication.Admin.Controllers;

/// <summary>
/// The Social admin surface: broadcast an alert to every user, and view one user's alerts.
/// Present only when the host wired <c>Authentication.Social</c>; the feature provider removes
/// this controller otherwise.
/// </summary>
[Authorize(Policy = AdminPolicies.Panel)]
[Route("alerts")]
public sealed class AdminAlertsController : Controller
{
    private const int PageSize = 30;

    private readonly IAdminAlertBroadcaster _broadcaster;
    private readonly IAlertService _alerts;

    public AdminAlertsController(IAdminAlertBroadcaster broadcaster, IAlertService alerts)
    {
        _broadcaster = broadcaster;
        _alerts = alerts;
    }

    [HttpGet("")]
    public IActionResult Broadcast() => View(new BroadcastViewModel());

    [HttpPost("")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Broadcast(BroadcastViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        int sent = await _broadcaster.BroadcastAsync(
            model.AlertType.Trim(),
            string.IsNullOrWhiteSpace(model.Message) ? null : model.Message.Trim(),
            string.IsNullOrWhiteSpace(model.RelatedContentType) ? null : model.RelatedContentType.Trim(),
            model.RelatedContentId,
            HttpContext.RequestAborted);

        TempData["Status"] = $"Announcement sent to {sent} user(s).";
        return RedirectToAction(nameof(Broadcast));
    }

    // Named UserAlerts, not User, so it does not shadow ControllerBase.User (the principal).
    [HttpGet("user/{id}")]
    public async Task<IActionResult> UserAlerts(string id, long? before)
    {
        AlertPage page = await _alerts.GetAsync(id, before, PageSize, HttpContext.RequestAborted);
        return View(new UserAlertsViewModel(id, page));
    }
}

/// <summary>A user and a page of their alerts, for the admin support view.</summary>
public sealed record UserAlertsViewModel(string UserId, AlertPage Page);
