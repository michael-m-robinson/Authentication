using Authentication.Admin;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

// See SetupController for why controllers suppress CS1591.
#pragma warning disable CS1591

namespace Authentication.Admin.Controllers;

/// <summary>
/// The base for the JSON admin API: gated to the admin role, CSRF-validated on every unsafe
/// method, and returning RFC 9457 Problem Details on failure.
/// </summary>
/// <remarks>
/// The API is a second face on the same services as the MVC UI, for a separate frontend or SPA.
/// It shares the host's cookie authentication, so it also shares the CSRF protection:
/// <see cref="AutoValidateAntiforgeryTokenAttribute"/> requires the antiforgery token on every
/// POST/PUT/PATCH/DELETE, which a client sends in the library's configured header
/// (<c>X-CSRF-TOKEN</c>) after fetching it from the antiforgery endpoint. Reads are exempt.
/// </remarks>
[ApiController]
[Authorize(Policy = AdminPolicies.Panel)]
[AutoValidateAntiforgeryToken]
[Produces("application/json")]
// The error shapes every endpoint can return, declared once for OpenAPI. Per-action success
// shapes stay on the actions (via ActionResult<T> / typed returns).
[ProducesResponseType(StatusCodes.Status400BadRequest, Type = typeof(Microsoft.AspNetCore.Mvc.ProblemDetails))]
[ProducesResponseType(StatusCodes.Status401Unauthorized)]
[ProducesResponseType(StatusCodes.Status403Forbidden)]
public abstract class AdminApiController : ControllerBase
{
    /// <summary>
    /// Turns an <see cref="AuthResult"/> into a response: <c>204 No Content</c> on success, or a
    /// <c>400</c> Problem Details carrying the explained errors on failure.
    /// </summary>
    protected IActionResult FromResult(AuthResult result)
        => result.Succeeded ? NoContent() : Failure(result);

    /// <summary>
    /// A <c>400</c> Problem Details from a rejected <see cref="AuthResult"/>. Admin failures are
    /// explained (they are behind the admin gate), so the reasons travel in the response.
    /// </summary>
    protected IActionResult Failure(AuthResult result)
        => Problem(
            detail: result.Errors.Count > 0 ? string.Join(" ", result.Errors) : "The request was rejected.",
            statusCode: StatusCodes.Status400BadRequest,
            title: "The request could not be completed.");
}
