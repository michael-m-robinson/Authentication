using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Mvc;

// See SetupController for why controllers suppress CS1591.
#pragma warning disable CS1591

namespace Authentication.Admin.Controllers;

/// <summary>
/// Issues an antiforgery token for a SPA driving the JSON API.
/// </summary>
/// <remarks>
/// The API validates the antiforgery token on every unsafe method (see
/// <see cref="AdminApiController"/>). A browser sends the paired cookie automatically, but a
/// SPA has to read the request token from somewhere and echo it in the header. This endpoint is
/// that somewhere: a <c>GET</c> (so no token is needed to call it) that sets the antiforgery
/// cookie and returns the request token and the header name to send it in.
/// <para>
/// Admin-gated like the rest of the API, so only a signed-in administrator can obtain a token,
/// which is all that needs one.
/// </para>
/// </remarks>
[Route("api/antiforgery")]
public sealed class AdminAntiforgeryController : AdminApiController
{
    private readonly IAntiforgery _antiforgery;

    public AdminAntiforgeryController(IAntiforgery antiforgery)
    {
        _antiforgery = antiforgery;
    }

    // no-store: the request token must not be retained by any cache (OWASP: a CSRF token must
    // not be leaked in logs or caches).
    [HttpGet("token")]
    [ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
    public IActionResult Token()
    {
        AntiforgeryTokenSet tokens = _antiforgery.GetAndStoreTokens(HttpContext);

        // Send this value in the returned header on every POST/PUT/PATCH/DELETE. The paired
        // cookie was just set on this response; the two are checked against each other.
        return Ok(new { token = tokens.RequestToken, headerName = tokens.HeaderName });
    }
}
