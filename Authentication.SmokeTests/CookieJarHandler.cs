using System.Net;

namespace Authentication.SmokeTests;

/// <summary>
/// Stores and replays cookies, the way a browser does.
/// </summary>
/// <remarks>
/// TestServer's handler has no cookie container of its own, so without this every request
/// would arrive anonymous and the session would never be exercised at all, and the tests would
/// pass or fail for reasons having nothing to do with the cookie.
/// <para>
/// Deliberately a real <see cref="CookieContainer"/> rather than "remember the last
/// Set-Cookie header": it applies the actual rules for path, domain and expiry, so a cookie
/// the library deletes by expiring it in the past really does stop being sent, which is
/// exactly what sign-out does, and what these tests need to observe.
/// </para>
/// </remarks>
internal sealed class CookieJarHandler : DelegatingHandler
{
    private readonly CookieContainer _cookies;

    public CookieJarHandler(HttpMessageHandler inner, CookieContainer cookies)
        : base(inner)
    {
        _cookies = cookies;
    }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        Uri uri = request.RequestUri ?? throw new InvalidOperationException("A request URI is required.");

        string header = _cookies.GetCookieHeader(uri);
        if (!string.IsNullOrEmpty(header))
        {
            request.Headers.Remove("Cookie");
            request.Headers.Add("Cookie", header);
        }

        HttpResponseMessage response = await base.SendAsync(request, cancellationToken);

        if (response.Headers.TryGetValues("Set-Cookie", out IEnumerable<string>? setCookies))
        {
            foreach (string setCookie in setCookies)
            {
                // SetCookies parses the whole header, including Max-Age=0 / an expiry in the
                // past, which is how the cookie gets removed on sign-out.
                _cookies.SetCookies(uri, setCookie);
            }
        }

        return response;
    }
}
