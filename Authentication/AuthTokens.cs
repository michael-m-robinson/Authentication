using System.Text;
using Microsoft.AspNetCore.WebUtilities;

namespace Authentication;

/// <summary>
/// Moves Identity tokens in and out of URL-safe form. The library owns both halves so
/// hosts never have to think about it.
/// </summary>
/// <remarks>
/// Raw Identity tokens contain characters that do not survive a query string. Microsoft's
/// own scaffolding leaves each app to remember the encode/decode pair, which is a
/// dependable source of "invalid token" bugs that look like expiry.
/// </remarks>
internal static class AuthTokens
{
    /// <summary>
    /// Makes a token safe to place in a URL.
    /// </summary>
    internal static string Encode(string token)
        => WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));

    /// <summary>
    /// Reverses <see cref="Encode"/>, returning null for anything malformed.
    /// </summary>
    /// <remarks>
    /// A mangled token is a failure, not an exception: it arrives from a URL a user may
    /// have truncated, and it must be indistinguishable from an expired or forged one.
    /// </remarks>
    internal static string? TryDecode(string token)
    {
        try
        {
            return Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(token));
        }
        catch (FormatException)
        {
            return null;
        }
    }
}
