using Microsoft.AspNetCore.Http;

namespace Authentication;

/// <summary>
/// Configuration for the reusable auth stack. Every value defaults to the secure
/// choice, so a host that configures nothing still gets a hardened setup.
/// </summary>
/// <remarks>
/// Some invariants are deliberately absent here because they are not negotiable:
/// the session cookie is always <c>HttpOnly</c> and always <c>Secure</c>, and the
/// framework password hasher is always used. There is no option to turn those off.
/// </remarks>
public sealed class ReusableAuthOptions
{
    /// <summary>
    /// Name of the session cookie. Defaults to <c>__Host-auth</c>.
    /// </summary>
    /// <remarks>
    /// The <c>__Host-</c> prefix is a browser-enforced guarantee that the cookie is
    /// Secure, path-scoped to <c>/</c>, and carries no <c>Domain</c> — which stops a
    /// compromised sibling subdomain from overwriting the session cookie. Setting
    /// <see cref="CookieDomain"/> is incompatible with the prefix and is rejected
    /// at startup; drop the prefix deliberately if you need a domain-wide cookie.
    /// <para>
    /// Browsers enforce the <c>__Host-</c> prefix inconsistently over plain
    /// <c>http://localhost</c>. For local development either serve HTTPS
    /// (<c>dotnet dev-certs https --trust</c>) or override this to an unprefixed name.
    /// </para>
    /// <para>
    /// The two-factor cookie names derive from this value, so overriding it for local
    /// development carries them with it.
    /// </para>
    /// </remarks>
    public string CookieName { get; set; } = "__Host-auth";

    /// <summary>
    /// Domain to scope the session cookie to. Null (the default) means the cookie is
    /// host-only, which is the stricter choice. Incompatible with a <c>__Host-</c>
    /// prefixed <see cref="CookieName"/>.
    /// </summary>
    public string? CookieDomain { get; set; }

    /// <summary>
    /// <c>SameSite</c> mode for the session and CSRF cookies. Defaults to
    /// <see cref="SameSiteMode.Lax"/>, which blocks the cross-site subresource
    /// requests that drive CSRF while still surviving normal top-level navigation.
    /// </summary>
    /// <remarks>
    /// <see cref="SameSiteMode.None"/> is a real weakening — it lets any site send the
    /// cookie — and is only defensible for a genuinely cross-origin SPA that relies on
    /// the CSRF double-submit check. <see cref="SameSiteMode.Unspecified"/> is rejected
    /// at startup rather than silently deferring to browser-specific behaviour.
    /// </remarks>
    public SameSiteMode CookieSameSite { get; set; } = SameSiteMode.Lax;

    /// <summary>
    /// How long a session stays valid. Defaults to 8 hours — roughly a working day,
    /// short enough that a stolen cookie has a bounded lifetime.
    /// </summary>
    public TimeSpan SessionLifetime { get; set; } = TimeSpan.FromHours(8);

    /// <summary>
    /// Whether an active session has its expiry extended on use. Defaults to
    /// <see langword="true"/>, so an in-use session is not cut off mid-work.
    /// </summary>
    public bool SlidingExpiration { get; set; } = true;

    /// <summary>
    /// How often an active session is re-checked against the user's security stamp.
    /// Defaults to 1 minute.
    /// </summary>
    /// <remarks>
    /// This is the window in which an already-issued cookie keeps working after the
    /// user's stamp changes — after a password reset, or after a privilege change that
    /// bumps the stamp. ASP.NET Core Identity defaults this to 30 minutes, which is a
    /// long time for a revoked session to stay live, so this library tightens it.
    /// <para>
    /// <see cref="TimeSpan.Zero"/> re-checks on every authenticated request, closing the
    /// window entirely at the cost of a store round-trip per request. Raising it trades
    /// revocation latency for fewer store hits.
    /// </para>
    /// </remarks>
    public TimeSpan SecurityStampValidationInterval { get; set; } = TimeSpan.FromMinutes(1);

    /// <summary>
    /// Name of the CSRF cookie. Defaults to <c>__Host-csrf</c>; the same
    /// <c>__Host-</c> reasoning as <see cref="CookieName"/> applies.
    /// </summary>
    public string CsrfCookieName { get; set; } = "__Host-csrf";

    /// <summary>
    /// Request header carrying the CSRF token for the double-submit check. Defaults
    /// to <c>X-CSRF-TOKEN</c>.
    /// </summary>
    public string CsrfHeaderName { get; set; } = "X-CSRF-TOKEN";

    /// <summary>
    /// Minimum password length. Defaults to 12; values below
    /// <see cref="MinimumAllowedPasswordLength"/> are rejected at startup.
    /// </summary>
    public int PasswordMinimumLength { get; set; } = 12;

    /// <summary>
    /// Whether a password must contain a digit. Defaults to <see langword="true"/>.
    /// </summary>
    public bool PasswordRequireDigit { get; set; } = true;

    /// <summary>
    /// Whether a password must contain a lowercase letter. Defaults to
    /// <see langword="true"/>.
    /// </summary>
    public bool PasswordRequireLowercase { get; set; } = true;

    /// <summary>
    /// Whether a password must contain an uppercase letter. Defaults to
    /// <see langword="true"/>.
    /// </summary>
    public bool PasswordRequireUppercase { get; set; } = true;

    /// <summary>
    /// Whether a password must contain a non-alphanumeric character. Defaults to
    /// <see langword="true"/>.
    /// </summary>
    public bool PasswordRequireNonAlphanumeric { get; set; } = true;

    /// <summary>
    /// Number of failed sign-in attempts before an account is locked out. Defaults
    /// to 5.
    /// </summary>
    public int LockoutMaxFailedAttempts { get; set; } = 5;

    /// <summary>
    /// How long an account stays locked out. Defaults to 15 minutes.
    /// </summary>
    public TimeSpan LockoutDuration { get; set; } = TimeSpan.FromMinutes(15);

    /// <summary>
    /// Whether lockout applies to newly created users. Defaults to
    /// <see langword="true"/>; turning it off leaves new accounts open to unlimited
    /// password guessing.
    /// </summary>
    public bool LockoutEnabledForNewUsers { get; set; } = true;

    /// <summary>
    /// Whether an email address must be confirmed before the user can sign in.
    /// Defaults to <see langword="true"/>.
    /// </summary>
    public bool RequireConfirmedEmail { get; set; } = true;

    /// <summary>
    /// Whether an email address may be used by at most one account. Defaults to
    /// <see langword="true"/>.
    /// </summary>
    public bool RequireUniqueEmail { get; set; } = true;

    /// <summary>
    /// The lowest <see cref="PasswordMinimumLength"/> the library accepts: 8.
    /// </summary>
    public const int MinimumAllowedPasswordLength = 8;

    /// <summary>
    /// The cookie name prefix that carries browser-enforced Secure, host-only and
    /// path-scoped guarantees.
    /// </summary>
    internal const string HostCookiePrefix = "__Host-";

    /// <summary>
    /// Suffix for the short-lived cookie that carries the user id between the password
    /// step and the two-factor step. Derived from <see cref="CookieName"/> so a host
    /// that renames the session cookie renames this with it.
    /// </summary>
    internal const string TwoFactorUserIdCookieSuffix = "-2fa";

    /// <summary>
    /// Suffix for the "remember this device" two-factor cookie. Derived from
    /// <see cref="CookieName"/> for the same reason as
    /// <see cref="TwoFactorUserIdCookieSuffix"/>.
    /// </summary>
    internal const string TwoFactorRememberMeCookieSuffix = "-2fa-remember";
}
