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
    /// Secure, path-scoped to <c>/</c>, and carries no <c>Domain</c>, which stops a
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
    /// <see cref="SameSiteMode.None"/> is a real weakening (it lets any site send the
    /// cookie) and is only defensible for a genuinely cross-origin SPA that relies on
    /// the CSRF double-submit check. <see cref="SameSiteMode.Unspecified"/> is rejected
    /// at startup rather than silently deferring to browser-specific behaviour.
    /// </remarks>
    public SameSiteMode CookieSameSite { get; set; } = SameSiteMode.Lax;

    /// <summary>
    /// How long a session stays valid. Defaults to 8 hours, roughly a working day:
    /// short enough that a stolen cookie has a bounded lifetime.
    /// </summary>
    public TimeSpan SessionLifetime { get; set; } = TimeSpan.FromHours(8);

    /// <summary>
    /// Whether an active session has its expiry extended on use. Defaults to
    /// <see langword="true"/>, so an in-use session is not cut off mid-work.
    /// </summary>
    public bool SlidingExpiration { get; set; } = true;

    /// <summary>
    /// Where to send an unauthenticated visitor who asks for something protected.
    /// Null (the default) answers <c>401 Unauthorized</c> instead of redirecting.
    /// </summary>
    /// <remarks>
    /// Set this in an MVC, Razor Pages or Blazor app, where a challenge is expected to
    /// land on a login page, and a bare 401 looks like a broken site. Leave it null in an
    /// API, where a redirect to HTML is worse than useless to a caller expecting JSON.
    /// <para>
    /// The library has no page of its own to offer, which is why the default is a status
    /// code rather than a guess at a path that probably would not exist.
    /// </para>
    /// </remarks>
    public string? LoginPath { get; set; }

    /// <summary>
    /// Where to send a signed-in visitor who lacks permission. Null (the default) answers
    /// <c>403 Forbidden</c> instead of redirecting.
    /// </summary>
    /// <remarks>
    /// Same reasoning as <see cref="LoginPath"/>. Note this is for a visitor who <em>is</em>
    /// authenticated and still not allowed, so sending them to a login page is the wrong
    /// answer. Give them a page that says so.
    /// </remarks>
    public string? AccessDeniedPath { get; set; }

    /// <summary>
    /// How often an active session is re-checked against the user's security stamp.
    /// Defaults to 1 minute.
    /// </summary>
    /// <remarks>
    /// This is the window in which an already-issued cookie keeps working after the
    /// user's stamp changes: after a password reset, or after a privilege change that
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
    /// How many auth emails may be waiting to be sent before callers are made to wait
    /// for room. Defaults to 1000.
    /// </summary>
    /// <remarks>
    /// Auth emails are sent off the request thread, so that
    /// <see cref="IAuthService.RequestPasswordResetAsync"/> takes the same time for a
    /// registered address as for an unknown one. Awaiting an SMTP call only for
    /// addresses that exist would answer "does this account exist" to anyone holding a
    /// stopwatch.
    /// <para>
    /// The queue is bounded because the endpoints behind it are unauthenticated: an
    /// unbounded one would let anyone grow it until the process ran out of memory. When
    /// it is full, callers wait for capacity (backpressure) rather than having their
    /// email silently dropped. That wait does not depend on the address, so it discloses
    /// nothing, but it does mean a flood can slow these endpoints down. Rate limiting
    /// them remains the host's job.
    /// </para>
    /// </remarks>
    public int BackgroundEmailQueueCapacity { get; set; } = 1000;

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
    /// How long a password-reset link stays usable. Defaults to 1 hour.
    /// </summary>
    /// <remarks>
    /// Shorter than <see cref="EmailConfirmationTokenLifetime"/> on purpose. A reset link
    /// is a bearer credential for the account: anyone who reads it owns the account, and
    /// it sits in an inbox, which is exactly where it is most likely to be read by
    /// someone else. An hour is ample for a real person to click a link they just asked
    /// for.
    /// <para>
    /// Identity gives every data-protection token one shared 1-day lifespan; honouring
    /// this separately is why the library registers a reset token provider of its own.
    /// </para>
    /// </remarks>
    public TimeSpan PasswordResetTokenLifetime { get; set; } = TimeSpan.FromHours(1);

    /// <summary>
    /// How long an email-confirmation link stays usable. Defaults to 1 day, matching
    /// Identity.
    /// </summary>
    /// <remarks>
    /// Longer than <see cref="PasswordResetTokenLifetime"/> because it grants far less
    /// (it proves an address, it does not hand over an account) and because confirmation
    /// mail is routinely read the next morning.
    /// <para>
    /// This sets the lifespan of Identity's default data-protection token provider, so it
    /// also governs change-email tokens.
    /// </para>
    /// </remarks>
    public TimeSpan EmailConfirmationTokenLifetime { get; set; } = TimeSpan.FromDays(1);

    /// <summary>
    /// The name shown against this account in a user's authenticator app. Defaults to
    /// <c>ReusableAuth</c>.
    /// </summary>
    /// <remarks>
    /// Set this to your application's name. It is what the user reads in Google
    /// Authenticator or 1Password when deciding which of a dozen six-digit codes is yours,
    /// so leaving it at the default is unhelpful to them, and Identity's own default,
    /// "Microsoft.AspNetCore.Identity.UI", is worse than unhelpful.
    /// <para>
    /// Changing it does not invalidate anything: existing authenticator entries keep the
    /// label they were created with, and only new setups pick this up.
    /// </para>
    /// </remarks>
    public string AuthenticatorIssuer { get; set; } = "ReusableAuth";

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
    /// The key the password-reset token provider is registered under in Identity's
    /// provider map.
    /// </summary>
    internal const string PasswordResetTokenProviderName = "ReusableAuthPasswordReset";

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
