using Authentication;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Registers the reusable auth stack: ASP.NET Core Identity, a hardened session
/// cookie, and antiforgery/CSRF.
/// </summary>
public static class ReusableAuthServiceCollectionExtensions
{
    /// <summary>
    /// Lifetime of the intermediate two-factor user-id cookie, matching Identity's own.
    /// </summary>
    private static readonly TimeSpan TwoFactorUserIdLifetime = TimeSpan.FromMinutes(5);


    /// <summary>
    /// Adds the reusable auth stack over the built-in <see cref="ReusableAuthUser"/>.
    /// </summary>
    /// <param name="services">The service collection to add to.</param>
    /// <param name="configure">
    /// Optional overrides. Every option already defaults to the secure choice, so
    /// passing nothing yields a hardened setup.
    /// </param>
    /// <returns>The same <paramref name="services"/>, for chaining.</returns>
    /// <remarks>
    /// The host must still register an Identity store (for example the
    /// <c>Authentication.EntityFrameworkCore</c> package, or its own
    /// <see cref="IUserStore{TUser}"/>); this library is storage-agnostic and
    /// deliberately does not pick one.
    /// </remarks>
    /// <exception cref="ArgumentNullException"><paramref name="services"/> is null.</exception>
    public static IServiceCollection AddReusableAuth(
        this IServiceCollection services,
        Action<ReusableAuthOptions>? configure = null)
        => services.AddReusableAuth<ReusableAuthUser>(configure);

    /// <summary>
    /// Adds the reusable auth stack over a host-supplied user type.
    /// </summary>
    /// <typeparam name="TUser">
    /// The user type, deriving from <see cref="IdentityUser"/>.
    /// </typeparam>
    /// <param name="services">The service collection to add to.</param>
    /// <param name="configure">
    /// Optional overrides. Every option already defaults to the secure choice, so
    /// passing nothing yields a hardened setup.
    /// </param>
    /// <returns>The same <paramref name="services"/>, for chaining.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="services"/> is null.</exception>
    public static IServiceCollection AddReusableAuth<TUser>(
        this IServiceCollection services,
        Action<ReusableAuthOptions>? configure = null)
        where TUser : IdentityUser<string>
    {
        ArgumentNullException.ThrowIfNull(services);

        RegisterOptions(services, configure);
        RegisterCookieAuthentication(services);
        RegisterIdentity<TUser>(services);
        RegisterAntiforgery(services);

        return services;
    }

    private static void RegisterOptions(IServiceCollection services, Action<ReusableAuthOptions>? configure)
    {
        OptionsBuilder<ReusableAuthOptions> builder = services.AddOptions<ReusableAuthOptions>();

        if (configure is not null)
        {
            builder.Configure(configure);
        }

        // A contradictory or weakened config fails the host at boot, not at runtime.
        builder.ValidateOnStart();
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IValidateOptions<ReusableAuthOptions>, ReusableAuthOptionsValidator>());
    }

    private static void RegisterCookieAuthentication(IServiceCollection services)
    {
        // IdentityConstants.ApplicationScheme, not a name of our own: SignInManager
        // signs in and out against that scheme, so renaming it would silently
        // decouple sign-in from the cookie we hardened. The two-factor schemes are
        // registered because SignInManager's 2FA path signs into them unguarded and
        // would throw at runtime if they were missing.
        services.AddAuthentication(IdentityConstants.ApplicationScheme)
            .AddCookie(IdentityConstants.ApplicationScheme)
            .AddCookie(IdentityConstants.TwoFactorUserIdScheme)
            .AddCookie(IdentityConstants.TwoFactorRememberMeScheme);

        services.AddOptions<CookieAuthenticationOptions>(IdentityConstants.ApplicationScheme)
            .Configure<IOptions<ReusableAuthOptions>>(
                (cookie, auth) => ConfigureApplicationCookie(cookie, auth.Value));

        services.AddOptions<CookieAuthenticationOptions>(IdentityConstants.TwoFactorUserIdScheme)
            .Configure<IOptions<ReusableAuthOptions>>(
                (cookie, auth) => ConfigureTwoFactorUserIdCookie(cookie, auth.Value));

        services.AddOptions<CookieAuthenticationOptions>(IdentityConstants.TwoFactorRememberMeScheme)
            .Configure<IOptions<ReusableAuthOptions>>(
                (cookie, auth) => ConfigureTwoFactorRememberMeCookie(cookie, auth.Value));

        services.AddAuthorization();
    }

    private static void RegisterIdentity<TUser>(IServiceCollection services)
        where TUser : IdentityUser<string>
    {
        services.AddHttpContextAccessor();

        services.AddOptions<IdentityOptions>()
            .Configure<IOptions<ReusableAuthOptions>>(
                (identity, auth) => ApplyIdentityPolicy(identity, auth.Value));

        // Identity defaults this to 30 minutes, i.e. a revoked session can keep
        // working for half an hour. See the option's docs for the trade-off.
        services.AddOptions<SecurityStampValidatorOptions>()
            .Configure<IOptions<ReusableAuthOptions>>(
                (stamp, auth) => stamp.ValidationInterval = auth.Value.SecurityStampValidationInterval);

        // AddIdentityCore, not AddIdentity: the latter registers its own cookie
        // schemes and would fight the hardened one configured above. AddSignInManager
        // already brings ISecurityStampValidator and ITwoFactorSecurityStampValidator
        // with it, which is what the cookies' OnValidatePrincipal resolves.
        services.AddIdentityCore<TUser>()
            .AddDefaultTokenProviders()
            .AddSignInManager();

        // Stamp validation silently no-ops on a store without IUserSecurityStampStore,
        // so refuse to boot rather than pretend sessions can be revoked.
        services.AddHostedService<SecurityStampStoreGuard<TUser>>();
    }

    private static void RegisterAntiforgery(IServiceCollection services)
    {
        services.AddAntiforgery();

        services.AddOptions<AntiforgeryOptions>()
            .Configure<IOptions<ReusableAuthOptions>>(
                (antiforgery, auth) => ApplyAntiforgeryHardening(antiforgery, auth.Value));
    }

    private static void ConfigureApplicationCookie(CookieAuthenticationOptions cookie, ReusableAuthOptions auth)
    {
        ApplyCookieHardening(cookie.Cookie, auth);

        cookie.Cookie.Name = auth.CookieName;
        cookie.ExpireTimeSpan = auth.SessionLifetime;
        cookie.SlidingExpiration = auth.SlidingExpiration;

        // Without this the security stamp is never checked and session invalidation
        // does not happen at all: a password reset would leave every existing cookie
        // working. AddIdentity wires this up; we deliberately do not use AddIdentity,
        // so we have to wire it ourselves.
        cookie.Events.OnValidatePrincipal = SecurityStampValidator.ValidatePrincipalAsync;

        // A library has no login page to redirect to, and inventing a path would be
        // an app-specific assumption. Answer with the status code and let the host
        // decide what to render.
        cookie.Events.OnRedirectToLogin = RespondWith(StatusCodes.Status401Unauthorized);
        cookie.Events.OnRedirectToAccessDenied = RespondWith(StatusCodes.Status403Forbidden);
    }

    private static void ConfigureTwoFactorUserIdCookie(CookieAuthenticationOptions cookie, ReusableAuthOptions auth)
    {
        ApplyCookieHardening(cookie.Cookie, auth);

        cookie.Cookie.Name = auth.CookieName + ReusableAuthOptions.TwoFactorUserIdCookieSuffix;

        // Short-lived by design: it only carries the user id across the gap between
        // the password step and the two-factor step. Matches Identity's own 5 minutes.
        cookie.ExpireTimeSpan = TwoFactorUserIdLifetime;
        cookie.SlidingExpiration = false;

        // No stamp validation here, matching Identity: this cookie is a single-purpose
        // intermediate that expires in minutes, and the user is not signed in yet.
        cookie.Events.OnRedirectToReturnUrl = _ => Task.CompletedTask;
    }

    private static void ConfigureTwoFactorRememberMeCookie(CookieAuthenticationOptions cookie, ReusableAuthOptions auth)
    {
        ApplyCookieHardening(cookie.Cookie, auth);

        cookie.Cookie.Name = auth.CookieName + ReusableAuthOptions.TwoFactorRememberMeCookieSuffix;

        // Validated against the two-factor stamp specifically, so revoking a user's
        // 2FA also drops their remembered devices.
        cookie.Events.OnValidatePrincipal =
            SecurityStampValidator.ValidateAsync<ITwoFactorSecurityStampValidator>;
    }

    private static void ApplyAntiforgeryHardening(AntiforgeryOptions antiforgery, ReusableAuthOptions auth)
    {
        // The cookie holds the CSRF cookie-token half of the double submit; the
        // matching request token travels in CsrfHeaderName. The cookie stays
        // HttpOnly because scripts are meant to echo back the request token, never
        // to read this. Note antiforgery's own SecurePolicy default is None, so the
        // hardening below is doing real work, not restating a default.
        ApplyCookieHardening(antiforgery.Cookie, auth);

        antiforgery.Cookie.Name = auth.CsrfCookieName;
        antiforgery.HeaderName = auth.CsrfHeaderName;
    }

    /// <summary>
    /// The settings that are the same for every cookie this library emits.
    /// </summary>
    private static void ApplyCookieHardening(CookieBuilder cookie, ReusableAuthOptions auth)
    {
        // HttpOnly and Secure are fixed, not sourced from options: they are the
        // invariant, and rules/security.md treats weakening them as a breaking
        // security change rather than a configuration choice. Path is pinned to "/"
        // because the __Host- prefix requires it and a non-root PathBase would
        // otherwise scope the cookie and silently void the prefix.
        cookie.HttpOnly = true;
        cookie.SecurePolicy = CookieSecurePolicy.Always;
        cookie.IsEssential = true;
        cookie.Path = "/";

        cookie.Domain = auth.CookieDomain;
        cookie.SameSite = auth.CookieSameSite;
    }

    private static void ApplyIdentityPolicy(IdentityOptions identity, ReusableAuthOptions auth)
    {
        identity.Password.RequiredLength = auth.PasswordMinimumLength;
        identity.Password.RequireDigit = auth.PasswordRequireDigit;
        identity.Password.RequireLowercase = auth.PasswordRequireLowercase;
        identity.Password.RequireUppercase = auth.PasswordRequireUppercase;
        identity.Password.RequireNonAlphanumeric = auth.PasswordRequireNonAlphanumeric;

        identity.Lockout.MaxFailedAccessAttempts = auth.LockoutMaxFailedAttempts;
        identity.Lockout.DefaultLockoutTimeSpan = auth.LockoutDuration;
        identity.Lockout.AllowedForNewUsers = auth.LockoutEnabledForNewUsers;

        identity.SignIn.RequireConfirmedEmail = auth.RequireConfirmedEmail;
        identity.User.RequireUniqueEmail = auth.RequireUniqueEmail;
    }

    private static Func<RedirectContext<CookieAuthenticationOptions>, Task> RespondWith(int statusCode)
        => context =>
        {
            context.Response.StatusCode = statusCode;
            return Task.CompletedTask;
        };
}
