using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

namespace Authentication;

/// <summary>
/// Fails the host at startup when <see cref="ReusableAuthOptions"/> is configured
/// into a state that is contradictory or weaker than the library is willing to run.
/// Wired with <c>ValidateOnStart</c>, so a bad config is a boot failure rather than
/// a security hole that only shows up under attack.
/// </summary>
internal sealed class ReusableAuthOptionsValidator : IValidateOptions<ReusableAuthOptions>
{
    public ValidateOptionsResult Validate(string? name, ReusableAuthOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        List<string> failures = [];
        ValidateCookies(options, failures);
        ValidateSession(options, failures);
        ValidatePasswordPolicy(options, failures);
        ValidateLockoutPolicy(options, failures);

        return failures.Count == 0
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(failures);
    }

    private static void ValidateCookies(ReusableAuthOptions options, List<string> failures)
    {
        RequireText(options.CookieName, nameof(options.CookieName), failures);
        RequireText(options.CsrfCookieName, nameof(options.CsrfCookieName), failures);
        RequireText(options.CsrfHeaderName, nameof(options.CsrfHeaderName), failures);

        if (string.Equals(options.CookieName, options.CsrfCookieName, StringComparison.Ordinal))
        {
            failures.Add(
                $"{nameof(options.CookieName)} and {nameof(options.CsrfCookieName)} must differ; " +
                "sharing one name means the CSRF cookie overwrites the session cookie.");
        }

        if (options.CookieSameSite == SameSiteMode.Unspecified)
        {
            failures.Add(
                $"{nameof(options.CookieSameSite)} must not be Unspecified; that leaves the " +
                "attribute off and defers to browser-specific defaults. Choose Lax, Strict, or None.");
        }

        RejectHostPrefixWithDomain(options.CookieName, nameof(options.CookieName), options.CookieDomain, failures);
        RejectHostPrefixWithDomain(options.CsrfCookieName, nameof(options.CsrfCookieName), options.CookieDomain, failures);
    }

    private static void RejectHostPrefixWithDomain(
        string cookieName,
        string propertyName,
        string? domain,
        List<string> failures)
    {
        if (string.IsNullOrWhiteSpace(domain) || cookieName is null)
        {
            return;
        }

        if (cookieName.StartsWith(ReusableAuthOptions.HostCookiePrefix, StringComparison.Ordinal))
        {
            failures.Add(
                $"{propertyName} uses the '{ReusableAuthOptions.HostCookiePrefix}' prefix, which browsers " +
                $"only honour on a cookie with no Domain, but {nameof(ReusableAuthOptions.CookieDomain)} is " +
                "set. Either clear the domain or drop the prefix.");
        }
    }

    private static void ValidateSession(ReusableAuthOptions options, List<string> failures)
    {
        if (options.SessionLifetime <= TimeSpan.Zero)
        {
            failures.Add($"{nameof(options.SessionLifetime)} must be greater than zero.");
        }

        // Zero is meaningful here (revalidate on every request); negative is not.
        if (options.SecurityStampValidationInterval < TimeSpan.Zero)
        {
            failures.Add(
                $"{nameof(options.SecurityStampValidationInterval)} must not be negative. " +
                "Use TimeSpan.Zero to revalidate on every request.");
        }
    }

    private static void ValidatePasswordPolicy(ReusableAuthOptions options, List<string> failures)
    {
        if (options.PasswordMinimumLength < ReusableAuthOptions.MinimumAllowedPasswordLength)
        {
            failures.Add(
                $"{nameof(options.PasswordMinimumLength)} must be at least " +
                $"{ReusableAuthOptions.MinimumAllowedPasswordLength}.");
        }
    }

    private static void ValidateLockoutPolicy(ReusableAuthOptions options, List<string> failures)
    {
        if (options.LockoutMaxFailedAttempts < 1)
        {
            failures.Add($"{nameof(options.LockoutMaxFailedAttempts)} must be at least 1.");
        }

        if (options.LockoutDuration <= TimeSpan.Zero)
        {
            failures.Add($"{nameof(options.LockoutDuration)} must be greater than zero.");
        }
    }

    private static void RequireText(string? value, string propertyName, List<string> failures)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            failures.Add($"{propertyName} must not be empty.");
        }
    }
}
