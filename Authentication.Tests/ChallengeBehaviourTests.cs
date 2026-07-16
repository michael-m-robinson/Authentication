using Authentication;
using Authentication.Tests.Fakes;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Authentication.Tests;

/// <summary>
/// Covers what happens when an unauthenticated or unauthorised visitor asks for something
/// protected: an API wants a status code, MVC and Blazor want a redirect, and the host
/// chooses by setting the paths or leaving them null.
/// </summary>
public class ChallengeBehaviourTests
{
    private static CookieAuthenticationOptions CookieFor(Action<ReusableAuthOptions>? configure = null)
    {
        ServiceCollection services = new();
        services.AddLogging();
        services.AddReusableAuth(configure);
        services.AddSingleton<IUserStore<ReusableAuthUser>, StampAwareUserStore>();
        services.AddSingleton<IRoleStore<IdentityRole>, InMemoryRoleStore>();

        using ServiceProvider provider = services.BuildServiceProvider();
        return provider.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>()
            .Get(IdentityConstants.ApplicationScheme);
    }

    private static RedirectContext<CookieAuthenticationOptions> RedirectContextFor(
        HttpContext context,
        CookieAuthenticationOptions cookie,
        string redirectUri) =>
        new(
            context,
            new AuthenticationScheme(
                IdentityConstants.ApplicationScheme,
                displayName: null,
                typeof(CookieAuthenticationHandler)),
            cookie,
            new AuthenticationProperties(),
            redirectUri);

    private static async Task<HttpContext> ChallengeAsync(CookieAuthenticationOptions cookie)
    {
        DefaultHttpContext context = new();
        await cookie.Events.OnRedirectToLogin(
            RedirectContextFor(context, cookie, cookie.LoginPath + "?ReturnUrl=%2Fprotected"));
        return context;
    }

    private static async Task<HttpContext> DenyAsync(CookieAuthenticationOptions cookie)
    {
        DefaultHttpContext context = new();
        await cookie.Events.OnRedirectToAccessDenied(
            RedirectContextFor(context, cookie, cookie.AccessDeniedPath + "?ReturnUrl=%2Fprotected"));
        return context;
    }

    [Fact]
    public async Task ByDefault_ChallengeAnswers401_AndDoesNotRedirect()
    {
        HttpContext context = await ChallengeAsync(CookieFor());

        Assert.Equal(StatusCodes.Status401Unauthorized, context.Response.StatusCode);
        Assert.False(context.Response.Headers.ContainsKey("Location"));
    }

    [Fact]
    public async Task ByDefault_AccessDeniedAnswers403_AndDoesNotRedirect()
    {
        HttpContext context = await DenyAsync(CookieFor());

        Assert.Equal(StatusCodes.Status403Forbidden, context.Response.StatusCode);
        Assert.False(context.Response.Headers.ContainsKey("Location"));
    }

    [Fact]
    public async Task ByDefault_TheFrameworksAccountLoginDefault_IsNotUsed()
    {
        // PostConfigureCookieAuthenticationOptions fills in LoginPath when it is unset, so
        // LoginPath IS "/Account/Login" here even though nothing asked for it. Overriding
        // the event is what stops an API host silently 302ing to a route that does not
        // exist. This asserts the override wins over the framework's default.
        CookieAuthenticationOptions cookie = CookieFor();

        Assert.Equal("/Account/Login", cookie.LoginPath);

        HttpContext context = await ChallengeAsync(cookie);
        Assert.Equal(StatusCodes.Status401Unauthorized, context.Response.StatusCode);
    }

    [Fact]
    public async Task WithALoginPath_ChallengeRedirects()
    {
        CookieAuthenticationOptions cookie = CookieFor(o => o.LoginPath = "/Account/SignIn");

        Assert.Equal("/Account/SignIn", cookie.LoginPath);

        HttpContext context = await ChallengeAsync(cookie);

        // What MVC, Razor Pages and Blazor expect.
        Assert.Equal(StatusCodes.Status302Found, context.Response.StatusCode);
        Assert.Contains("/Account/SignIn", context.Response.Headers.Location.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task WithAnAccessDeniedPath_DenialRedirects()
    {
        CookieAuthenticationOptions cookie = CookieFor(o => o.AccessDeniedPath = "/Account/Denied");

        HttpContext context = await DenyAsync(cookie);

        Assert.Equal(StatusCodes.Status302Found, context.Response.StatusCode);
        Assert.Contains("/Account/Denied", context.Response.Headers.Location.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task ThePathsAreIndependent()
    {
        // A host may well want a login page but a JSON 403, or the reverse.
        CookieAuthenticationOptions cookie = CookieFor(o => o.LoginPath = "/Account/SignIn");

        HttpContext denied = await DenyAsync(cookie);

        Assert.Equal(StatusCodes.Status403Forbidden, denied.Response.StatusCode);
    }

    [Fact]
    public void SettingTheChallengePaths_DoesNotWeakenTheCookie()
    {
        CookieAuthenticationOptions cookie = CookieFor(o =>
        {
            o.LoginPath = "/Account/SignIn";
            o.AccessDeniedPath = "/Account/Denied";
        });

        Assert.True(cookie.Cookie.HttpOnly);
        Assert.Equal(CookieSecurePolicy.Always, cookie.Cookie.SecurePolicy);
    }

    [Theory]
    [InlineData("Account/Login")]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("https://elsewhere.example.com/login")]
    public void ARelativeOrEmptyPath_IsRejectedAtStartup(string path)
    {
        // A path that does not start with "/" never matches, so the redirect lands nowhere
        // and reads as a routing bug rather than a configuration one.
        ReusableAuthOptions options = new() { LoginPath = path };

        ValidateOptionsResult result = new ReusableAuthOptionsValidator().Validate(Options.DefaultName, options);

        Assert.True(result.Failed);
    }

    [Fact]
    public void NullPaths_AreValid()
    {
        ReusableAuthOptions options = new() { LoginPath = null, AccessDeniedPath = null };

        ValidateOptionsResult result = new ReusableAuthOptionsValidator().Validate(Options.DefaultName, options);

        Assert.True(result.Succeeded);
    }
}
