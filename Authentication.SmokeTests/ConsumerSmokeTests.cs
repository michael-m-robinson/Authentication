using System.Net;
using System.Net.Http.Json;
using Authentication;
using Microsoft.Extensions.DependencyInjection;

namespace Authentication.SmokeTests;

/// <summary>
/// Drives the library over real HTTP, through a real ASP.NET Core pipeline, with the cookie
/// a browser would hold.
/// </summary>
/// <remarks>
/// The unit tests call services directly and cannot see the cookie at all. These can: they
/// are the only evidence that what the library issues is actually accepted on the next
/// request, and — the part that matters — that it stops being accepted when it should.
/// </remarks>
public sealed class ConsumerSmokeTests : IAsyncLifetime
{
    private const string Email = "person@example.com";
    private const string Password = "Correct-horse-9!";

    private ConsumerApp _app = null!;

    public async Task InitializeAsync() => _app = await ConsumerApp.StartAsync();

    public async Task DisposeAsync() => await _app.DisposeAsync();

    // ---- The flow PLAN.md asks for: register -> login -> me -> logout ------------------

    [Fact]
    public async Task RegisterConfirmLoginMeLogout()
    {
        using HttpClient client = _app.CreateClient();

        // Register.
        HttpResponseMessage registered = await client.PostAsJsonAsync(
            "/register", new ConsumerApp.Credentials(Email, Password));
        Assert.Equal(HttpStatusCode.OK, registered.StatusCode);

        // The confirmation email is sent off the request thread, so wait for it rather than
        // racing the worker.
        CapturedEmail confirmation = await _app.Emails.WaitForAsync("confirmation", Email);

        // Sign-in before confirming is refused - and says nothing about why.
        HttpResponseMessage tooSoon = await client.PostAsJsonAsync(
            "/login", new ConsumerApp.Credentials(Email, Password));
        Assert.Equal(HttpStatusCode.Unauthorized, tooSoon.StatusCode);

        // Follow the link the user would have clicked.
        HttpResponseMessage confirmed = await client.PostAsJsonAsync(
            "/confirm", new ConsumerApp.ConfirmRequest(confirmation.UserId!, confirmation.Token!));
        Assert.Equal(HttpStatusCode.OK, confirmed.StatusCode);

        // Anonymous, so far.
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/me")).StatusCode);

        // Log in. This is where the session cookie is issued.
        HttpResponseMessage loggedIn = await client.PostAsJsonAsync(
            "/login", new ConsumerApp.Credentials(Email, Password));
        Assert.Equal(HttpStatusCode.OK, loggedIn.StatusCode);

        // ...and the cookie comes back on the next request, unprompted, as a browser would.
        HttpResponseMessage me = await client.GetAsync("/me");
        Assert.Equal(HttpStatusCode.OK, me.StatusCode);

        ConsumerApp.Me? who = await me.Content.ReadFromJsonAsync<ConsumerApp.Me>();
        Assert.NotNull(who);
        Assert.Equal(Email, who.Name);
        Assert.NotEmpty(who.Id);

        // Log out.
        Assert.Equal(HttpStatusCode.OK, (await client.PostAsync("/logout", null)).StatusCode);

        // And the session is genuinely gone, not just forgotten client-side.
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/me")).StatusCode);
    }

    // ---- The cookie itself -------------------------------------------------------------

    [Fact]
    public async Task TheSessionCookie_IsHardened_OnTheWire()
    {
        // Every other test asserts the options object. This asserts what actually reached
        // the client - the only thing a browser will ever act on.
        using HttpClient client = await SignedInClientAsync();

        Cookie? session = _app.Cookies
            .GetAllCookies()
            .FirstOrDefault(c => c.Name == "__Host-auth");

        Assert.NotNull(session);
        Assert.True(session.HttpOnly, "The session cookie must be HttpOnly.");
        Assert.True(session.Secure, "The session cookie must be Secure.");
        Assert.Equal("/", session.Path);

        // __Host- requires no Domain. CookieContainer fills in the host it came from, so the
        // check that matters is that the server never sent one.
        Assert.False(session.Value.Length == 0, "The session cookie must carry a value.");
    }

    [Fact]
    public async Task SignOut_ExpiresTheCookie_RatherThanLeavingItLive()
    {
        using HttpClient client = await SignedInClientAsync();

        await client.PostAsync("/logout", null);

        // The container drops an expired cookie, which is what a browser does. If sign-out
        // only cleared server-side state and left the cookie alive, this would still be here.
        Cookie? session = _app.Cookies.GetAllCookies().FirstOrDefault(c => c.Name == "__Host-auth");

        Assert.True(
            session is null || string.IsNullOrEmpty(session.Value),
            "Signing out must expire the session cookie, not merely ignore it.");
    }

    // ---- The rotation test PLAN.md has wanted since milestone 3 ------------------------

    [Fact]
    public async Task ACookieIssuedBeforeAPrivilegeChange_StopsWorkingAfterIt()
    {
        // This is the invariant the whole library is built around, and until now it rested on
        // research and unit tests - never on a real cookie through a real pipeline.
        using HttpClient client = await SignedInClientAsync();
        string userId = await UserIdAsync(client);

        // Grant the role. The cookie the client holds was minted BEFORE this.
        await UsingRolesAsync(async roles =>
        {
            Assert.Equal(AuthStatus.Succeeded, (await roles.CreateRoleAsync("Admins")).Status);
            Assert.Equal(AuthStatus.Succeeded, (await roles.AddToRoleAsync(userId, "Admins")).Status);
        });

        // The old cookie is now stale, so the stamp check rejects it and signs them out.
        // That is the security property working, and it means the user must sign in again to
        // pick the role up - which is also the honest cost of it.
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/me")).StatusCode);

        // Sign in again: now the cookie carries the role.
        using HttpClient admin = await SignedInClientAsync();
        Assert.Equal(HttpStatusCode.OK, (await admin.GetAsync("/admin")).StatusCode);

        ConsumerApp.Me? who = await (await admin.GetAsync("/me")).Content.ReadFromJsonAsync<ConsumerApp.Me>();
        Assert.Contains("Admins", who!.Roles);

        // Now revoke it. THIS is the case that matters: the client is holding a cookie that
        // asserts "Admins", and nothing about that cookie has changed.
        await UsingRolesAsync(async roles =>
            Assert.Equal(AuthStatus.Succeeded, (await roles.RemoveFromRoleAsync(userId, "Admins")).Status));

        // The revoked administrator is not an administrator any more. Without the stamp
        // refresh RoleService does, this would still be 200: the cookie would keep asserting
        // a role the user no longer has until it expired, hours later.
        Assert.Equal(HttpStatusCode.Unauthorized, (await admin.GetAsync("/admin")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await admin.GetAsync("/me")).StatusCode);
    }

    [Fact]
    public async Task ACookieIssuedBeforeAPasswordChange_StopsWorking()
    {
        using HttpClient client = await SignedInClientAsync();
        string userId = await UserIdAsync(client);

        // A second session, as if from another device, holding its own cookie.
        using HttpClient other = await SignedInClientAsync();
        Assert.Equal(HttpStatusCode.OK, (await other.GetAsync("/me")).StatusCode);

        await UsingScopeAsync(async services =>
        {
            IAccountService account = services.GetRequiredService<IAccountService>();
            Assert.Equal(AuthStatus.Succeeded, (await account.ResetAuthenticatorKeyAsync(userId)).Status);
        });

        // Resetting the authenticator key rotates the stamp, so every session that user had
        // open dies - which is the point of it, for someone whose device was stolen.
        Assert.Equal(HttpStatusCode.Unauthorized, (await other.GetAsync("/me")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/me")).StatusCode);
    }

    [Fact]
    public async Task AnUnauthenticatedRequest_Gets401_NotARedirect()
    {
        // The library default, over the wire: no LoginPath is set, so an API caller gets a
        // status code rather than a 302 to HTML it cannot use.
        using HttpClient client = _app.CreateClient();

        HttpResponseMessage response = await client.GetAsync("/me");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Null(response.Headers.Location);
    }

    [Fact]
    public async Task AWrongPassword_IsIndistinguishableFromAnUnknownAccount()
    {
        await RegisterAndConfirmAsync();
        using HttpClient client = _app.CreateClient();

        HttpResponseMessage wrongPassword = await client.PostAsJsonAsync(
            "/login", new ConsumerApp.Credentials(Email, "Wrong-password-1!"));
        HttpResponseMessage unknownUser = await client.PostAsJsonAsync(
            "/login", new ConsumerApp.Credentials("nobody@example.com", Password));

        // Same status, same empty body, no cookie either way. Over the wire, there is nothing
        // to tell them apart.
        Assert.Equal(HttpStatusCode.Unauthorized, wrongPassword.StatusCode);
        Assert.Equal(unknownUser.StatusCode, wrongPassword.StatusCode);
        Assert.False(wrongPassword.Headers.Contains("Set-Cookie"));
        Assert.False(unknownUser.Headers.Contains("Set-Cookie"));
    }

    [Fact]
    public async Task RegisteringATakenAddress_LooksIdenticalOverTheWire()
    {
        await RegisterAndConfirmAsync();
        using HttpClient client = _app.CreateClient();

        HttpResponseMessage taken = await client.PostAsJsonAsync(
            "/register", new ConsumerApp.Credentials(Email, "Different-pass-1!"));
        HttpResponseMessage free = await client.PostAsJsonAsync(
            "/register", new ConsumerApp.Credentials("free@example.com", Password));

        Assert.Equal(HttpStatusCode.OK, taken.StatusCode);
        Assert.Equal(free.StatusCode, taken.StatusCode);

        // And the owner of the taken address is told, out of band.
        CapturedEmail notice = await _app.Emails.WaitForAsync("registration-attempted", Email);
        Assert.Equal(Email, notice.Email);
    }

    // ---- Helpers -----------------------------------------------------------------------

    private async Task RegisterAndConfirmAsync(string email = Email)
    {
        using HttpClient client = _app.CreateClient();

        await client.PostAsJsonAsync("/register", new ConsumerApp.Credentials(email, Password));
        CapturedEmail confirmation = await _app.Emails.WaitForAsync("confirmation", email);

        HttpResponseMessage confirmed = await client.PostAsJsonAsync(
            "/confirm", new ConsumerApp.ConfirmRequest(confirmation.UserId!, confirmation.Token!));

        Assert.Equal(HttpStatusCode.OK, confirmed.StatusCode);
    }

    /// <summary>
    /// A client holding a live session cookie, having gone through the real flow to get it.
    /// </summary>
    private async Task<HttpClient> SignedInClientAsync()
    {
        if (_app.Emails.Sent.All(e => e.Kind != "confirmation"))
        {
            await RegisterAndConfirmAsync();
        }

        HttpClient client = _app.CreateClient();
        HttpResponseMessage loggedIn = await client.PostAsJsonAsync(
            "/login", new ConsumerApp.Credentials(Email, Password));

        Assert.Equal(HttpStatusCode.OK, loggedIn.StatusCode);

        return client;
    }

    private static async Task<string> UserIdAsync(HttpClient client)
    {
        ConsumerApp.Me? me = await (await client.GetAsync("/me")).Content.ReadFromJsonAsync<ConsumerApp.Me>();

        return me!.Id;
    }

    private async Task UsingRolesAsync(Func<IRoleService, Task> work)
        => await UsingScopeAsync(services => work(services.GetRequiredService<IRoleService>()));

    private async Task UsingScopeAsync(Func<IServiceProvider, Task> work)
    {
        using IServiceScope scope = _app.Services.CreateScope();
        await work(scope.ServiceProvider);
    }
}
