using System.Net;
using System.Security.Claims;
using Authentication;
using Authentication.EntityFrameworkCore;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Authentication.SmokeTests;

/// <summary>
/// A throwaway consuming app, wired the way the README tells hosts to wire one, running a
/// real ASP.NET Core pipeline in-process.
/// </summary>
/// <remarks>
/// This is the only place the library is used the way a consumer uses it: over HTTP, with
/// the cookie a browser would actually hold and send back. Every other test calls the
/// services directly, which cannot tell you whether the cookie works — whether it is
/// issued, whether it comes back, whether it stops working when it should.
/// </remarks>
internal sealed class ConsumerApp : IAsyncDisposable
{
    private readonly SqliteConnection _connection;
    private readonly WebApplication _app;

    private ConsumerApp(SqliteConnection connection, WebApplication app)
    {
        _connection = connection;
        _app = app;
        Emails = app.Services.GetRequiredService<IAuthEmailSender>() as CapturedEmails
            ?? throw new InvalidOperationException("Expected the capturing email sender.");
    }

    /// <summary>
    /// What the app tried to email, so a test can follow a confirmation link.
    /// </summary>
    public CapturedEmails Emails { get; }

    public IServiceProvider Services => _app.Services;

    public static async Task<ConsumerApp> StartAsync()
    {
        SqliteConnection connection = new("DataSource=:memory:");
        connection.Open();

        WebApplicationBuilder builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.UseTestServer();
        builder.Logging.SetMinimumLevel(LogLevel.Warning);

        builder.Services.AddDbContext<AppDbContext>(o => o.UseSqlite(connection));

        // The README's three registrations, unchanged.
        builder.Services.AddReusableAuth(options =>
        {
            // Every authenticated request re-checks the security stamp. A real app leaves
            // this at 1 minute; a test that waited 60 seconds to prove revocation would
            // never be run.
            options.SecurityStampValidationInterval = TimeSpan.Zero;

            // Confirmation is exercised through its own flow below rather than switched off,
            // so the smoke test covers what a real deployment does.
            options.RequireConfirmedEmail = true;
        });
        builder.Services.AddReusableAuthEntityFrameworkStores<AppDbContext>();
        builder.Services.AddSingleton<IAuthEmailSender, CapturedEmails>();

        builder.Services.AddAuthorization();

        WebApplication app = builder.Build();

        app.UseAuthentication();
        app.UseAuthorization();

        MapEndpoints(app);

        using (IServiceScope scope = app.Services.CreateScope())
        {
            await scope.ServiceProvider.GetRequiredService<AppDbContext>().Database.EnsureCreatedAsync();
        }

        await app.StartAsync();

        return new ConsumerApp(connection, app);
    }

    /// <summary>
    /// Routes of the host's own devising — the library ships none, which is the point.
    /// </summary>
    private static void MapEndpoints(WebApplication app)
    {
        app.MapPost("/register", async (Credentials body, IAuthService auth) =>
            Respond(await auth.RegisterAsync(body.Email, body.Password)));

        app.MapPost("/confirm", async (ConfirmRequest body, IAuthService auth) =>
            Respond(await auth.ConfirmEmailAsync(body.UserId, body.Token)));

        app.MapPost("/login", async (Credentials body, IAuthService auth) =>
            Respond(await auth.SignInAsync(body.Email, body.Password)));

        app.MapPost("/logout", async (IAuthService auth) =>
        {
            await auth.SignOutAsync();
            return Results.Ok();
        });

        // The "me" endpoint: only reachable with a valid session cookie.
        app.MapGet("/me", (ClaimsPrincipal user) =>
            Results.Ok(new Me(
                user.FindFirstValue(ClaimTypes.NameIdentifier) ?? "",
                user.FindFirstValue(ClaimTypes.Name) ?? "",
                user.FindAll(ClaimTypes.Role).Select(c => c.Value).ToArray())))
            .RequireAuthorization();

        // Guarded by a role claim carried in the cookie. This is what a revoked
        // administrator must stop being able to reach.
        app.MapGet("/admin", () => Results.Ok("admin area"))
            .RequireAuthorization(policy => policy.RequireRole("Admins"));
    }

    private static IResult Respond(AuthResult result) => result.Status switch
    {
        AuthStatus.Succeeded => Results.Ok(),
        AuthStatus.RequiresTwoFactor => Results.Ok(new { requiresTwoFactor = true }),
        AuthStatus.PasswordRejected => Results.BadRequest(new { errors = result.Errors }),
        AuthStatus.Rejected => Results.BadRequest(new { errors = result.Errors }),
        _ => Results.Unauthorized(),
    };

    /// <summary>
    /// An <see cref="HttpClient"/> that keeps cookies, like a browser.
    /// </summary>
    /// <remarks>
    /// The base address is <c>https</c> deliberately. The session cookie is issued
    /// <c>Secure</c> and cannot be weakened, so over plain http the server would never set
    /// it and every test here would fail for the wrong reason. TestServer does no real TLS;
    /// the scheme is what matters.
    /// </remarks>
    public HttpClient CreateClient()
    {
        TestServer server = _app.GetTestServer();
        server.BaseAddress = new Uri("https://localhost");

        return new HttpClient(new CookieJarHandler(server.CreateHandler(), Cookies))
        {
            BaseAddress = new Uri("https://localhost"),
        };
    }

    /// <summary>
    /// The cookies the client is holding — the test's window onto what the browser has.
    /// </summary>
    public CookieContainer Cookies { get; } = new();

    public async ValueTask DisposeAsync()
    {
        await _app.StopAsync();
        await _app.DisposeAsync();
        _connection.Dispose();
    }

    internal sealed class AppDbContext : ReusableAuthDbContext
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
        {
        }
    }

    internal sealed record Credentials(string Email, string Password);

    internal sealed record ConfirmRequest(string UserId, string Token);

    internal sealed record Me(string Id, string Name, string[] Roles);
}
