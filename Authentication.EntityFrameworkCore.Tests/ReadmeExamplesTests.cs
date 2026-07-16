using System.Security.Claims;
using Authentication;
using Authentication.EntityFrameworkCore;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;

namespace Authentication.EntityFrameworkCore.Tests;

/// <summary>
/// Runs the README's quick-start wiring for real, so the documentation cannot drift away
/// from the library.
/// </summary>
/// <remarks>
/// Compiling the examples is not enough. The README previously showed
/// <c>UserManager.AddToRoleAsync</c> next to <c>RotateSessionAsync</c>; it compiled
/// perfectly and threw at runtime, because the library composes Identity without roles and
/// the store has no role support. Only executing it caught that.
/// </remarks>
public sealed class ReadmeExamplesTests : IDisposable
{
    private readonly SqliteConnection _connection;

    public ReadmeExamplesTests()
    {
        _connection = new SqliteConnection("DataSource=:memory:");
        _connection.Open();
    }

    /// <summary>
    /// The README's "Quick start", verbatim apart from the provider.
    /// </summary>
    private ServiceProvider BuildQuickStart(Action<ReusableAuthOptions>? configure = null)
    {
        ServiceCollection services = new();
        services.AddLogging();
        services.AddDataProtection();

        services.AddDbContext<QuickStartDbContext>(o => o.UseSqlite(_connection));

        services.AddReusableAuth(configure ?? (_ => { }));
        services.AddReusableAuthEntityFrameworkStores<QuickStartDbContext>();
        services.AddScoped<IAuthEmailSender, ExampleEmailSender>();

        ServiceProvider provider = services.BuildServiceProvider();

        using (IServiceScope scope = provider.CreateScope())
        {
            scope.ServiceProvider.GetRequiredService<QuickStartDbContext>().Database.EnsureCreated();
        }

        return provider;
    }

    [Fact]
    public void QuickStart_Resolves()
    {
        using ServiceProvider provider = BuildQuickStart();
        using IServiceScope scope = provider.CreateScope();

        // Three registrations and IAuthService is usable. That is the README's claim.
        Assert.NotNull(scope.ServiceProvider.GetRequiredService<IAuthService>());
    }

    [Fact]
    public void QuickStart_SatisfiesTheStartupGuard()
    {
        using ServiceProvider provider = BuildQuickStart();
        using IServiceScope scope = provider.CreateScope();

        SecurityStampStoreGuard<ReusableAuthUser>.Verify(
            scope.ServiceProvider.GetRequiredService<UserManager<ReusableAuthUser>>());
    }

    [Fact]
    public async Task ReadmeUsageExample_Runs()
    {
        using ServiceProvider provider = BuildQuickStart();
        using IServiceScope scope = provider.CreateScope();
        IAuthService auth = scope.ServiceProvider.GetRequiredService<IAuthService>();

        // Straight from "Using it".
        AuthResult registered = await auth.RegisterAsync("person@example.com", "Correct-horse-9!");
        Assert.Equal(AuthStatus.Succeeded, registered.Status);

        // Unconfirmed, so sign-in fails - and says nothing about why, per the README's
        // "Behaviour that will surprise you".
        AuthResult signedIn = await auth.SignInAsync("person@example.com", "Correct-horse-9!");
        Assert.Equal(AuthStatus.Failed, signedIn.Status);

        // Nobody is signed in outside a request.
        Assert.Null(auth.CurrentPrincipal);

        // Always succeeds, whether or not the address is registered.
        Assert.Equal(AuthStatus.Succeeded, (await auth.RequestPasswordResetAsync("nobody@example.com")).Status);

        // A no-op rather than an error.
        await auth.SignOutAsync();
    }

    [Fact]
    public async Task ReadmeClaim_TheTakenAddressExample_Holds()
    {
        using ServiceProvider provider = BuildQuickStart();
        using IServiceScope scope = provider.CreateScope();
        IAuthService auth = scope.ServiceProvider.GetRequiredService<IAuthService>();

        await auth.RegisterAsync("taken@example.com", "Correct-horse-9!");

        // The README says: "Registering with an address that's already taken returns
        // Succeeded." If that ever stops being true, the docs are lying about a security
        // property, so it is asserted here rather than only in the unit tests.
        AuthResult again = await auth.RegisterAsync("taken@example.com", "Different-pass-1!");

        Assert.Equal(AuthStatus.Succeeded, again.Status);
    }

    [Fact]
    public async Task ReadmeRoleExample_Runs()
    {
        using ServiceProvider provider = BuildQuickStart();
        using IServiceScope scope = provider.CreateScope();
        IRoleService roles = scope.ServiceProvider.GetRequiredService<IRoleService>();
        UserManager<ReusableAuthUser> users =
            scope.ServiceProvider.GetRequiredService<UserManager<ReusableAuthUser>>();

        ReusableAuthUser user = new() { UserName = "person@example.com", Email = "person@example.com" };
        await users.CreateAsync(user, "Correct-horse-9!");

        // Straight from the README's role section.
        Assert.Equal(AuthStatus.Succeeded, (await roles.CreateRoleAsync("Admins")).Status);
        Assert.Equal(AuthStatus.Succeeded, (await roles.AddToRoleAsync(user.Id, "Admins")).Status);
        Assert.Contains("Admins", await roles.GetUserRolesAsync(user.Id));

        Assert.Equal(AuthStatus.Succeeded, (await roles.RemoveFromRoleAsync(user.Id, "Admins")).Status);
        Assert.DoesNotContain("Admins", await roles.GetUserRolesAsync(user.Id));
    }

    [Fact]
    public async Task ReadmeClaimsExample_Runs()
    {
        using ServiceProvider provider = BuildQuickStart();
        using IServiceScope scope = provider.CreateScope();
        UserManager<ReusableAuthUser> users =
            scope.ServiceProvider.GetRequiredService<UserManager<ReusableAuthUser>>();

        ReusableAuthUser user = new() { UserName = "person@example.com", Email = "person@example.com" };
        await users.CreateAsync(user, "Correct-horse-9!");

        IdentityResult added = await users.AddClaimAsync(user, new Claim("department", "engineering"));

        Assert.True(added.Succeeded);
    }

    [Fact]
    public void ReadmeOptionsExample_Applies()
    {
        // From "Options".
        using ServiceProvider provider = BuildQuickStart(options =>
        {
            options.SessionLifetime = TimeSpan.FromHours(4);
            options.PasswordMinimumLength = 16;
        });

        IdentityOptions identity =
            provider.GetRequiredService<Microsoft.Extensions.Options.IOptions<IdentityOptions>>().Value;

        Assert.Equal(16, identity.Password.RequiredLength);
    }

    public void Dispose() => _connection.Dispose();

    private sealed class QuickStartDbContext : ReusableAuthDbContext
    {
        public QuickStartDbContext(DbContextOptions<QuickStartDbContext> options) : base(options)
        {
        }
    }

    private sealed class ExampleEmailSender : IAuthEmailSender
    {
        public Task SendEmailConfirmationAsync(string email, string userId, string token) => Task.CompletedTask;

        public Task SendPasswordResetAsync(string email, string userId, string token) => Task.CompletedTask;

        public Task SendRegistrationAttemptedAsync(string email) => Task.CompletedTask;
    }
}
