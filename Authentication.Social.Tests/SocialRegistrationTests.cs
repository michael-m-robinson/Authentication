using Authentication.Social;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Authentication.Social.Tests;

/// <summary>
/// Covers <c>AddReusableAuthSocial</c>: that a host wiring it the documented way gets a
/// container that builds and resolves.
/// </summary>
/// <remarks>
/// These resolve from a real container rather than asserting over
/// <c>ServiceDescriptor</c>s. A descriptor test proves a registration was written down; it
/// cannot notice that the thing registered has a dependency nobody supplied, which is exactly
/// the mistake this package's own EF wiring made once and shipped.
/// </remarks>
public sealed class SocialRegistrationTests : IDisposable
{
    private readonly SqliteConnection _connection;

    public SocialRegistrationTests()
    {
        _connection = new SqliteConnection("DataSource=:memory:");
        _connection.Open();
    }

    /// <summary>
    /// A host's container, wired the way the README says.
    /// </summary>
    private ServiceProvider BuildHost(Action<IServiceCollection> addSocial)
    {
        ServiceCollection services = new();
        services.AddLogging();
        services.AddDbContext<SocialDbContext>(o => o.UseSqlite(_connection));

        addSocial(services);

        // Validating on build is what turns a captive dependency or a missing service into a
        // failure here rather than on someone's first request.
        return services.BuildServiceProvider(new ServiceProviderOptions
        {
            ValidateOnBuild = true,
            ValidateScopes = true,
        });
    }

    [Fact]
    public void TheGenericOverload_ResolvesEverything()
    {
        using ServiceProvider provider = BuildHost(s =>
            s.AddReusableAuthSocial<SocialDbContext, StubContentSource>());

        using IServiceScope scope = provider.CreateScope();

        Assert.NotNull(scope.ServiceProvider.GetRequiredService<ILikeService>());
        Assert.NotNull(scope.ServiceProvider.GetRequiredService<IAlertService>());
        Assert.NotNull(scope.ServiceProvider.GetRequiredService<IContentSource>());
    }

    [Fact]
    public void TheOverloadWithoutAContentSource_ResolvesEverything_WhenTheHostRegistersOne()
    {
        using ServiceProvider provider = BuildHost(s =>
        {
            s.AddScoped<IContentSource>(_ => new StubContentSource());
            s.AddReusableAuthSocial<SocialDbContext>();
        });

        using IServiceScope scope = provider.CreateScope();

        Assert.NotNull(scope.ServiceProvider.GetRequiredService<ILikeService>());
        Assert.NotNull(scope.ServiceProvider.GetRequiredService<IAlertService>());
    }

    [Fact]
    public void AMissingContentSource_FailsAtStartup_NamingWhatIsMissing()
    {
        // The reason this package ships no boot-time guard for IContentSource. The container
        // already reports it, by name, before the app serves a request - unlike a missing
        // security stamp store, which fails silently and is why the core package guards that
        // one.
        // ValidateOnBuild reports every broken registration at once, so the individual
        // failures arrive wrapped.
        AggregateException ex = Assert.Throws<AggregateException>(
            () => BuildHost(s => s.AddReusableAuthSocial<SocialDbContext>()));

        Assert.Contains(
            ex.InnerExceptions,
            inner => inner.Message.Contains(nameof(IContentSource), StringComparison.Ordinal));
    }

    [Fact]
    public void TheServices_AreScoped_NotSingletons()
    {
        // Each holds the host's DbContext. A singleton would capture one context for the life
        // of the process and share it across every request: ValidateScopes turns that into
        // the failure below rather than into intermittent corruption under load.
        using ServiceProvider provider = BuildHost(s =>
            s.AddReusableAuthSocial<SocialDbContext, StubContentSource>());

        Assert.Throws<InvalidOperationException>(() => provider.GetRequiredService<ILikeService>());
    }

    [Fact]
    public void CallingTwice_ChangesNothing()
    {
        // Every registration is a TryAdd, so a host that calls it from two places - or a
        // library that calls it on the host's behalf - does not end up with duplicates.
        using ServiceProvider provider = BuildHost(s =>
        {
            s.AddReusableAuthSocial<SocialDbContext, StubContentSource>();
            s.AddReusableAuthSocial<SocialDbContext, StubContentSource>();
        });

        using IServiceScope scope = provider.CreateScope();

        Assert.Single(scope.ServiceProvider.GetServices<ILikeService>());
        Assert.Single(scope.ServiceProvider.GetServices<IAlertService>());
    }

    [Fact]
    public void AContentSourceTheHostRegisteredFirst_Wins()
    {
        // TryAdd, so the host's own registration is not overwritten by the type argument.
        using ServiceProvider provider = BuildHost(s =>
        {
            s.AddScoped<IContentSource, OtherStubContentSource>();
            s.AddReusableAuthSocial<SocialDbContext, StubContentSource>();
        });

        using IServiceScope scope = provider.CreateScope();

        Assert.IsType<OtherStubContentSource>(scope.ServiceProvider.GetRequiredService<IContentSource>());
    }

    [Fact]
    public void AHostsOwnClock_Wins()
    {
        // TryAddSingleton, so a host that has already chosen a TimeProvider keeps it. Alert
        // timestamps then come from the same clock as everything else the host stamps.
        FakeTimeProvider clock = new();

        using ServiceProvider provider = BuildHost(s =>
        {
            s.AddSingleton<TimeProvider>(clock);
            s.AddReusableAuthSocial<SocialDbContext, StubContentSource>();
        });

        Assert.Same(clock, provider.GetRequiredService<TimeProvider>());
    }

    [Fact]
    public async Task TheResolvedServices_ActuallyWork()
    {
        // End to end through the container, on a real database: the registration is only
        // correct if what comes out of it can store a like and raise its alert.
        using ServiceProvider provider = BuildHost(s =>
            s.AddReusableAuthSocial<SocialDbContext, StubContentSource>());

        using (IServiceScope setup = provider.CreateScope())
        {
            await setup.ServiceProvider.GetRequiredService<SocialDbContext>().Database.EnsureCreatedAsync();
        }

        using IServiceScope scope = provider.CreateScope();
        ILikeService likes = scope.ServiceProvider.GetRequiredService<ILikeService>();

        LikeResult result = await likes.LikeAsync("user-1", "Article", 42, default);

        Assert.True(result.IsLiked);
        Assert.Equal(1, result.LikeCount);

        IAlertService alerts = scope.ServiceProvider.GetRequiredService<IAlertService>();
        Assert.Equal(1, await alerts.CountUnreadAsync(StubContentSource.OwnerId, default));
    }

    public void Dispose() => _connection.Dispose();

    private sealed class StubContentSource : IContentSource
    {
        public const string OwnerId = "owner-1";

        public Task<ContentInfo?> GetAsync(
            string userId,
            string contentType,
            long contentId,
            CancellationToken cancellationToken)
            => Task.FromResult<ContentInfo?>(new ContentInfo(OwnerId, SupportsLikes: true));
    }

    private sealed class OtherStubContentSource : IContentSource
    {
        public Task<ContentInfo?> GetAsync(
            string userId,
            string contentType,
            long contentId,
            CancellationToken cancellationToken)
            => Task.FromResult<ContentInfo?>(null);
    }

    private sealed class FakeTimeProvider : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => DateTimeOffset.UnixEpoch;
    }
}
