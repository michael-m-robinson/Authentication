using Authentication.Social;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Wires likes and alerts into a host's container.
/// </summary>
/// <remarks>
/// Both services are stored on the host's own <c>DbContext</c>, named by the <c>TContext</c>
/// type argument on the call. That is what lets a like and the alert it raises reach the
/// database in one <c>SaveChangesAsync</c>.
/// <para>
/// Nothing here touches authentication, registration, passwords, roles, claims, cookies or
/// lockout. Call it alongside <c>AddReusableAuth</c>, not instead of any part of it.
/// </para>
/// </remarks>
public static class ReusableAuthSocialServiceCollectionExtensions
{
    /// <summary>
    /// Adds likes and alerts, with <typeparamref name="TContentSource"/> deciding who may see
    /// what.
    /// </summary>
    /// <typeparam name="TContext">
    /// The host's context: the same one carrying the auth tables, and the one whose
    /// <c>OnModelCreating</c> calls <c>AddReusableAuthSocial</c>.
    /// </typeparam>
    /// <typeparam name="TContentSource">
    /// Your <see cref="IContentSource"/>. Registered scoped, so it may take your
    /// <typeparamref name="TContext"/> and query it.
    /// </typeparam>
    /// <param name="services">The service collection to add to.</param>
    /// <returns>The same <paramref name="services"/>, for chaining.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="services"/> is null.</exception>
    /// <remarks>
    /// <code>
    /// builder.Services.AddReusableAuthSocial&lt;AppDbContext, ArticleContentSource&gt;();
    /// </code>
    /// </remarks>
    public static IServiceCollection AddReusableAuthSocial<TContext, TContentSource>(
        this IServiceCollection services)
        where TContext : DbContext
        where TContentSource : class, IContentSource
    {
        ArgumentNullException.ThrowIfNull(services);

        services.TryAddScoped<IContentSource, TContentSource>();

        return services.AddReusableAuthSocial<TContext>();
    }

    /// <summary>
    /// Adds likes and alerts, leaving <see cref="IContentSource"/> for you to register.
    /// </summary>
    /// <typeparam name="TContext">
    /// The host's context: the same one carrying the auth tables, and the one whose
    /// <c>OnModelCreating</c> calls <c>AddReusableAuthSocial</c>.
    /// </typeparam>
    /// <param name="services">The service collection to add to.</param>
    /// <returns>The same <paramref name="services"/>, for chaining.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="services"/> is null.</exception>
    /// <remarks>
    /// For an <see cref="IContentSource"/> that needs more than a type name: a factory, an
    /// instance, or a lifetime of your choosing.
    /// <code>
    /// builder.Services.AddScoped&lt;IContentSource&gt;(sp => new ArticleContentSource(...));
    /// builder.Services.AddReusableAuthSocial&lt;AppDbContext&gt;();
    /// </code>
    /// Register one either way. Without it nothing can resolve <c>ILikeService</c>, and the
    /// container says so by name the first time something asks.
    /// </remarks>
    public static IServiceCollection AddReusableAuthSocial<TContext>(this IServiceCollection services)
        where TContext : DbContext
    {
        ArgumentNullException.ThrowIfNull(services);

        // Microsoft's own default, and the reason the services take a TimeProvider at all: a
        // test can substitute the clock without either service knowing.
        services.TryAddSingleton(TimeProvider.System);

        // Scoped, all of them: each holds the host's context, which is scoped itself. A
        // singleton over a scoped context is the classic captive dependency - one context,
        // shared by every request, for the lifetime of the process.
        services.TryAddScoped<AlertWriter<TContext>>();
        services.TryAddScoped<ILikeService, LikeService<TContext>>();
        services.TryAddScoped<IAlertService, AlertService<TContext>>();

        return services;
    }
}
