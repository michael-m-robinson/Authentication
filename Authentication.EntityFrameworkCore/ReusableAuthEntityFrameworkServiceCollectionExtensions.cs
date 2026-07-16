using Authentication;
using Authentication.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Wires Entity Framework Core storage for the reusable auth stack.
/// </summary>
/// <remarks>
/// The store itself is Microsoft's. ASP.NET Core Identity already ships an EF Core store
/// that implements every interface this library needs, including
/// <c>IUserSecurityStampStore</c>, without which session invalidation silently does
/// nothing, and it is maintained and security-reviewed with each release. Re-implementing
/// it would mean re-implementing concurrency-stamp handling and personal-data protection
/// for credential storage, which is the same mistake as hand-rolling a password hasher.
/// So this type wires Microsoft's store; it does not replace it.
/// </remarks>
public static class ReusableAuthEntityFrameworkServiceCollectionExtensions
{
    /// <summary>
    /// Stores the built-in <see cref="ReusableAuthUser"/> in <typeparamref name="TContext"/>.
    /// </summary>
    /// <typeparam name="TContext">
    /// The context, deriving from <see cref="ReusableAuthDbContext"/> or any
    /// <c>IdentityUserContext</c>.
    /// </typeparam>
    /// <param name="services">The service collection to add to.</param>
    /// <returns>The same <paramref name="services"/>, for chaining.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="services"/> is null.</exception>
    /// <exception cref="InvalidOperationException">
    /// <typeparamref name="TContext"/> is not an <c>IdentityUserContext</c>, or is one for
    /// a different user type.
    /// </exception>
    public static IServiceCollection AddReusableAuthEntityFrameworkStores<TContext>(
        this IServiceCollection services)
        where TContext : DbContext
        => services.AddReusableAuthEntityFrameworkStores<ReusableAuthUser, TContext>();

    /// <summary>
    /// Stores a host-supplied user type in <typeparamref name="TContext"/>.
    /// </summary>
    /// <typeparam name="TUser">The user type given to <c>AddReusableAuth&lt;TUser&gt;</c>.</typeparam>
    /// <typeparam name="TContext">
    /// The context, deriving from <see cref="ReusableAuthDbContext{TUser}"/> or any
    /// <c>IdentityUserContext</c> over the same user type.
    /// </typeparam>
    /// <param name="services">The service collection to add to.</param>
    /// <returns>The same <paramref name="services"/>, for chaining.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="services"/> is null.</exception>
    /// <exception cref="InvalidOperationException">
    /// <typeparamref name="TContext"/> is not an <c>IdentityUserContext</c>, or is one for
    /// a different user type.
    /// </exception>
    /// <remarks>
    /// Registers Identity's <c>UserOnlyStore</c>, the no-roles store this library composes,
    /// as <c>IUserStore&lt;TUser&gt;</c>. Registration uses
    /// <c>TryAdd</c>, so a store you registered yourself wins.
    /// </remarks>
    public static IServiceCollection AddReusableAuthEntityFrameworkStores<TUser, TContext>(
        this IServiceCollection services)
        where TUser : IdentityUser<string>, new()
        where TContext : DbContext
    {
        ArgumentNullException.ThrowIfNull(services);

        EnsureUsableContext<TUser, TContext>();

        // IdentityBuilder's constructor is public, so Microsoft's own AddEntityFrameworkStores
        // can be called from here without IdentityBuilder appearing in this library's API.
        //
        // The role type must be passed. AddEntityFrameworkStores decides what to register by
        // looking at builder.RoleType: leave it null and it registers a users-only store and
        // NO role store at all, so RoleManager - which the role-aware claims factory depends
        // on - cannot resolve and the host fails to build its container.
        new IdentityBuilder(typeof(TUser), typeof(IdentityRole), services)
            .AddEntityFrameworkStores<TContext>();

        return services;
    }

    /// <summary>
    /// Fails fast when <typeparamref name="TContext"/> cannot actually store
    /// <typeparamref name="TUser"/>.
    /// </summary>
    /// <remarks>
    /// Microsoft's <c>AddEntityFrameworkStores</c> constrains its context only to
    /// <see cref="DbContext"/>, and it decides which store to wire by looking for an
    /// <c>IdentityDbContext</c> in the context's ancestry. Hand it anything else and it
    /// does not complain. It quietly registers a store bound to the default POCOs, which
    /// then reaches for role entities the model has never heard of and throws from inside
    /// EF, with an error about entity types rather than about the misconfiguration that
    /// caused them. Likewise a context built for a different user type is accepted and
    /// breaks at first use.
    /// <para>
    /// Both are configuration mistakes with delayed, misleading symptoms, so this reports
    /// them at startup with the types named. Same reasoning as
    /// <c>SecurityStampStoreGuard</c> in the core package: a store problem must be a boot
    /// failure, not a runtime surprise.
    /// </para>
    /// <para>
    /// Note this checks for <c>IdentityDbContext</c>, not <c>IdentityUserContext</c>. The
    /// latter is its base and has no role tables, so it would satisfy a looser check and
    /// still fail the moment anyone touched a role.
    /// </para>
    /// </remarks>
    private static void EnsureUsableContext<TUser, TContext>()
        where TUser : IdentityUser<string>
        where TContext : DbContext
    {
        Type? identityContext = FindGenericBase(typeof(TContext), typeof(IdentityDbContext<,,,,,,,,>));

        if (identityContext is null)
        {
            throw new InvalidOperationException(
                $"{typeof(TContext).Name} cannot store Identity users and roles: it does not derive " +
                $"from IdentityDbContext. Derive it from ReusableAuthDbContext<{typeof(TUser).Name}> " +
                "(or an IdentityDbContext of your own) and try again.");
        }

        Type contextUserType = identityContext.GenericTypeArguments[0];
        if (!contextUserType.IsAssignableFrom(typeof(TUser)))
        {
            throw new InvalidOperationException(
                $"{typeof(TContext).Name} stores {contextUserType.Name}, but the auth stack was " +
                $"registered for {typeof(TUser).Name}. Both must name the same user type.");
        }
    }

    /// <summary>
    /// Walks the base-type chain for a closed form of <paramref name="genericBaseType"/>,
    /// or null.
    /// </summary>
    private static Type? FindGenericBase(Type type, Type genericBaseType)
    {
        Type? current = type;

        while (current is not null)
        {
            if (current.IsGenericType && current.GetGenericTypeDefinition() == genericBaseType)
            {
                return current;
            }

            current = current.BaseType;
        }

        return null;
    }
}
