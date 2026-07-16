using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Authentication.EntityFrameworkCore;

/// <summary>
/// A ready-made <see cref="DbContext"/> for the auth tables, over a host-supplied user
/// type.
/// </summary>
/// <typeparam name="TUser">The Identity user type.</typeparam>
/// <remarks>
/// This derives from <c>IdentityDbContext&lt;TUser, IdentityRole, string&gt;</c>, and the
/// base is load-bearing rather than incidental. Identity's
/// <c>AddEntityFrameworkStores</c> looks for a context descended from
/// <c>IdentityDbContext</c> to decide it can wire the role-aware store; hand it anything
/// else and it does not complain, it quietly registers a store that reaches for role
/// entities the model has never heard of, and the first role call throws from inside EF.
/// <para>
/// Creates: <c>AspNetUsers</c>, <c>AspNetUserClaims</c>, <c>AspNetUserLogins</c>,
/// <c>AspNetUserTokens</c>, <c>AspNetRoles</c>, <c>AspNetUserRoles</c>,
/// <c>AspNetRoleClaims</c>. Migrations are the host's — see the README.
/// </para>
/// <para>
/// Deriving from this is optional; any <c>DbContext</c> descended from
/// <c>IdentityDbContext&lt;TUser, IdentityRole, string&gt;</c> works just as well.
/// </para>
/// </remarks>
public class ReusableAuthDbContext<TUser> : IdentityDbContext<TUser, IdentityRole, string>
    where TUser : IdentityUser<string>
{
    /// <summary>
    /// Creates the context with the given options.
    /// </summary>
    /// <param name="options">The options, typically supplied by <c>AddDbContext</c>.</param>
    public ReusableAuthDbContext(DbContextOptions options)
        : base(options)
    {
    }

    /// <summary>
    /// Creates the context for a derived type that configures itself.
    /// </summary>
    protected ReusableAuthDbContext()
    {
    }
}

/// <summary>
/// A ready-made <see cref="DbContext"/> for the auth tables, over the built-in
/// <see cref="ReusableAuthUser"/>.
/// </summary>
/// <remarks>
/// The zero-configuration case: derive from this, point it at a provider, and the schema
/// matches what <c>AddReusableAuth()</c> expects.
/// </remarks>
public class ReusableAuthDbContext : ReusableAuthDbContext<ReusableAuthUser>
{
    /// <summary>
    /// Creates the context with the given options.
    /// </summary>
    /// <param name="options">The options, typically supplied by <c>AddDbContext</c>.</param>
    public ReusableAuthDbContext(DbContextOptions options)
        : base(options)
    {
    }

    /// <summary>
    /// Creates the context for a derived type that configures itself.
    /// </summary>
    protected ReusableAuthDbContext()
    {
    }
}
