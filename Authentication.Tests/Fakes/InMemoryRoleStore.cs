using System.Collections.Concurrent;
using Microsoft.AspNetCore.Identity;

namespace Authentication.Tests.Fakes;

/// <summary>
/// An in-memory <see cref="IRoleStore{TRole}"/>.
/// </summary>
/// <remarks>
/// Required, not optional. Turning roles on swaps Identity's claims factory for the
/// role-aware one, which depends on <see cref="RoleManager{TRole}"/>, which will not
/// resolve without a role store, so a host with no role store cannot build its container
/// at all. Implements <see cref="IQueryableRoleStore{TRole}"/> too, since
/// <c>RoleManager.Roles</c> throws <see cref="NotSupportedException"/> without it.
/// </remarks>
internal sealed class InMemoryRoleStore : IRoleStore<IdentityRole>, IQueryableRoleStore<IdentityRole>
{
    private readonly ConcurrentDictionary<string, IdentityRole> _roles = new(StringComparer.Ordinal);

    public IQueryable<IdentityRole> Roles => _roles.Values.AsQueryable();

    public Task<IdentityResult> CreateAsync(IdentityRole role, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(role);
        return Task.FromResult(
            _roles.TryAdd(role.Id, role)
                ? IdentityResult.Success
                : IdentityResult.Failed(new IdentityError { Code = "DuplicateRoleId" }));
    }

    public Task<IdentityResult> UpdateAsync(IdentityRole role, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(role);
        _roles[role.Id] = role;
        return Task.FromResult(IdentityResult.Success);
    }

    public Task<IdentityResult> DeleteAsync(IdentityRole role, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(role);
        _roles.TryRemove(role.Id, out _);
        return Task.FromResult(IdentityResult.Success);
    }

    public Task<IdentityRole?> FindByIdAsync(string roleId, CancellationToken cancellationToken)
        => Task.FromResult(_roles.GetValueOrDefault(roleId));

    public Task<IdentityRole?> FindByNameAsync(string normalizedRoleName, CancellationToken cancellationToken)
        => Task.FromResult(_roles.Values.FirstOrDefault(
            r => string.Equals(r.NormalizedName, normalizedRoleName, StringComparison.Ordinal)));

    public Task<string> GetRoleIdAsync(IdentityRole role, CancellationToken cancellationToken)
        => Task.FromResult(role.Id);

    public Task<string?> GetRoleNameAsync(IdentityRole role, CancellationToken cancellationToken)
        => Task.FromResult(role.Name);

    public Task SetRoleNameAsync(IdentityRole role, string? roleName, CancellationToken cancellationToken)
    {
        role.Name = roleName;
        return Task.CompletedTask;
    }

    public Task<string?> GetNormalizedRoleNameAsync(IdentityRole role, CancellationToken cancellationToken)
        => Task.FromResult(role.NormalizedName);

    public Task SetNormalizedRoleNameAsync(IdentityRole role, string? normalizedName, CancellationToken cancellationToken)
    {
        role.NormalizedName = normalizedName;
        return Task.CompletedTask;
    }

    public void Dispose()
    {
        // Nothing to release.
    }
}
