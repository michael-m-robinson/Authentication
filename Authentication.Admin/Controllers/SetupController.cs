using System.Security.Cryptography;
using System.Text;
using Authentication.Admin.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

// Controllers are public only because MVC discovers public controllers; a consuming app never
// calls their actions, so they are framework plumbing rather than the package's documented API
// surface. The documented contract lives on the services and DTOs they call. The class itself
// carries a doc comment; per-action docs would be noise.
#pragma warning disable CS1591

namespace Authentication.Admin.Controllers;

/// <summary>
/// The one-time first-administrator setup. Reachable only while no administrator exists; the
/// <see cref="SetupSealFilter"/> returns 404 for every action the moment one does.
/// </summary>
/// <remarks>
/// Anonymous by necessity - there is no admin to authenticate as yet - which is exactly why the
/// seal, the optional <see cref="AdminOptions.SetupToken"/>, and the non-enumerating create path
/// all matter. Once an administrator exists, promotion of further users happens through the
/// gated Users pages, not here.
/// </remarks>
[AllowAnonymous]
[ServiceFilter(typeof(SetupSealFilter))]
[Route("setup")]
public sealed class SetupController : Controller
{
    private readonly IAuthService _auth;
    private readonly IAdminUserService _users;
    private readonly IRoleService _roles;
    private readonly AdminOptions _options;

    public SetupController(
        IAuthService auth,
        IAdminUserService users,
        IRoleService roles,
        AdminOptions options)
    {
        _auth = auth;
        _users = users;
        _roles = roles;
        _options = options;
    }

    [HttpGet("")]
    public IActionResult Index()
        => View(new SetupViewModel());

    [HttpPost("")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Index(SetupViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        if (!SetupTokenMatches(model.SetupToken))
        {
            ModelState.AddModelError(string.Empty, "The setup secret is missing or incorrect.");
            return View(model);
        }

        // The role must exist before it can be granted. Idempotent: the bootstrapper usually
        // made it already, and creating an existing role is a harmless rejection.
        await _roles.CreateRoleAsync(_options.AdminRoleName);

        (string? userId, string? error) = await ResolveAdministratorAsync(model);
        if (userId is null)
        {
            ModelState.AddModelError(string.Empty, error!);
            return View(model);
        }

        AuthResult granted = await _roles.AddToRoleAsync(userId, _options.AdminRoleName);
        if (!granted.Succeeded)
        {
            AddErrors(granted);
            return View(model);
        }

        // Sign nobody in. The new admin signs in through the app's normal login, which mints the
        // hardened session cookie the same way for everyone.
        return View("Done");
    }

    // Promote an existing user, or create a new confirmed one, returning their id or an error.
    private async Task<(string? UserId, string? Error)> ResolveAdministratorAsync(SetupViewModel model)
    {
        if (model.PromoteExisting)
        {
            string? existingId = await _users.FindIdByEmailAsync(model.Email);
            // Generic failure: do not distinguish "no such email" from any other failure, so
            // this anonymous (pre-seal) page is not an email-existence oracle. In Production the
            // setup token is required first (see SetupSealFilter), which is the real gate.
            return existingId is null
                ? (null, "That email could not be set up as an administrator. Check the address, or create a new administrator instead.")
                : (existingId, null);
        }

        return await CreateAdministratorAsync(model);
    }

    private async Task<(string? UserId, string? Error)> CreateAdministratorAsync(SetupViewModel model)
    {
        if (string.IsNullOrWhiteSpace(model.Password))
        {
            return (null, "A password is required to create a new administrator.");
        }

        AuthResult registered = await _auth.RegisterAsync(model.Email, model.Password);
        if (registered.Status == AuthStatus.PasswordRejected)
        {
            return (null, string.Join(" ", registered.Errors));
        }

        string? userId = await _users.FindIdByEmailAsync(model.Email);
        if (userId is null)
        {
            // Registration reports success even for an already-taken email (non-enumeration),
            // so a null here means the address was already in use by someone the operator did
            // not mean to promote. Say so without confirming which.
            return (null, "That email could not be set up as a new administrator. If it already "
                + "has an account, tick 'promote existing user' instead.");
        }

        // A first admin who had to fish a confirmation link out of an inbox before they could
        // sign in would be a poor first-run experience, so confirm them here.
        await _users.ForceConfirmEmailAsync(userId);
        return (userId, null);
    }

    private bool SetupTokenMatches(string? supplied)
    {
        if (string.IsNullOrEmpty(_options.SetupToken))
        {
            return true;   // no secret configured
        }

        // Constant-time compare: string.Equals short-circuits on the first differing byte,
        // which leaks the secret one character at a time to a timing attack. FixedTimeEquals is
        // the framework's constant-time comparison (see CryptographicOperations docs).
        return CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(supplied ?? string.Empty),
            Encoding.UTF8.GetBytes(_options.SetupToken));
    }

    private void AddErrors(AuthResult result)
    {
        foreach (string error in result.Errors)
        {
            ModelState.AddModelError(string.Empty, error);
        }
    }
}
