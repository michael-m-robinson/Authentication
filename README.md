# Authentication

A reusable, project-agnostic authentication library for ASP.NET Core. Drop it into
an MVC, Razor Pages, Blazor or minimal-API app and the auth work is done: a
hardened session cookie (**httpOnly + Secure + SameSite**), **double-submit CSRF**,
password hashing, lockout, email confirmation, password reset, and session
invalidation on privilege change.

**It is a library, not an API.** It adds no HTTP endpoints and no pages. You call
methods; you keep your own routes, pages and components. That works the same in
MVC, Blazor, or anything else.

**It is mostly Microsoft's code.** ASP.NET Core Identity already ships the hard,
security-reviewed parts — the password hasher, the cookie handler, the token
providers, the EF Core store. This library wires them together with secure
defaults, closes the places Identity leaks information by default, and refuses to
start when it's configured into something unsafe. It contains no cryptography,
persistence or session handling of its own. See
[What's Microsoft's, what's ours](#whats-microsofts-whats-ours).

## Status

**Pre-release (0.1.0).** Registration, sign-in, sign-out, email confirmation,
password reset, password change, session rotation and role management all work and
are tested. Per-user settings (change email, phone, two-factor) are not built yet —
see [PLAN.md](PLAN.md).

## Quick start

Three things to register: the library, a store, and an email sender.

```csharp
builder.Services.AddDbContext<AppDbContext>(o => o.UseNpgsql(connectionString));

builder.Services.AddReusableAuth();                                  // 1. the library
builder.Services.AddReusableAuthEntityFrameworkStores<AppDbContext>(); // 2. a store
builder.Services.AddScoped<IAuthEmailSender, MyEmailSender>();       // 3. sending mail

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();
```

That's the whole setup. Every option defaults to the secure choice, so configuring
nothing gives you a hardened setup.

### MVC or Razor Pages

Set a login path and a challenge redirects to your page, as MVC expects:

```csharp
builder.Services.AddReusableAuth(options =>
{
    options.LoginPath = "/Account/Login";
    options.AccessDeniedPath = "/Account/Denied";
});
```

```csharp
public class AccountController(IAuthService auth) : Controller
{
    [HttpPost]
    public async Task<IActionResult> Login(string email, string password)
    {
        AuthResult result = await auth.SignInAsync(email, password);

        if (result.Succeeded)
        {
            return RedirectToAction("Index", "Home");
        }

        ModelState.AddModelError("", "Invalid email or password.");
        return View();
    }
}
```

### Blazor

Same registration; inject `IAuthService` into a component.

```razor
@inject IAuthService Auth

<button @onclick="SignOut">Sign out</button>

@code {
    private async Task SignOut() => await Auth.SignOutAsync();
}
```

### API

Leave the paths unset and a challenge answers `401`/`403` instead of redirecting to
HTML a JSON client can't use. That's the default.

```csharp
app.MapPost("/login", async (LoginRequest req, IAuthService auth) =>
{
    AuthResult result = await auth.SignInAsync(req.Email, req.Password);

    return result.Succeeded ? Results.Ok() : Results.Unauthorized();
});
```

## What you must supply

### A store

Anything implementing `IUserStore<TUser>`, `IUserSecurityStampStore<TUser>`,
`IUserRoleStore<TUser>` and `IRoleStore<IdentityRole>`. Easiest is the EF Core
package — see [below](#entity-framework-core-storage), which gives you Microsoft's
store and satisfies all of them.

`IUserSecurityStampStore` is not optional. Without it, Identity silently treats
every security-stamp check as valid, so password resets and privilege changes would
quietly fail to invalidate existing sessions. The library checks at startup and
refuses to boot rather than let that pass unnoticed.

### An email sender

The library mints tokens; it never sends mail, because picking an SMTP provider
would be exactly the app-specific assumption it exists to avoid.

```csharp
public sealed class MyEmailSender(IEmailClient client) : IAuthEmailSender
{
    public Task SendEmailConfirmationAsync(string email, string userId, string token)
    {
        var link = $"https://myapp.com/confirm?userId={userId}&token={token}";
        return client.SendAsync(email, "Confirm your email", $"Click here: {link}");
    }

    public Task SendPasswordResetAsync(string email, string userId, string token)
    {
        var link = $"https://myapp.com/reset?userId={userId}&token={token}";
        return client.SendAsync(email, "Reset your password", $"Click here: {link}");
    }

    public Task SendRegistrationAttemptedAsync(string email)
    {
        // Someone tried to register with an address that already has an account.
        // Carries no token and grants nothing.
        return client.SendAsync(email, "Registration attempt",
            "Someone tried to register with your address. If it was you, sign in or reset your password.");
    }
}
```

Tokens arrive **URL-safe** — drop them straight into a query string, and pass them
back unchanged. The library owns both halves of that encoding so you never have to
think about it.

## Using it

Inject `IAuthService`. Every method returns an `AuthResult` rather than throwing:
a wrong password is an ordinary outcome, not an exception.

```csharp
public class MyService(IAuthService auth)
{
    public async Task ExampleAsync()
    {
        // Register. Sends a confirmation email.
        AuthResult r = await auth.RegisterAsync("person@example.com", "Correct-horse-9!");

        // Sign in. Issues the hardened session cookie.
        AuthResult s = await auth.SignInAsync("person@example.com", "Correct-horse-9!");

        // Who is signed in?
        ClaimsPrincipal? me = auth.CurrentPrincipal;

        // Confirm an email, using the values from your confirmation link.
        await auth.ConfirmEmailAsync(userId, token);

        // Forgot password: emails a link, if the address is eligible.
        await auth.RequestPasswordResetAsync("person@example.com");

        // Complete the reset, using the values from your reset link.
        await auth.ResetPasswordAsync(userId, token, "Brand-new-pass-2!");

        // Change password. Invalidates other sessions, keeps this one.
        await auth.ChangePasswordAsync("Correct-horse-9!", "Brand-new-pass-2!");

        // Sign out.
        await auth.SignOutAsync();
    }
}
```

### Reading the result

```csharp
AuthResult result = await auth.SignInAsync(email, password);

switch (result.Status)
{
    case AuthStatus.Succeeded:
        break;
    case AuthStatus.RequiresTwoFactor:
        break;
    case AuthStatus.PasswordRejected:
        // result.Errors holds the policy messages, safe to show.
        break;
    case AuthStatus.Failed:
        // Deliberately no reason. See below.
        break;
}
```

## Roles

Inject `IRoleService`. Roles are ASP.NET Core Identity roles, so
`[Authorize(Roles = "Admins")]`, `User.IsInRole("Admins")` and `RequireRole` all
work against them with no extra wiring.

```csharp
public class AdminService(IRoleService roles)
{
    public async Task ExampleAsync(string userId)
    {
        await roles.CreateRoleAsync("Admins");

        await roles.AddToRoleAsync(userId, "Admins");       // grants it
        await roles.RemoveFromRoleAsync(userId, "Admins");  // and takes it away

        bool isAdmin = await roles.IsInRoleAsync(userId, "Admins");
        IReadOnlyList<string> theirRoles = await roles.GetUserRolesAsync(userId);
        IReadOnlyList<string> members = await roles.GetUsersInRoleAsync("Admins");
        IReadOnlyList<string> all = await roles.GetRolesAsync();

        await roles.DeleteRoleAsync("Admins");
    }
}
```

```csharp
[Authorize(Roles = "Admins")]
public IActionResult Dashboard() => View();
```

**Removing a role really removes the access.** Identity refreshes the security
stamp when a password changes but **not** when roles change — so a plain
`UserManager.RemoveFromRoleAsync` leaves the user holding a cookie that still
claims the role, and `[Authorize(Roles = "Admins")]` keeps letting them in until it
expires. A revoked administrator stays an administrator. `IRoleService` refreshes
the stamp for you, so a change takes effect on every session that user has open
within `SecurityStampValidationInterval` (1 minute by default).

The same applies to `DeleteRoleAsync`: deleting a role would otherwise leave every
member's cookie asserting a role that no longer exists, so it refreshes each
member's stamp. That costs one write per member, so deleting a role with very many
members is correspondingly expensive.

Failures here are **explained**, unlike sign-in:

```csharp
AuthResult result = await roles.AddToRoleAsync(userId, "Admins");

if (result.Status == AuthStatus.Rejected)
{
    // result.Errors: no such role, no such user, already a member...
}
```

That's safe because these are administrative calls made by your own code with an id
it already holds — there's no anonymous caller to disclose anything to.

**Role names are matched case-insensitively but authorised case-sensitively.**
`AddToRoleAsync(id, "ADMINS")` finds the role you created as `"Admins"`, but the
claim written into the cookie keeps the original casing, and
`[Authorize(Roles = "...")]` compares it exactly. Create `Admins`, authorise on
`Admins`.

### Claims

For anything finer-grained than a role, use claims via `UserManager`, then rotate:

```csharp
await userManager.AddClaimAsync(user, new Claim("department", "engineering"));
await auth.RotateSessionAsync();   // invalidate other sessions, re-issue this one
```

`RotateSessionAsync` is the manual equivalent of what `IRoleService` does for you —
Identity doesn't refresh the stamp for claim changes either.

## Behaviour that will surprise you

These are deliberate. Each one exists because the obvious alternative tells an
attacker whether an account exists.

**Registering with an address that's already taken returns `Succeeded`.** No account
is created and the existing password is untouched; the *existing* address gets a
"someone tried to register" email instead. Reporting "that email is taken" would
confirm the account exists to whoever asked. Identity's own `DuplicateEmail` error
is never surfaced.

**A failed sign-in never says why.** Unknown address, wrong password, locked-out
account and unconfirmed account all return the same `AuthStatus.Failed`. Identity
decides "locked out" *before* it checks the password, so passing that through would
tell someone who doesn't know the password that the account exists. Lockout still
applies — it just isn't announced.

**Sign-in takes the same time whether or not the address exists.** Identity returns
early without hashing anything for an unknown user, which makes an unknown address
answer measurably faster than a real one. The library pays the hash anyway, so the
clock stays as quiet as the response.

**`RequestPasswordResetAsync` always returns `Succeeded`,** and does the lookup and
the send on a background worker. Awaiting an email only for addresses that exist
would answer "does this account exist" to anyone with a stopwatch. Consequences:
a send that fails is logged rather than returned, and queued mail is lost if the
process dies.

**A password-policy failure *is* reported.** It describes the password you just
typed, not who is registered, so it leaks nothing.

## Options

Everything defaults to the secure choice. `HttpOnly`, `Secure`, `Path=/` and the
CSRF check are **not** configurable — weakening them is a breaking security change,
not a convenience toggle.

```csharp
builder.Services.AddReusableAuth(options =>
{
    options.SessionLifetime = TimeSpan.FromHours(4);
    options.PasswordMinimumLength = 16;
});
```

| Option | Default | Notes |
| --- | --- | --- |
| `CookieName` | `__Host-auth` | Two-factor cookie names derive from this. |
| `CookieDomain` | `null` | Host-only. Incompatible with a `__Host-` prefix. |
| `CookieSameSite` | `Lax` | `None` is a real weakening. `Unspecified` is rejected. |
| `SessionLifetime` | 8 hours | |
| `SlidingExpiration` | `true` | |
| `LoginPath` | `null` | Set for MVC/Blazor; `null` answers `401`. |
| `AccessDeniedPath` | `null` | Set for MVC/Blazor; `null` answers `403`. |
| `SecurityStampValidationInterval` | 1 minute | Identity's default is 30 min. `Zero` checks every request. |
| `CsrfCookieName` | `__Host-csrf` | Must differ from `CookieName`. |
| `CsrfHeaderName` | `X-CSRF-TOKEN` | |
| `PasswordMinimumLength` | 12 | Below 8 is rejected. |
| `PasswordRequireDigit` | `true` | |
| `PasswordRequireLowercase` | `true` | |
| `PasswordRequireUppercase` | `true` | |
| `PasswordRequireNonAlphanumeric` | `true` | |
| `LockoutMaxFailedAttempts` | 5 | |
| `LockoutDuration` | 15 minutes | |
| `LockoutEnabledForNewUsers` | `true` | |
| `PasswordResetTokenLifetime` | 1 hour | Shorter than confirmation: a leaked reset link hands over the account. |
| `EmailConfirmationTokenLifetime` | 1 day | |
| `RequireConfirmedEmail` | `true` | |
| `RequireUniqueEmail` | `true` | |
| `BackgroundEmailQueueCapacity` | 1000 | Full queue applies backpressure. |

A contradictory or weakened configuration **fails at startup**, not at runtime — a
`__Host-` cookie with a `Domain`, a password floor below 8, a relative `LoginPath`,
a CSRF cookie sharing the session cookie's name.

## Entity Framework Core storage

Reference `Authentication.EntityFrameworkCore` and a database provider:

```csharp
builder.Services.AddDbContext<AppDbContext>(o => o.UseNpgsql(connectionString));
builder.Services.AddReusableAuth();
builder.Services.AddReusableAuthEntityFrameworkStores<AppDbContext>();
```

```csharp
public sealed class AppDbContext : ReusableAuthDbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

    // your own DbSets here
}
```

The store is **Microsoft's** — Identity's `UserOnlyStore`. This package only wires
it, supplies a context based on `IdentityUserContext` (so you don't get role tables
this library never uses), and fails at startup if the context can't actually store
your user type — Microsoft's own wiring accepts any `DbContext` and falls back
silently to something that breaks later.

Creates `AspNetUsers`, `AspNetUserClaims`, `AspNetUserLogins`, `AspNetUserTokens`,
`AspNetRoles`, `AspNetUserRoles`, `AspNetRoleClaims`. **Migrations are yours**, since
the library doesn't know your provider:

```bash
dotnet ef migrations add InitialAuth
dotnet ef database update
```

You don't have to use this package, but a custom store has to cover everything the
library composes: `IUserStore<TUser>`, `IUserSecurityStampStore<TUser>`,
`IUserRoleStore<TUser>` and `IRoleStore<IdentityRole>`. The core takes no EF
dependency.

## Your own user type

`AddReusableAuth()` uses a built-in `ReusableAuthUser`. For extra fields, derive
from `IdentityUser` and say so:

```csharp
public sealed class AppUser : IdentityUser
{
    public string? DisplayName { get; set; }
}

builder.Services.AddReusableAuth<AppUser>();
builder.Services.AddReusableAuthEntityFrameworkStores<AppUser, AppDbContext>();
```

```csharp
public sealed class AppDbContext : ReusableAuthDbContext<AppUser>
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }
}
```

## Local development and the `__Host-` cookie prefix

Cookies default to the `__Host-` prefix, which asks the browser itself to enforce
that the cookie is `Secure`, scoped to `/`, and carries no `Domain` — so a
compromised sibling subdomain cannot overwrite your session. Browsers enforce that
prefix **inconsistently over plain `http://localhost`**.

Best fix is HTTPS locally:

```bash
dotnet dev-certs https --trust
```

If you must run plain HTTP, override the cookie name in development only. The
two-factor cookie names derive from it, so they follow automatically:

```csharp
builder.Services.AddReusableAuth(options =>
{
    if (builder.Environment.IsDevelopment())
    {
        options.CookieName = "dev-auth";   // -> dev-auth-2fa, dev-auth-2fa-remember
        options.CsrfCookieName = "dev-csrf";
    }
});
```

`HttpOnly`, `Secure` and CSRF stay on in development. Only the *name* changes.

## What's Microsoft's, what's ours

| Concern | Whose code |
| --- | --- |
| Password hashing, `UserManager`, `SignInManager` | Microsoft |
| Cookie authentication handler | Microsoft |
| Antiforgery / CSRF | Microsoft |
| Security-stamp validation | Microsoft |
| Token providers (confirmation, reset) | Microsoft |
| EF Core store and `DbContext` base | Microsoft |
| `RoleManager` and role claims in the cookie | Microsoft |
| Background email queue | Microsoft's docs sample (MIT — see [THIRD-PARTY-NOTICES.txt](THIRD-PARTY-NOTICES.txt)) |
| Options, secure defaults, startup validation | Ours |
| Non-enumeration behaviour on top of Identity | Ours |
| Startup guard against a fail-open store | Ours |
| Refreshing the stamp so a role change actually revokes | Ours |
| DI wiring | Ours |

## Packages

| Package | Purpose |
| --- | --- |
| `Authentication` | Core: options, DI wiring, hardened cookie + CSRF, `IAuthService`, `IRoleService`, abstractions. |
| `Authentication.EntityFrameworkCore` | Optional. Wires Identity's EF Core store and supplies a `DbContext` base. |

## Building

```bash
dotnet build          # warnings are errors
dotnet test
dotnet format --verify-no-changes
```

## License

MIT — see [LICENSE](LICENSE). Third-party notices in
[THIRD-PARTY-NOTICES.txt](THIRD-PARTY-NOTICES.txt).
