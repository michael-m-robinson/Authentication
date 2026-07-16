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

**Pre-release (0.1.0).** Registration, sign-in (including two-factor), sign-out,
email confirmation, password reset, password change, change email, phone,
authenticator-app two-factor with recovery codes, session rotation and role
management all work and are tested. See [PLAN.md](PLAN.md) for what's left.

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
        // Password was right; now call auth.TwoFactorSignInAsync(code).
        break;
    case AuthStatus.PasswordRejected:
        // result.Errors holds the policy messages, safe to show.
        break;
    case AuthStatus.Failed:
        // Deliberately no reason. See below.
        break;
}
```

## Account settings

Inject `IAccountService` for a user's own settings.

### Changing email

Two steps, because the new address has to prove it's theirs before it becomes their
sign-in identity:

```csharp
// 1. emails a confirmation link to the NEW address
await account.RequestEmailChangeAsync(userId, "new@example.com");

// 2. from your confirmation page, with the values out of the link
await account.ConfirmEmailChangeAsync(userId, "new@example.com", token);
```

`RequestEmailChangeAsync` always reports success, even if the address already
belongs to someone else. That's deliberate: this library requires unique emails, so
answering "that address is taken" would let any signed-in user enumerate the user
base one address at a time. A taken address simply receives nothing.

### Phone

```csharp
await account.SetPhoneNumberAsync(userId, "+44 7700 900000");
```

> **The number is not verified.** Nothing here proves the user owns it — never treat
> it as a second factor or a recovery channel. Verifying means texting a code, and
> ASP.NET Core Identity has no SMS sender at all; Microsoft's own scaffolded page
> takes exactly the same position and calls the same unverified API.

### Two-factor (authenticator app)

```csharp
// 1. show the user a QR code (or the key, to type by hand)
TwoFactorSetup? setup = await account.BeginTwoFactorSetupAsync(userId);
// setup.AuthenticatorUri -> render as a QR code
// setup.SharedKey        -> show for manual entry

// 2. they scan it, then type a code back. Verified before it is switched on.
await account.EnableTwoFactorAsync(userId, code);

// 3. give them recovery codes. Show once; this is their only way back in.
IReadOnlyList<string> codes = await account.GenerateRecoveryCodesAsync(userId);
```

> `AuthenticatorUri` is a **URI, not an image**. Identity doesn't render QR codes and
> neither do we — use a client-side library. Microsoft's own page ships an empty
> `<div id="qrCode">` and a link to a doc saying the same.

The code is verified *before* two-factor is switched on, on purpose: enabling it for
an app that was never really configured locks the user out of their own account.

Then signing in takes a second step:

```csharp
AuthResult result = await auth.SignInAsync(email, password);

if (result.Status == AuthStatus.RequiresTwoFactor)
{
    await auth.TwoFactorSignInAsync(code);          // from their authenticator app
    // or, if they've lost it:
    await auth.RedeemRecoveryCodeAsync(recoveryCode);
}
```

Turning it off and cutting off a lost device are different things:

```csharp
await account.DisableTwoFactorAsync(userId);       // off; their app still works if re-enabled
await account.ResetAuthenticatorKeyAsync(userId);  // new key; the old app is now useless
```

`ResetAuthenticatorKeyAsync` also switches two-factor off — leaving it on with a key
nobody holds would lock the account. The user has to run setup again.

Recovery codes are spent as they're used, so it's worth showing how many are left:

```csharp
int left = await account.CountRecoveryCodesAsync(userId);
```

Every change here invalidates the user's other sessions within
`SecurityStampValidationInterval`. Identity does that itself for email, phone and
two-factor writes — unlike role changes, which need `IRoleService` to force it.

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
| `AuthenticatorIssuer` | `ReusableAuth` | Set to your app's name — users read it in their authenticator app. |
| `RequireUniqueEmail` | `true` | |
| `BackgroundEmailQueueCapacity` | 1000 | Full queue applies backpressure. |

A contradictory or weakened configuration **fails at startup**, not at runtime — a
`__Host-` cookie with a `Domain`, a password floor below 8, a relative `LoginPath`,
a CSRF cookie sharing the session cookie's name.

### From appsettings.json

Settings can live in configuration instead of code — `appsettings.json`,
environment variables, Key Vault, anything bound to `IConfiguration`:

```csharp
builder.Services.AddReusableAuth(builder.Configuration.GetSection("Auth"));
```

```json
{
  "Auth": {
    "SessionLifetime": "04:00:00",
    "PasswordMinimumLength": 16,
    "LockoutMaxFailedAttempts": 3,
    "AuthenticatorIssuer": "Contoso"
  }
}
```

Anything you don't set keeps its secure default, and the same startup validation
applies — a config file can't smuggle in a setup that a line of code would have been
rejected for. You can pass both, and code wins:

```csharp
builder.Services.AddReusableAuth(builder.Configuration.GetSection("Auth"), options =>
{
    options.LoginPath = "/Account/Login";   // beats the config file
});
```

> **Settings are read once, at startup. Editing configuration on a running app
> changes nothing until it restarts** — and that is not something this library can
> fix. ASP.NET Core Identity reads its own options through `IOptions<T>`, which
> resolves once and caches for the life of the process: `UserManager` captures the
> password and lockout policy in its constructor, `SecurityStampValidator` captures
> its interval, and the antiforgery service is a singleton holding a copy. None of
> them re-read anything, whatever the configuration does. It's a known framework
> issue ([dotnet/aspnetcore#55162](https://github.com/dotnet/aspnetcore/issues/55162))
> and the only real fix is upstream. Bind configuration to keep settings out of code
> and out of source control — not to change them without a restart.

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

## Adding your own data (alerts, likes, anything)

The library stops at authentication. Anything your app needs *about* a user —
alerts, likes, preferences, an audit trail — is yours to model, and Microsoft's
[documented way](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/customize-identity-model)
of doing it works unchanged here: put simple fields on your user type, and
everything list-shaped in its own table with a `UserId` foreign key.

### Simple fields go on the user

```csharp
public sealed class AppUser : IdentityUser
{
    public bool AlertsEnabled { get; set; } = true;
    public string? DisplayName { get; set; }
}

builder.Services.AddReusableAuth<AppUser>();
```

### Lists go in their own table

There is no standard .NET package for alerts or likes — ABP has no notification
module (only toast popups), and Orchard Core's is a CMS channel-preference system.
But there *is* a standard shape, arrived at independently by
[ASP.NET Boilerplate's notification system](https://aspnetboilerplate.com/Pages/Documents/Notification-System),
[Orchard Core](https://docs.orchardcore.net/en/latest/reference/modules/Notifications/)
and [ABP's CMS Kit reactions](https://abp.io/docs/en/abp/latest/Modules/Cms-Kit/Reactions).
Worth copying rather than reinventing.

**Alerts: split the event from the delivery.** One `Notification` row for the thing
that happened, one `UserNotification` row per recipient carrying *that person's*
read state. The obvious single-table shortcut — one row with a nullable `UserId`,
blank meaning "everyone" — falls over the moment two people need different read
state for the same alert.

```csharp
public sealed class Notification                 // the event: written once
{
    public int Id { get; set; }
    public string Message { get; set; } = "";
    public DateTimeOffset RaisedAt { get; set; }
}

public sealed class UserNotification             // the delivery: one row per recipient
{
    public int Id { get; set; }
    public int NotificationId { get; set; }
    public string UserId { get; set; } = "";
    public bool Read { get; set; }
    public DateTimeOffset? ReadAt { get; set; }
}
```

A global alert is then the same `Notification` fanned out to a `UserNotification`
per user — "fan-out-on-write". That's the right default: recipient counts are
small, and it's what makes per-person read state possible at all.

**Likes: a join table with a unique constraint.**

```csharp
public sealed class Like
{
    public int Id { get; set; }
    public string UserId { get; set; } = "";
    public string EntityType { get; set; } = "";   // "Article", "Comment", ...
    public string EntityId { get; set; } = "";
}
```

The unique index is doing two jobs: one like per person per thing, and free
idempotency — a double-submitted like violates the constraint, which you catch and
treat as a no-op rather than double-counting. Keep a denormalised `LikeCount` on the
parent once `COUNT(*)` stops being cheap.

Hang them off your context alongside the auth tables:

```csharp
public sealed class AppDbContext : ReusableAuthDbContext<AppUser>
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

    public DbSet<Notification> Notifications => Set<Notification>();
    public DbSet<UserNotification> UserNotifications => Set<UserNotification>();
    public DbSet<Like> Likes => Set<Like>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);   // <- do not omit: this builds the auth tables

        modelBuilder.Entity<Like>()
            .HasIndex(l => new { l.UserId, l.EntityType, l.EntityId })
            .IsUnique();
    }
}
```

> Forgetting `base.OnModelCreating(modelBuilder)` silently drops the entire Identity
> schema — no error, just no auth tables in your next migration.

```bash
dotnet ef migrations add AddAlertsAndLikes
dotnet ef database update
```

Then write whatever API reads best for you — it's your domain, so nothing here
constrains it:

```csharp
public sealed class AlertService(AppDbContext db, IAuthService auth)
{
    public async Task AddForUserAsync(string userId, string message)
    {
        Notification alert = new() { Message = message, RaisedAt = DateTimeOffset.UtcNow };
        db.Notifications.Add(alert);
        db.UserNotifications.Add(new UserNotification { Notification = alert, UserId = userId });

        await db.SaveChangesAsync();   // one transaction: the alert and its delivery
    }

    public Task<List<UserNotification>> UnreadForCurrentUserAsync()
    {
        string? userId = auth.CurrentPrincipal?.FindFirstValue(ClaimTypes.NameIdentifier);

        return db.UserNotifications.Where(n => n.UserId == userId && !n.Read).ToListAsync();
    }
}
```

Turning a feature off is then a plain property on your own user — no library flag
needed, and no schema you don't want:

```csharp
if (user.AlertsEnabled)
{
    await alerts.AddForUserAsync(user.Id, "Something happened.");
}
```

**If you want them live**, persist first and push second: write the rows, then
signal over [SignalR](https://learn.microsoft.com/en-us/aspnet/core/signalr/introduction)
with `Clients.User(userId)`, which reaches every tab that person has open. SignalR is
transport, not storage — a disconnected client misses the push, so the database write
is what makes the alert real. Microsoft's
[social-style notifications walkthrough](https://learn.microsoft.com/en-us/archive/msdn-magazine/2018/august/cutting-edge-social-style-notifications-with-asp-net-core-signalr)
covers the shape. If the alert has to survive a crash between the business write and
the publish, that's the
[transactional outbox](https://microservices.io/patterns/data/transactional-outbox.html) —
the same pattern
[Microsoft's own microservices guidance](https://learn.microsoft.com/en-us/dotnet/architecture/microservices/multi-container-microservice-net-applications/integration-event-based-microservice-communications)
recommends.

### Why this isn't in the library

Identity has no notion of alerts or likes, and neither does this library, on
purpose. They are your domain, not authentication's — a package that shipped them
would push a schema onto every consumer that wanted none of it, and would make an
auth library carry code that has nothing to do with auth. A flag would not help:
`AlertsEnabled = false` still ships the tables, the types and the migration.

Nor is there a package to defer to. The .NET ecosystem has no dominant library for
either — ABP's own support forum tells people to build notifications themselves, and
likes are hand-rolled everywhere. What exists is the *pattern* above, which is why it
is documented here rather than implemented here. Microsoft's guidance for
app-specific user data says the same thing: subclass, add your own tables.

> **Don't put this kind of data in claims.** Claims are serialised into the auth
> cookie and re-sent on *every* request. A growing list — every alert, every like —
> inflates that cookie until it is chunked across multiple `Set-Cookie` headers
> (`ChunkingCookieManager` splits at ~4050 characters) and eventually until the
> browser rejects it outright with `400 Bad Request - Request Header Or Cookie Too
> Large`. Claims are for small, stable facts about identity. Lists belong in a
> table, fetched by user id.

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
| TOTP two-factor, authenticator keys, recovery codes | Microsoft |
| The `otpauth://` setup URI and key formatting | Microsoft's scaffolded Identity UI (MIT) |
| Background email queue | Microsoft's docs sample (MIT — see [THIRD-PARTY-NOTICES.txt](THIRD-PARTY-NOTICES.txt)) |
| Options, secure defaults, startup validation | Ours |
| Non-enumeration behaviour on top of Identity | Ours |
| Startup guard against a fail-open store | Ours |
| Refreshing the stamp so a role change actually revokes | Ours |
| DI wiring | Ours |

## Packages

| Package | Purpose |
| --- | --- |
| `Authentication` | Core: options, DI wiring, hardened cookie + CSRF, `IAuthService`, `IAccountService`, `IRoleService`, abstractions. |
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
