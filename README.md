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
security-reviewed parts: the password hasher, the cookie handler, the token
providers, the EF Core store. This library wires them together with secure
defaults, closes the places Identity leaks information by default, and refuses to
start when it's configured into something unsafe. It contains no cryptography,
persistence or session handling of its own. See
[What's Microsoft's, what's ours](#whats-microsofts-whats-ours).

## Status

**Pre-release (0.1.0).** Registration, sign-in (including two-factor), sign-out,
email confirmation, password reset, password change, change email, phone,
authenticator-app two-factor with recovery codes, session rotation and role
management all work and are tested. [Likes and alerts](#likes-and-alerts) ship
separately in `Authentication.Social`, for apps that want them. See
[PLAN.md](PLAN.md) for what's left.

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
package. See [below](#entity-framework-core-storage), which gives you Microsoft's
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

Tokens arrive **URL-safe**, so drop them straight into a query string and pass them
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

Two steps, because the new address has to prove it's the user's before it becomes
their sign-in identity:

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

> **The number is not verified.** Nothing here proves the user owns it, so never treat
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
> neither do we, so use a client-side library. Microsoft's own page ships an empty
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

`ResetAuthenticatorKeyAsync` also switches two-factor off, because leaving it on with a key
nobody holds would lock the account. The user has to run setup again.

Recovery codes are spent as they're used, so it's worth showing how many are left:

```csharp
int left = await account.CountRecoveryCodesAsync(userId);
```

Every change here invalidates the user's other sessions within
`SecurityStampValidationInterval`. Identity does that itself for email, phone and
two-factor writes, unlike role changes, which need `IRoleService` to force it.

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
stamp when a password changes but **not** when roles change, so a plain
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
it already holds. There's no anonymous caller to disclose anything to.

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

`RotateSessionAsync` is the manual equivalent of what `IRoleService` does for you:
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
applies, it just isn't announced.

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
CSRF check are **not** configurable. Weakening them is a breaking security change,
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
| `AuthenticatorIssuer` | `ReusableAuth` | Set to your app's name; users read it in their authenticator app. |
| `RequireUniqueEmail` | `true` | |
| `BackgroundEmailQueueCapacity` | 1000 | Full queue applies backpressure. |

A contradictory or weakened configuration **fails at startup**, not at runtime: a
`__Host-` cookie with a `Domain`, a password floor below 8, a relative `LoginPath`,
a CSRF cookie sharing the session cookie's name.

### From appsettings.json

Settings can live in configuration instead of code, whether that's `appsettings.json`,
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
applies, so a config file can't smuggle in a setup that a line of code would have been
rejected for. You can pass both, and code wins:

```csharp
builder.Services.AddReusableAuth(builder.Configuration.GetSection("Auth"), options =>
{
    options.LoginPath = "/Account/Login";   // beats the config file
});
```

> **Settings are read once, at startup. Editing configuration on a running app
> changes nothing until it restarts**, and that is not something this library can
> fix. ASP.NET Core Identity reads its own options through `IOptions<T>`, which
> resolves once and caches for the life of the process: `UserManager` captures the
> password and lockout policy in its constructor, `SecurityStampValidator` captures
> its interval, and the antiforgery service is a singleton holding a copy. None of
> them re-read anything, whatever the configuration does. It's a known framework
> issue ([dotnet/aspnetcore#55162](https://github.com/dotnet/aspnetcore/issues/55162))
> and the only real fix is upstream. Bind configuration to keep settings out of code
> and out of source control, not to change them without a restart.

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

The store is **Microsoft's** own `UserOnlyStore`. This package only wires
it, supplies a context based on `IdentityUserContext` (so you don't get role tables
this library never uses), and fails at startup if the context can't actually store
your user type. Microsoft's own wiring accepts any `DbContext` and falls back
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

## Likes and alerts

Reference `Authentication.Social`. Likes are keyed to the signed-in Identity user
and to whatever content your app has, and liking someone's content tells them.

Three things to wire: the tables onto your context, the services into your
container, and an `IContentSource` so the library knows what your content is.

```csharp
public sealed class AppDbContext : ReusableAuthDbContext<AppUser>
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);   // <- the auth tables
        modelBuilder.AddReusableAuthSocial(); // <- likes and alerts
    }
}
```

```csharp
builder.Services.AddReusableAuthSocial<AppDbContext, MyContentSource>();
```

```bash
dotnet ef migrations add AddLikesAndAlerts
dotnet ef database update
```

The tables go on *your* context, next to the auth tables. Posting a like raises the
alert that goes with it, and both are written in one transaction.

Then inject `ILikeService` and `IAlertService`:

```csharp
LikeResult result = await likes.LikeAsync(userId, ContentTypes.Article, 42, ct);

result.IsLiked;           // true
result.LikeCount;         // 1
result.ContentAvailable;  // false if the content isn't this user's to see

await likes.UnlikeAsync(userId, ContentTypes.Article, 42, ct);
await likes.GetAsync(userId, ContentTypes.Article, 42, ct);
```

`ContentTypes` is a class of your own, holding the names of the things your app has.
[Naming your content types](#naming-your-content-types) below shows it.

```csharp
AlertPage page = await alerts.GetAsync(userId, beforeId: null, limit: 20, ct);
int unread = await alerts.CountUnreadAsync(userId, ct);

await alerts.MarkAsReadAsync(userId, alertId, ct);
await alerts.MarkAllAsReadAsync(userId, ct);
```

Every method takes a user id, and every one filters on it in the query, so there is
no id a caller can pass to reach someone else's likes or alerts. That holds only if
the id is the signed-in user's, so take it from the cookie and never from the
request:

```csharp
string? userId = auth.CurrentPrincipal?.FindFirstValue(ClaimTypes.NameIdentifier);
```

An id from a form field, a query string or a JSON body is a value the caller chose,
and passing one here hands them everyone else's alerts.

`GetAsync` pages by cursor: pass the `NextCursor` from the previous page as
`beforeId`, and stop when it comes back `null`. Cursors rather than page numbers,
because alerts arrive while someone is reading them, and page 2 of an offset-paged
list quietly repeats a row every time a new alert lands.

### Naming your content types

The library takes the kind of thing as a string, because it has never heard of your
content: `Article`, `Comment` and `Recipe` are your vocabulary, not the library's.
Written as a literal, that string is a quiet bug waiting to happen. `"Artcile"`
reaches your `IContentSource`, matches nothing, and comes back as content that isn't
available: no exception, just a like button that does nothing.

So name them once, in your own code, and never write the literal again:

```csharp
public static class ContentTypes
{
    public const string Article = "Article";
    public const string Comment = "Comment";
}

await likes.LikeAsync(userId, ContentTypes.Article, 42, ct);
```

The compiler now catches the typo. The constants also work in a `switch`, which an
`IContentSource` covering several types will want.

**Not an enum, and not one the library ships.** The library can't declare an enum of
types it has never heard of, so it would have to be yours, and it would have to
become a string at the boundary anyway. That conversion is the whole problem:
`((int)kind).ToString()` writes `"0"` into the column, and the day anyone reorders
the enum, every like already stored changes meaning. Constants are the same text in
your code and in the database, with nothing to convert and nothing to reorder. It's
the call the library already makes for `AlertTypes`, for the same reason.

If you want an enum for your own code, keep it away from the column and pass
`nameof`:

```csharp
await likes.LikeAsync(userId, nameof(ContentKind.Article), 42, ct);
```

The stored value is then the name rather than the ordinal, so it survives the enum
being reordered.

### Telling your users what happened

Alerts carry no message text. A `UserAlert` records *what* happened, who did it and
to which content, and your app decides what that reads like:

```csharp
public sealed class UserAlert
{
    public long Id { get; set; }
    public required string RecipientUserId { get; set; }  // who is being told
    public string? ActorUserId { get; set; }              // who did it, if anyone
    public required string AlertType { get; set; }        // AlertTypes.ContentLiked, ...
    public string? RelatedContentType { get; set; }
    public long? RelatedContentId { get; set; }
    public bool IsRead { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? ReadAt { get; set; }
}
```

A stored string would be wrong in every language but the one that wrote it, would
freeze the wording at the moment the alert was raised, and would be one more place
for user-supplied text to end up rendered as HTML. Keeping alerts as facts means you
can translate them, restyle them, or show a like as an avatar instead of a sentence.

Raise your own alongside the library's, on the same table:

```csharp
await alerts.CreateAsync(new CreateAlertRequest(
    RecipientUserId: article.AuthorId,
    AlertType: AlertTypes.ContentCommented,
    ActorUserId: currentUserId,
    RelatedContentType: ContentTypes.Article,
    RelatedContentId: article.Id), ct);
```

`AlertTypes` names the ones the library knows about, but the field is a plain string:
your own types are as valid as the library's.

**If you want them live**, persist first and push second: `CreateAsync` writes the
row, then signal over
[SignalR](https://learn.microsoft.com/en-us/aspnet/core/signalr/introduction) with
`Clients.User(userId)`, which reaches every tab that person has open. SignalR is
transport, not storage. A disconnected client misses the push, so the database write
is what makes the alert real. Microsoft's
[social-style notifications walkthrough](https://learn.microsoft.com/en-us/archive/msdn-magazine/2018/august/cutting-edge-social-style-notifications-with-asp-net-core-signalr)
covers the shape.

### Who gets told, and how often

One alert per person per item, ever. Someone who likes, unlikes and likes again does
not ring your bell twice, which is a thing people do idly and a thing they can do
deliberately: without the rule, a like button is a way to notify a stranger as many
times as they can click.

The alert stays after the like is removed. It is a record that something happened,
and it did.

Liking your own content tells nobody.

### Describing your content

The library has no idea what your content is, so you tell it. Implement
`IContentSource`, which is the only thing standing between a like request and your
database:

```csharp
public sealed class MyContentSource(AppDbContext db) : IContentSource
{
    public async Task<ContentInfo?> GetAsync(
        string userId, string contentType, long contentId, CancellationToken ct)
    {
        if (contentType != ContentTypes.Article)
        {
            return null;
        }

        Article? article = await db.Articles
            .SingleOrDefaultAsync(a => a.Id == contentId && !a.IsDeleted, ct);

        if (article is null || !article.IsVisibleTo(userId))
        {
            return null;
        }

        return new ContentInfo(article.AuthorId, SupportsLikes: true);
    }
}
```

The user id is passed in so you can answer "may *this* person see it?", and
`ContentInfo.OwnerUserId` names whoever gets the alert. Return an empty owner for
content nobody owns, like a site-wide announcement: the like still counts, and there
is nobody to tell.

### Likes are opt-in, per item

`ContentInfo.SupportsLikes` **defaults to `false`**. This refuses likes:

```csharp
return new ContentInfo(article.AuthorId);                      // not likeable
return new ContentInfo(article.AuthorId, SupportsLikes: true); // likeable
```

The default is the safe direction rather than the convenient one. Add a new content
type and forget to set it, and you get content nobody can like: visible, harmless,
and obvious the first time someone tries. The other default would give you content
quietly accepting likes it was never meant to have, which nobody notices.

### Return `null` for anything the user can't have

Content that doesn't exist, was deleted, is hidden, is a draft, or simply isn't
theirs to see: all `null`. **Do not distinguish between them.**

That is the whole point of the method's shape. If "no such thing" and "not for you"
gave different answers, liking becomes a way to ask whether an id exists, and a
caller can walk the ids to map out content they aren't allowed to read. One answer
for both leaves nothing to learn. It's the same reasoning that makes a failed
sign-in refuse to say which part was wrong.

`IContentSource` is called when someone likes something, and **not** when they
unlike it: removing your own like shouldn't be blocked because the content was
deleted or hidden since you liked it.

## Adding your own data

Anything else your app needs *about* a user (preferences, an audit trail, a profile)
is yours to model, and Microsoft's
[documented way](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/customize-identity-model)
of doing it works unchanged here: put simple fields on your user type, and
everything list-shaped in its own table with a `UserId` foreign key.

### Simple fields go on the user

```csharp
public sealed class AppUser : IdentityUser
{
    public string? DisplayName { get; set; }
    public string? TimeZoneId { get; set; }
}

builder.Services.AddReusableAuth<AppUser>();
```

### Lists go in their own table

Hang them off your context alongside the auth tables, and chain up to the base:

```csharp
public sealed class AppDbContext : ReusableAuthDbContext<AppUser>
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

    public DbSet<AuditEntry> AuditEntries => Set<AuditEntry>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);   // <- do not omit: this builds the auth tables

        modelBuilder.Entity<AuditEntry>()
            .HasIndex(e => new { e.UserId, e.OccurredAt });
    }
}
```

> Forgetting `base.OnModelCreating(modelBuilder)` silently drops the entire Identity
> schema. No error, just no auth tables in your next migration.

```bash
dotnet ef migrations add AddAuditEntries
dotnet ef database update
```

One context for your tables and the auth tables means your write and the user it
belongs to share a transaction. It's also why `AddReusableAuthSocial` goes on this
same context rather than one of its own.

Key your rows to `user.Id`, the Identity user id, and not to a username or email
address. Both of those are things a user can change, and a row keyed to one is a row
that belongs to whoever holds that name next.

> **Don't put this kind of data in claims.** Claims are serialised into the auth
> cookie and re-sent on *every* request. A growing list (every alert, every like)
> inflates that cookie until it is chunked across multiple `Set-Cookie` headers
> (`ChunkingCookieManager` splits at ~4050 characters) and eventually until the
> browser rejects it outright with `400 Bad Request - Request Header Or Cookie Too
> Large`. Claims are for small, stable facts about identity. Lists belong in a
> table, fetched by user id.

## Local development and the `__Host-` cookie prefix

Cookies default to the `__Host-` prefix, which asks the browser itself to enforce
that the cookie is `Secure`, scoped to `/`, and carries no `Domain`, so a
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
| Background email queue | Microsoft's docs sample (MIT; see [THIRD-PARTY-NOTICES.txt](THIRD-PARTY-NOTICES.txt)) |
| Options, secure defaults, startup validation | Ours |
| Non-enumeration behaviour on top of Identity | Ours |
| Startup guard against a fail-open store | Ours |
| Refreshing the stamp so a role change actually revokes | Ours |
| Likes, alerts, and the content gate in front of them | Ours |
| DI wiring | Ours |

## Packages

| Package | Purpose |
| --- | --- |
| `Authentication` | Core: options, DI wiring, hardened cookie + CSRF, `IAuthService`, `IAccountService`, `IRoleService`, abstractions. |
| `Authentication.EntityFrameworkCore` | Optional. Wires Identity's EF Core store and supplies a `DbContext` base. |
| `Authentication.Social` | Optional. Likes and alerts on your own `DbContext`: `ILikeService`, `IAlertService`, `IContentSource`. |

## Building

```bash
dotnet build          # warnings are errors
dotnet test
dotnet format --verify-no-changes
```

## License

MIT. See [LICENSE](LICENSE) for the terms, and third-party notices in
[THIRD-PARTY-NOTICES.txt](THIRD-PARTY-NOTICES.txt).
