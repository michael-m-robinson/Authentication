# Plan — reusable, project-agnostic Microsoft Identity auth library

**Goal:** a NuGet-packaged .NET 10 library that any ASP.NET Core app can drop in to
get a hardened authentication model, an **httpOnly + Secure + SameSite session
cookie** with **double-submit CSRF**, built on ASP.NET Core Identity. No
app-specific assumptions: storage is supplied by the host, behaviour is set
through options, and every integration point is an interface the host can replace.

## Design principles

- **Generic first.** The core library depends only on
  `Microsoft.AspNetCore.Identity` + `Microsoft.AspNetCore.Authentication.Cookies`
  abstractions, never on a concrete DbContext, email provider, or app.
- **Composed through DI + options.** One entry point,
  `services.AddReusableAuth(options => ...)`, wires everything with secure
  defaults; the host overrides only what it needs.
- **Secure by default, hard to misconfigure.** Hardened cookie + CSRF + framework
  password hasher are the defaults; weakening them takes deliberate opt-out.
- **Host owns policy it must own.** Persistence and email delivery are interfaces
  the host implements; the library never picks a database or an SMTP provider.
- **Build on trusted packages, not hand-rolled code.** Where a trusted, secure,
  well-maintained NuGet package exists (first-party `Microsoft.*` first), use it
  rather than writing our own, above all for security-sensitive work. Balanced
  against a minimal dependency surface: prefer the framework over a package.
  Binding detail in `rules/security.md`.

## Package layout

- `Authentication` (core) — options, DI extensions, cookie + CSRF configuration,
  auth services, and the abstraction interfaces. Depends only on Identity/cookie
  abstractions.
- `Authentication.EntityFrameworkCore` (v1, optional to reference) — wires
  Identity's own EF Core store, plus a correctly-based `DbContext` and a fail-fast
  startup check. It contains no store logic of ours; Microsoft's is already
  security-reviewed and satisfies the stamp guard. Kept separate so the core stays
  storage-agnostic and takes no EF dependency.
**The library exposes no HTTP endpoints.** An earlier draft planned an
`Authentication.Endpoints` package with `MapAuthEndpoints()`; that is dropped.
Shipping endpoints would both hand hosts an HTTP surface they did not ask for and
assume minimal APIs, which is the opposite of dropping into an existing MVC or
Blazor app. The library is methods you call — the host owns its own routes, pages,
components and HTTP shape.

That places the burden on the methods: each one is expected to be *complete*, so a
host calling `AddToGroupAsync` gets the persistence, the claim refresh and the
session rotation without knowing those are separate concerns.

## Public surface (initial)

- `AddReusableAuth(this IServiceCollection, Action<ReusableAuthOptions>)` — the DI
  entry point, over the built-in `ReusableAuthUser`. Registers Identity, the
  hardened cookie scheme, antiforgery/CSRF, and the auth services.
- `AddReusableAuth<TUser>(this IServiceCollection, Action<ReusableAuthOptions>)`
  where `TUser : IdentityUser<string>` — same wiring for a host-supplied user type.
- `ReusableAuthUser : IdentityUser<string>` — the minimal built-in user. Adds
  nothing beyond Identity's own fields; hosts needing more subclass it.
- `ReusableAuthOptions` — cookie name/domain/SameSite/expiration, sliding
  expiration, password policy, lockout policy, CSRF header + cookie names,
  require-confirmed-email toggle. All with secure defaults.
- `IAuthService` — register, sign-in (with lockout), sign-out, current principal,
  change/reset password, confirm email. Returns result types, never throws for
  expected auth failures.
- `IUserStoreAdapter<TUser>` / rely on Identity's `IUserStore<TUser>` — host plugs
  in persistence; the EF package (in v1) provides the default.
- `ISessionRotator` — re-issues the session cookie on sign-in and on privilege
  change. Internal by default; public only if a host must trigger rotation itself.
- `IAuthEmailSender` — host implements delivery of confirmation/reset links; the
  library only generates the tokens, it never sends mail itself.
- Group membership over Identity's own `RoleManager` — create/delete a group, add
  and remove members, list them. Fully featured: role changes do not refresh the
  security stamp in Identity, so these methods do it, or a revoked member keeps
  their access until the cookie expires.
- Per-user settings — change email (with re-confirmation), phone, two-factor,
  claims. Each does the whole job, rotating the session where the change is a
  privilege change.
- `LoginPath` / `AccessDeniedPath` options — set them and the cookie redirects, as
  MVC and Blazor expect; leave them unset and it answers 401/403, as an API wants.

## Security invariants (do not regress)

- Session is an httpOnly + Secure + SameSite cookie; **no tokens in JS/local
  storage**, ever.
- Session is rotated (new identifier issued, old one invalidated) on sign-in and
  on any privilege change; a pre-escalation cookie never stays valid.
- CSRF via double-submit cookie + antiforgery; unsafe methods require the header.
- Framework password hasher only; constant-time comparison for token checks.
- Generic failures on auth errors, no user-enumeration, no leaking why a token
  failed.
- Never log passwords, tokens, cookie values, or PII. Ship no secrets in the
  package; the host supplies all keys/connection strings via config.

(These mirror `rules/security.md` and `rules/code-quality.md`, treat those as the
binding source.)

## Milestones

1. **Scaffold** — *done (0.1.0).* `Class1` removed; `Authentication.sln` +
   xUnit `Authentication.Tests`; analyzers, warnings-as-errors and shared package
   metadata in `Directory.Build.props`; MIT `LICENSE` + packaged `README.md`;
   `NuGet.config` pinned to nuget.org with `packageSourceMapping`; repo
   initialised (`main`, working on `testing`). Gate green: format clean, build
   0 warnings, 1 test passing, `dotnet pack` produces a valid nupkg + snupkg.
   Outstanding: `RepositoryUrl`/`PublishRepositoryUrl` + Source Link need a
   remote.
2. **Options + DI core** — *done.* `ReusableAuthOptions` (secure defaults, startup
   validation) and `AddReusableAuth` wiring Identity, the hardened cookie, the 2FA
   schemes and antiforgery. 25 tests. Research against the aspnetcore source caught
   three defects worth recording:
   - `OnValidatePrincipal` was unwired, so the security stamp was never checked and
     session invalidation did not exist at all. `AddIdentity` does this for you; we
     do not use `AddIdentity`, so we must.
   - Identity fails *open* when a store lacks `IUserSecurityStampStore<TUser>`:
     `ValidateSecurityStampAsync` silently returns true. `SecurityStampStoreGuard`
     now refuses to boot instead.
   - The regression test for the first defect passed with the fix removed, because
     `CookieAuthenticationEvents.OnValidatePrincipal` defaults to a non-null no-op.
     Assert delegate identity, never null-ness. Mutation-tested both ways.
   Also: `SecurityStampValidationInterval` defaults to 1 minute, not Identity's 30.
3. **Auth services** — *done.* `IAuthService` + `AuthService`, `IAuthEmailSender`,
   background email delivery, and the reset/confirm token lifetime split. 65 tests
   against an in-memory store; the security-critical assertions are
   mutation-tested (each fails when its fix is removed).
   Identity's disclosure defaults that had to be undone, all confirmed in source:
   - `PasswordSignInAsync` skips hashing entirely for an unknown user, so an
     unknown address answers faster than a real one. Every path that skips
     verification now pays the hash.
   - `LockedOut`/`NotAllowed` are decided *before* the password check, so both
     announce an account exists to someone who does not know its password. They
     collapse into the generic failure.
   - `CreateAsync` surfaces `DuplicateEmail`; registration reports success for a
     taken address and notifies the owner by email instead.
   - `ConfirmEmailAsync` does not rotate the stamp; we do, since confirmation is
     a privilege change.
   Password reset queues the address and returns — awaiting SMTP only for
   addresses that exist was a stopwatch-visible existence oracle, whatever the
   response body said. Background delivery and the token split both use
   Microsoft's official samples (MIT, see `THIRD-PARTY-NOTICES.txt`).
   Still open: `RotateSessionAsync` is covered only for the signed-out case. The
   test PLAN.md asks for — a pre-change cookie ceasing to authenticate — needs a
   real request pipeline, so it belongs with the consumer smoke test in
   milestone 7.
4. **EF Core store package** — *done, and smaller than planned.* This milestone
   said "a ready-made EF Core Identity store". We do not write one: ASP.NET Core
   Identity already ships `UserOnlyStore`, which implements every store interface
   this library needs — `IUserSecurityStampStore` included, so it satisfies the
   startup guard — and Microsoft security-reviews it every release. Writing our own
   would mean re-implementing concurrency-stamp handling and personal-data
   protection for credential storage: the store equivalent of hand-rolling a
   password hasher, which `rules/code-quality.md` forbids.
   So `Authentication.EntityFrameworkCore` is a thin wrapper holding only:
   - `ReusableAuthDbContext<TUser>` over `IdentityUserContext<TUser, string>`, not
     `IdentityDbContext` — which would add `AspNetRoles`, `AspNetUserRoles` and
     `AspNetRoleClaims` plus a required FK that this library never uses.
   - `AddReusableAuthEntityFrameworkStores<TUser, TContext>()`, which calls
     Microsoft's `AddEntityFrameworkStores` through a locally-built
     `IdentityBuilder` (its constructor is public), keeping `IdentityBuilder` out
     of our API.
   - A startup check that `TContext` really is an `IdentityUserContext` for
     `TUser`. Microsoft's accepts any `DbContext` and silently falls back to a
     POCO-bound store that fails later inside EF; fail-fast matches
     `rules/security.md`.
   8 tests over Sqlite (not the InMemory provider, which enforces no relational
   constraints).
   Note: pinned `SQLitePCLRaw.bundle_e_sqlite3` 2.1.12 in the EF test project.
   EF Core Sqlite 10.0.10 still floors at 2.1.11, which carries CVE-2025-6965
   (memory corruption in SQLite itself). Test-only and not reachable by our tests,
   but `rules/ci-scanning.md` fails on any known-vulnerable dependency. Remove the
   pin once EF Core ships a patched floor (dotnet/efcore#38257).
   Migrations remain the host's; the README covers it.
5. **Host-agnostic challenge** — `LoginPath`/`AccessDeniedPath` options. Milestone 2
   hard-coded 401/403 on the reasoning that "a library has no login page to
   redirect to". True of an API, wrong for MVC and Blazor, where a challenge is
   expected to redirect — so an MVC app cannot currently drop this in. Unset still
   means 401/403.
6. **Roles** — *done.* `IRoleService` over Identity's `RoleManager`: create, delete,
   add a member, remove a member, and the lookups. Named "role", not "group", to
   match `[Authorize(Roles = ...)]` and every Identity doc rather than layer a
   synonym over them. 113 tests; the stamp-refresh assertions are mutation-tested
   against both a fake and a real database.
   Three things the research turned up, each of which would have shipped broken:
   - **The EF context had to change base.** `AddEntityFrameworkStores` decides which
     store to wire by looking for an `IdentityDbContext` ancestor. Milestone 4's
     `IdentityUserContext` is its *base*, not that type, so the check failed and it
     silently registered a store reaching for role entities the model had never
     heard of — an EF error on the first role call, no compile error, no migration.
     `ReusableAuthDbContext` now derives from `IdentityDbContext<TUser, IdentityRole,
     string>`, restoring the three tables milestone 4 removed.
   - **The role type has to be passed to `IdentityBuilder`.** With `RoleType` null,
     Microsoft's wiring registers no role store at all, so `RoleManager` cannot
     resolve and the host fails to build its container. A test caught this.
   - **`AddToRoleAsync` against a missing role throws a raw
     `InvalidOperationException`** out of the EF store rather than returning a failed
     result — a 500 where `rules/security.md` wants a handled failure. `RoleService`
     checks first.
   Consequence worth knowing: roles are not optional. Turning them on swaps in the
   role-aware claims factory, so every host must now supply an `IRoleStore` — free
   with the EF package, real work for a custom store.
   `AuthStatus.Rejected` was added for this: role failures *are* explained, because
   they are administrative calls made by the host's own code about an id it already
   holds, with no anonymous caller to disclose anything to.
7. **Per-user settings** — *done.* `IAccountService`: change email (re-confirming the
   new address), phone, and authenticator-app two-factor with recovery codes. Plus
   `TwoFactorSignInAsync`/`RedeemRecoveryCodeAsync` on `IAuthService`. 147 tests.
   Unlike roles, Identity refreshes the security stamp itself on all of these, so
   nothing here has to force it.
   What the research changed:
   - **The recorded stamp list was wrong.** Milestone 3 noted 10 methods that bump
     the stamp; there are 11. `ResetAuthenticatorKeyAsync` was missing — which is
     exactly the one two-factor depends on.
   - **Two-factor was a dead end.** `SignInAsync` returned `RequiresTwoFactor` with
     nothing able to complete it, so any host enabling 2FA locked its users out. The
     two new sign-in members close that.
   - **Change-email is an enumeration risk for us specifically.** Identity defaults
     `RequireUniqueEmail` to false so `DuplicateEmail` never fires; we set it true, so
     it does. `RequestEmailChangeAsync` therefore mints and sends unconditionally and
     always reports success, mirroring Microsoft's own page; the duplicate is refused
     later, out of band, generically.
   - **Identity's `ChangeEmailAsync` moves `Email` but not `UserName`.** Since the
     user name is the sign-in identity here, leaving it behind would mean users kept
     signing in with their old address. `ConfirmEmailChangeAsync` moves both.
   - **Phone is set, not verified**, matching Microsoft's own scaffold. Identity has no
     SMS sender of any kind; its phone token provider computes a code and sends
     nothing. Documented rather than faked.
   Claims are deliberately left to `UserManager` + `RotateSessionAsync`, which the
   README covers — they need no service of their own.
8. **Runtime configuration** — *dropped; replaced with configuration binding.* The
   feature cannot be built correctly, and the reason is architectural rather than
   effort:
   - `UserManager` captures `IOptions<IdentityOptions>.Value` in its constructor, and
     `IOptions<T>` resolves once and caches for the process lifetime. Being scoped
     does not help — every new instance reads the same frozen singleton. Password
     policy and lockout are fixed at first use. Known open framework bug:
     dotnet/aspnetcore#55162.
   - `SecurityStampValidator` does the same with a get-only property, so the
     revalidation interval is fixed too.
   - `DefaultAntiforgery` is a *singleton* holding a `readonly` copy — fixed hardest
     of all.
   - Cookie options *could* reload (the handler calls `OptionsMonitor.Get(scheme)`
     every request), but stock `AddCookie` registers no change-token source, so
     nothing fires.
   - And our own `.Configure<IOptions<ReusableAuthOptions>>(...)` pattern is frozen
     regardless: the dependency is `IOptions`, so the delegate would hand any
     recomputed target startup-time values anyway.
   Making it work would mean replacing `UserManager`, the validators and the stamp
   validator with our own — hand-rolling the security-critical pieces Microsoft ships
   and reviews, for a feature the framework may fix upstream. A partial version was
   rejected as worse than none: a library where `SessionLifetime` reloads but
   `PasswordMinimumLength` silently does not is a trap, because the two look identical
   at the call site.
   *Instead:* `AddReusableAuth(IConfiguration)` binds settings from
   `appsettings.json`, environment variables or a secret store — Microsoft's official
   options pattern, through the same startup validation, with code overriding
   configuration. Documented as startup-only, with a test asserting that a runtime
   change is ignored. That test doubles as a tripwire: if it ever fails, the framework
   has been fixed and the docs need updating.
9. **CI + packaging** — Actions: build (warnings-as-errors) + test + Semgrep +
   Sonar + vulnerable-package scan + emailed summary; `dotnet pack`/`push` on a
   tagged release (`rules/ci-scanning.md`, `rules/packaging.md`).
10. **Consumer smoke test** — *done.* `Authentication.SmokeTests` stands up a real
    ASP.NET Core pipeline in-process (TestHost), wired exactly as the README tells a
    host to wire one, and drives it over HTTP with the cookie a browser would hold.
    8 tests: register → confirm → login → me → logout; the cookie is `HttpOnly`,
    `Secure`, `Path=/` *on the wire* rather than merely in an options object; sign-out
    expires it rather than ignoring it; an unauthenticated request gets 401 and not a
    redirect; and a wrong password is indistinguishable from an unknown account down
    to the absent `Set-Cookie`.
    **The rotation test the plan has wanted since milestone 3 now exists**, and it is
    the one that matters: a client holds a cookie asserting `Admins`, the role is
    revoked, and `/admin` must stop admitting it. Mutation-tested — remove the stamp
    refresh from `RoleService` and the revoked administrator gets `200 OK` from
    `/admin`, which is the actual vulnerability, demonstrated. Until this existed, the
    library's central invariant rested on reading the framework source correctly.
    Notes for anyone extending it: the client's base address must be `https`, because
    the session cookie is `Secure` and cannot be weakened — over plain http the server
    never sets it and every test fails for the wrong reason. And
    `SecurityStampValidationInterval` is `Zero` here so revocation lands on the next
    request; a test that waited the default minute would never be run.
    Not done: an MVC app and a Blazor app. The claim "drops into any project" is
    covered for the pipeline (the challenge-path tests cover the redirect behaviour
    MVC needs), but no test stands up either framework for real.

## Decisions (settled)

- **Built-in user.** Ship a minimal `ReusableAuthUser : IdentityUser<string>` so
  the common case needs no host type. The API stays generic over `TUser` where
  `TUser : IdentityUser<string>`, and `AddReusableAuth()` with no type argument
  defaults to the built-in; a host that needs extra claims/columns supplies its
  own subclass via `AddReusableAuth<TUser>()`.
- **EF store ships in v1.** `Authentication.EntityFrameworkCore` is in scope for
  the 1.0.0 release, not a follow-up minor. It stays a separate package so the
  core keeps its storage-agnostic dependency set.
- **Session rotation ships in v1.** The session cookie is re-issued with a new
  identifier on privilege change (role/claim change, password change, email
  confirmation) and on sign-in, so a captured pre-escalation cookie is useless.
  This is a security invariant, not an option to switch off.
