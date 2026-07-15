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
- `Authentication.EntityFrameworkCore` (v1, optional to reference) — a ready-made
  EF Core Identity store for hosts that want one instead of writing their own.
  Kept separate so the core stays storage-agnostic.
- `Authentication.Endpoints` (optional) — `app.MapAuthEndpoints()` minimal-API
  handlers (register / login / logout / me / confirm / reset). Hosts that already
  have controllers can skip it and call the services directly.

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
- `MapAuthEndpoints(this IEndpointRouteBuilder)` (Endpoints package) — opt-in
  minimal-API surface.

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
3. **Auth services** — `IAuthService` (register / sign-in+lockout / sign-out /
   me / confirm / reset) against Identity abstractions, plus session rotation on
   sign-in and privilege change. Unit-test with an in-memory user store; cover
   rotation with a test that asserts the pre-change cookie stops authenticating.
4. **EF Core store package** — `Authentication.EntityFrameworkCore` with the
   default Identity store + migrations guidance. In v1 scope; separate package,
   optional for the host to reference.
5. **Endpoints package** — optional `MapAuthEndpoints` minimal-API surface.
6. **CI + packaging** — Actions: build (warnings-as-errors) + test + Semgrep +
   Sonar + vulnerable-package scan + emailed summary; `dotnet pack`/`push` on a
   tagged release (`rules/ci-scanning.md`, `rules/packaging.md`).
7. **Consumer smoke test** — wire a throwaway minimal API to the package and drive
   register -> login -> me -> logout to prove it works end to end.

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
