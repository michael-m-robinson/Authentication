# Authentication

A reusable, project-agnostic authentication library for ASP.NET Core, built on
ASP.NET Core Identity. It packages a hardened session model — an **httpOnly +
Secure + SameSite** cookie with **double-submit CSRF** — so any consuming app gets
the same secure auth without re-implementing it.

- **Storage-agnostic.** The host supplies the store; an optional EF Core package
  provides a ready-made one.
- **Composed through DI + options.** One entry point, secure defaults, no
  app-specific assumptions.
- **Secure by default.** Hardened cookie, CSRF, framework password hasher, and
  session rotation on privilege change are the defaults, not opt-ins.

## Status

**Pre-release (0.1.0) — not yet usable.** Options and DI wiring exist; the auth
services do not. See [PLAN.md](PLAN.md) for the design, the settled decisions, and
the milestones toward 1.0.0.

## Local development and the `__Host-` cookie prefix

Cookies default to the `__Host-` prefix (`__Host-auth`, `__Host-csrf`), which asks
the browser itself to enforce that the cookie is `Secure`, scoped to `/`, and
carries no `Domain` — so a compromised sibling subdomain cannot overwrite your
session. Browsers enforce that prefix **inconsistently over plain
`http://localhost`**.

The better fix is to serve HTTPS locally:

```bash
dotnet dev-certs https --trust
```

If you must run plain HTTP locally, override the cookie name in development only.
The two-factor cookie names derive from it, so they follow automatically:

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

`HttpOnly`, `Secure` and the CSRF check are **not** configurable and stay on in
development. Only the cookie *name* changes.

## Store requirement

The store you register must implement `IUserSecurityStampStore<TUser>`. Without
it, ASP.NET Core Identity silently treats every security-stamp check as valid,
which would make session invalidation a no-op. The library checks this at startup
and refuses to boot rather than let that pass unnoticed.

## Packages

| Package | Purpose |
| --- | --- |
| `Authentication` | Core: options, DI extensions, cookie + CSRF configuration, auth services, abstractions. |
| `Authentication.EntityFrameworkCore` | Optional ready-made EF Core Identity store. |
| `Authentication.Endpoints` | Optional `MapAuthEndpoints()` minimal-API surface. |

## Building

```bash
dotnet build          # warnings are errors
dotnet test
dotnet format --verify-no-changes
```

## License

MIT — see [LICENSE](LICENSE).
