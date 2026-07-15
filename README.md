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

**Pre-release (0.1.0) — not yet usable.** The scaffold is in place; the public API
is still being built. See [PLAN.md](PLAN.md) for the design, the settled
decisions, and the milestones toward 1.0.0.

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
