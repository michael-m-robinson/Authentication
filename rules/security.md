## Security & secrets

- NEVER paste secrets (API keys, tokens, SMTP creds, DB passwords) into chat.
  The human sets them via `gh secret set <NAME>` or the provider's dashboard/UI.
- If a secret is ever committed: (1) remove it from the file, (2) untrack +
  `.gitignore` the file, (3) scrub it from git history (git-filter-repo) and
  force-push, then (4) ROTATE the secret at the provider and update every place
  that consumes it.
- Treat local config such as `.claude/settings.local.json` as secret-bearing;
  keep it untracked.

## Dependencies & supply chain

- **Implement with trusted, secure NuGet packages wherever one exists.** Prefer a
  well-maintained package from a known publisher (first-party
  `Microsoft.*` / .NET Foundation first) over hand-rolling, especially for
  anything security-sensitive. Never hand-roll crypto, hashing, or token
  generation: use the framework primitive.
- Vet before adding: known publisher, active maintenance, real usage, a license
  compatible with ours, and a signed package where available. Prefer packages
  whose owner prefix is reserved on nuget.org.
- Trusted does not mean unlimited. Keep the dependency surface minimal, every
  direct and transitive package is attack surface, and the core library takes only
  the Identity/cookie abstractions. Prefer the framework over a package, and one
  package over three.
- Pin explicit versions; no floating ranges (`*`, `1.2.*`). `nuget.org` is the only
  source, enforced with `packageSourceMapping` so nothing resolves from an
  unexpected feed (dependency confusion).
- CI fails the build on any known-vulnerable direct or transitive package, see
  `rules/ci-scanning.md`.

## Auth-library specifics

- This library handles credentials and session material. NEVER log passwords,
  tokens, cookie values, or PII, not even at debug level. Log identifiers
  (user id, a trace id), never secrets.
- Ship no secrets, connection strings, or signing keys in the package or source.
  All such values are supplied by the consuming app via configuration/DI.
- Fail securely: on any auth error return a generic failure, never leak whether a
  user exists, why a token was rejected, or internal state. Reject invalid input
  early; never trust caller-supplied data.
- Keep the hardened cookie defaults (`HttpOnly` + `Secure` + `SameSite`) and
  double-submit CSRF intact; a change that weakens them is a breaking security
  change, not a convenience tweak.
