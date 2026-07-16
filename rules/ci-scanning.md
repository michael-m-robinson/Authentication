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
- Pin actions to a known-good major version; bump promptly if one is deprecated.
