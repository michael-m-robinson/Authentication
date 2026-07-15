## CI security & quality scanning

- Run on every push as GitHub Actions: `dotnet build` (warnings-as-errors) +
  `dotnet test`, **Semgrep**, and **SonarQube/SonarCloud** with the C# analyzer
  (`dotnet-sonarscanner begin/end` around the build so coverage + issues report).
- Run `dotnet list package --vulnerable --include-transitive` and fail the job on
  any known-vulnerable dependency.
- Email a findings summary to `<FINDINGS_EMAIL>` on every run (e.g. via
  `dawidd6/action-send-mail` over SMTP). Use glanceable circle indicators in the
  subject line:
    - 🟢  clean / no findings
    - 🟡  non-blocking findings
    - 🔴  blocking findings
    - ❗  scan error
- Keep all tokens (`SEMGREP_APP_TOKEN`, `SONAR_TOKEN`, `NUGET_API_KEY`, SMTP
  creds) in GitHub Actions secrets, never in the workflow YAML.
- Pin actions to a known-good major version; bump promptly if one is deprecated.
