## Code quality: keep the analyzer/SonarQube report clean

- Target `net10.0`; keep `Nullable` and `ImplicitUsings` enabled. Treat nullable
  warnings as real; do not `!`-suppress to silence them without justification.
- Enable analyzers and warnings-as-errors for the library build
  (`<TreatWarningsAsErrors>true</TreatWarningsAsErrors>`,
  `<EnableNETAnalyzers>true</EnableNETAnalyzers>`, `<AnalysisLevel>latest</AnalysisLevel>`).
- Cognitive complexity per method stays under 15. When a method is over:
    - Extract logical sub-sections into private methods that take only the
      parameters they use.
    - Push cross-cutting concerns (validation, hashing, cookie shaping) behind
      small focused services/interfaces so they can be unit-tested in isolation.
- No nested ternaries: convert `a ? : b ? :` into `if/else` returns in a small
  helper. No deeply-nested local functions: hoist them to method or type level.
- Public API surface is a contract: keep it small, documented with XML doc
  comments, and stable. Prefer `internal` + `sealed` by default; make a type
  `public` only when a consuming app needs it.
- Follow secure-by-default: constant-time comparison for secrets/tokens, the
  framework password hasher (never a hand-rolled one), and cookies emitted
  `HttpOnly` + `Secure` + `SameSite`. Never weaken these defaults for convenience.
- Ship one concern at a time. Gate every change on: `dotnet format --verify-no-changes`
  clean + `dotnet build` succeeds (warnings-as-errors) + `dotnet test` passes.
