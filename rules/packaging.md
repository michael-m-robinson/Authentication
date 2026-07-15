## Packaging & release

- This is a **library**, not a deployable app. It ships as a **NuGet package**,
  consumed by apps via a package reference (not Fly.io/Netlify).
- Set package metadata in the `.csproj`: `PackageId`, `Version`, `Authors`,
  `Description`, `RepositoryUrl`, `PackageLicenseExpression`. Enable
  `<GenerateDocumentationFile>true</GenerateDocumentationFile>` so consumers get
  XML docs, and consider `<PublishRepositoryUrl>` + Source Link for debuggability.
- Version with **SemVer**: patch = fixes, minor = additive/back-compatible, major
  = breaking public-API change. A breaking change to the auth/cookie contract is
  always a major bump, note it in the changelog.
- Publish only from CI on a tagged release: `dotnet pack -c Release` ->
  `dotnet nuget push` using `NUGET_API_KEY` from Actions secrets. Never publish a
  package built from uncommitted local changes.
- Build + test locally and have a human verify against a real consuming app
  BEFORE tagging a release.
