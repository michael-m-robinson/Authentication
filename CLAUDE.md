# Project Conventions for Claude Code

A **reusable, project-agnostic Microsoft Identity authentication library**
(`Authentication`, net10.0 class library). It packages a hardened auth model, an
**httpOnly + Secure + SameSite session cookie** with **double-submit CSRF**, over
ASP.NET Core Identity, so **any** consuming app gets the same secure auth without
re-implementing it. It is storage-agnostic (the host supplies the store) and
composed through DI + options, no app-specific assumptions baked in. The library
must fail securely and never leak secrets or PII.

Modular conventions are imported below. Edit any value in angle brackets, and
delete any module that stops applying.

@rules/git-workflow.md
@rules/security.md
@rules/ci-scanning.md
@rules/code-quality.md
@rules/packaging.md
