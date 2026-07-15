## Git workflow

- Do day-to-day work on the `testing` branch.
- To ship a change: commit on `testing` -> `git push origin testing` -> checkout
  the default branch (`main`) -> `git merge --no-ff testing` -> push the
  default branch -> `git checkout testing`.
- Never commit or push unless asked. If you're on the default branch, branch first.
- End every commit message with a co-author trailer:
  `Co-Authored-By: <Model Name> <noreply@anthropic.com>`
- Interactive git flags (`-i`) are not supported in this environment.
