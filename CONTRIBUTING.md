# CONTRIBUTING.md

## Contribution Workflow

1. Create an issue or link to an existing issue for meaningful changes.
2. Create a branch with a clear name.
3. Keep changes scoped.
4. Add or update tests for changed behavior.
5. Run the required local checks.
6. Open a pull request using the PR template.
7. Address review feedback and keep the branch up to date.

## Local Quality Bar

Before opening a pull request:

- Run lint, formatting, type checks, and tests defined by the project.
- Run a build if packaging or frontend behavior changed.
- Perform a smoke test for the changed path.
- Complete security review for sensitive changes.

## Commit Style

Use clear, focused commits. Prefer messages that explain the user-facing or
developer-facing outcome.

Examples:

```text
Add validation for account invite emails
Fix stale session handling on logout
Document security review process
```

