# TESTING_GUIDE.md

## Testing Policy

Testing depth should match risk. Small isolated changes can use targeted tests.
Shared behavior, public APIs, security-sensitive code, and user workflows require
broader verification.

## Test Levels

### Unit Tests

Use unit tests for pure functions, validation logic, error handling, permission
decisions, data transformations, edge cases, and regressions.

### Integration Tests

Use integration tests for database behavior, API routes, service boundaries,
authenticated flows, third-party adapters, background jobs, and queues.

### End-to-End Tests

Use end-to-end tests for critical user workflows, login, checkout, account
changes, onboarding, admin flows, navigation, forms, and persisted state.

### Smoke Tests

A smoke test is required for any change that can be exercised through a running
app, API, CLI, worker, or job.

Smoke test examples:

- App starts without errors.
- Changed page renders and primary action works.
- Changed endpoint returns expected success and failure responses.
- Changed CLI command completes with expected output.
- Changed background job processes one representative input.

## Standard Verification Flow

1. Run a targeted test for the changed code.
2. Run lint and type checks if available.
3. Run broader tests when shared behavior changed.
4. Run a build check for frontend, packaging, or deployment changes.
5. Perform a smoke test.
6. Report pass/fail results and any blocked checks.

## When Tests Are Missing

If the repo lacks tests for the touched area:

- Add a focused regression test when practical.
- If test setup is missing or too costly for the task, perform a stronger manual
  smoke test.
- Document the test gap in the final response.

## Common Check Commands

Use the repository's actual commands when available. Common examples:

```bash
npm test
npm run lint
npm run typecheck
npm run build
pnpm test
pnpm lint
pnpm typecheck
pytest
ruff check .
mypy .
cargo test
go test ./...
dotnet test
```

