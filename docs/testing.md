# RTQ testing strategy

RTQ separates **what is proven** from **what is asserted**. Every test file
carries a label so the CI report and this document agree about what a green
run means. A JS test never claims OS-level sandbox enforcement by itself.

## Labels

| Label                 | Meaning                                                 | Runs on                                                          | Examples                                                                 |
| --------------------- | ------------------------------------------------------- | ---------------------------------------------------------------- | ------------------------------------------------------------------------ |
| `unit`                | pure logic in isolation                                 | every platform                                                   | `tests/unit/*`, `tests/fs/path.test.ts`                                  |
| `contract`            | cross-component behavior (ticket + approval + pipeline) | every platform                                                   | `tests/security/pipeline.test.ts` (parts)                                |
| `integration`         | full pipeline end-to-end                                | every platform                                                   | `tests/security/pipeline.test.ts`, `tests/invariants/invariants.test.ts` |
| `real OS enforcement` | executes an actual OS-sandboxed child                   | **only where the backend exists**; otherwise skips with a reason | `tests/sandbox/darwin.test.ts`                                           |

## Suite map

| Suite                                                                                                         | Label                                     | Command                                                                        |
| ------------------------------------------------------------------------------------------------------------- | ----------------------------------------- | ------------------------------------------------------------------------------ |
| `tests/unit/` (9 files: crypto, policy, risk, ticket-store, registry, schema, approval, clarification, audit) | unit                                      | `npm run test:unit`                                                            |
| `tests/security/pipeline.test.ts`                                                                             | contract + integration                    | `npm run test:security`                                                        |
| `tests/invariants/invariants.test.ts`                                                                         | integration (the 12 invariants)           | `npx vitest run tests/invariants`                                              |
| `tests/fs/path.test.ts`                                                                                       | unit (filesystem policy layer)            | `npm run test:fs`                                                              |
| `tests/sandbox/darwin.test.ts`                                                                                | **real OS enforcement** (Seatbelt)        | `npm run test:sandbox` on macOS                                                |
| `tests/sandbox/linux.test.ts`                                                                                 | construction only (bwrap argv)            | `npm run test:sandbox`; real enforcement on ubuntu-latest with bwrap installed |
| `tests/sandbox/windows.test.ts`                                                                               | unit on runner output + runner invariants | `npm run test:sandbox`                                                         |
| `tests/cli/cli.test.ts`                                                                                       | integration (CLI exit-code contracts)     | `npm run test:cli` (or `npm test`)                                             |

## Platform gating (never fake a pass)

- **macOS / Seatbelt:** `tests/sandbox/darwin.test.ts` checks for
  `/usr/bin/sandbox-exec`; if absent the whole suite is `describe.skip`ped
  and vitest reports it as skipped, not passed.
- **Linux / bubblewrap:** `tests/sandbox/linux.test.ts` builds argv and
  probes `checkBwrapCapability()`. Real enforcement runs on `ubuntu-latest` in
  CI where `bwrap` is installed; locally without bwrap the real-enforcement
  tests are skipped.
- **Windows / AppContainer:** the runner script
  (`packages/sandbox/scripts/windows-runner.ps1`) invariants are unit-tested
  (no auto-bypass, honest failure reporting); real enforcement runs on
  `windows-latest` in CI.
- **The 12 invariants** are deliberately cross-platform: their sandbox
  checks verify the _construction layer_ (argv/env/profile), not the OS.

## Coverage

`npm run test:coverage` runs vitest coverage (v8 provider). The 12
invariants are the quality gate for the security model: they must pass on
every platform CI runs.

## Reporting

Every CI workflow prints the platform, whether the OS backend is present
(`rtq diagnostics`), and the vitest skip counts — so a "green" macOS run and
a "green" Linux run are visibly about different amounts of real enforcement.
