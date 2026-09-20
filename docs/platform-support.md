# RTQ platform support

RTQ's sandboxing is OS-native. This page is honest about what runs where —
including what is NOT enforced on a given platform.

## Backends

| OS      | Backend                   | Mechanism                                                         | Default                   |
| ------- | ------------------------- | ----------------------------------------------------------------- | ------------------------- |
| macOS   | Seatbelt                  | `sandbox-exec` with generated profiles                            | enforced                  |
| Linux   | bubblewrap (`bwrap`)      | user namespaces, bind mounts, netns                               | enforced                  |
| Windows | AppContainer + Job Object | PowerShell runner (`packages/sandbox/scripts/windows-runner.ps1`) | enforced                  |
| other   | none                      | `NO_ISOLATION` report                                             | **refused** (fail-closed) |

## Per-layer enforcement (what "enforced" means)

Each execution returns an `EnforcementReport` naming what was actually
applied (`sandboxed`, seatbelt profile / netns / app-container membership,
environment drops). Verification matrix: `docs/SECURITY_VERIFICATION_MATRIX.md`.

### macOS (Seatbelt)

- Filesystem: read/write/delete allowlists become sandbox rules; separate
  op sets enforced.
- Network: `network: none` denies socket connections; **deny wins**.
- Processes: `processes.spawn` off by default.
- Environment: allowlist-based, secret-shaped keys dropped.
- Real tests: `tests/sandbox/darwin.test.ts` (gated on `/usr/bin/sandbox-exec`).
- Known limit: `sandbox-exec` is deprecated by Apple; Mach IPC remains
  default-allowed (see `THREAT_MODEL.md`).

### Linux (bubblewrap)

- New user + pid + net namespace by default (`--unshare-*`).
- Read-only binds for read allowlists, rw binds for write allowlists.
- Private `/dev` (empty) and private `/tmp` (tmpfs).
- An allowlist the backend cannot enforce (e.g. per-domain network) is
  **refused**, never ignored.
- Real tests run on `ubuntu-latest` with `bwrap` installed; locally without
  bwrap the argv construction is still unit-tested.
- Known limit: bwrap is not a root boundary (unprivileged CI).

### Windows (AppContainer + Job Object)

- PowerShell runner launches the command as an AppContainer with a Job
  Object; success marker requires `sandboxed = $true`, `jobAssigned = $true`,
  `appContainer = $true`.
- Failure paths emit `sandboxed = $false` and `exit 1` — the runner never
  claims isolation it did not produce, and never falls back to unsandboxed.
- Known limit: target stdout/stderr are not captured by the runner; integrity
  level is AppContainer (see `THREAT_MODEL.md`).

## The escape hatch

`useSandbox: false` (explicit, host-supplied, per-execution) runs
unsandboxed for development/testing. It is **never automatic**, is reported
`sandboxed: false`, and its invariant ("reports sandboxed:false, never
automatic") is verified by a real macOS test.

## Fail-closed rule

If the platform has no backend, or the backend cannot be constructed or
verified, execution is **refused** with `SandboxError` — there is no
unsandboxed fallback path.

## CI matrix

`.github/workflows/` runs the same suites on `macos-latest`,
`ubuntu-latest`, and `windows-latest`, printing `rtq diagnostics` (backend
presence) so green runs are comparable: macOS exercises real Seatbelt
enforcement; Ubuntu exercises real bwrap once installed; Windows exercises
runner invariants + real AppContainer execution.
