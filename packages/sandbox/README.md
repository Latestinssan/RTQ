# @rtq/sandbox

**Real OS enforcement, not a policy suggestion.** `@rtq/sandbox` runs a tool
inside a **real OS backend** on every major platform — bubblewrap (Linux),
Seatbelt (`sandbox-exec`, macOS), AppContainer+Job (Windows) — using
RTQ-derived allowlists, and returns an enforcement report the gateway can
*prove* in the audit trail (RTQ §46.21–46.22, §13).

The first principle here is **§46.21 #1**: RTQ will not execute a server's tool
directly in-process "just this once" and hope; the tool either runs inside a
real OS sandbox with an enforcement report, or RTQ records that this backend
is **not** being enforced on this OS (explicit skip report, never a silent
pass). Fail-closed, always.

## What's inside

- `createSandbox(options)` — returns a `SandboxHandle` for a runtime built
  on one of `createDarwinSandbox` (Seatbelt), `createLinuxSandbox`
  (bubblewrap), or `createWindowsSandbox` (AppContainer + Job object),
  selected from the runtime → backend mapping in
  `SandboxRuntimeOptionsBackend` / `McpGatewayConfig.transportKind`.
- `buildBubblewrapArgs` / `buildSeatbeltArgs` — construct the real backend
  argv in a **new namespace**: ro/rw bind mounts from RTQ allowlists only,
  no shared `/dev` (empty mount), private `/tmp` (tmpfs), no `--share-net`
  by default, bubbles apart from the host. Linux no-`/usr` on Windows →
  `SANDBOX_POLICY_INVALID` if the allowlist can't validate **fail-closed**
  (§46.21 #11, `linux.test.ts` #6).
- `checkBwrapCapability` / `checkSeatbeltCapability` — probe whether the real
  backend binary/`sandbox-exec` exists **before** promising enforcement
  (construction invariants: never a silent `false`-positive "enforced").
- `canonicalizePath` / `isPathAllowed` / `validateAllowlistPaths` — path
  canonicalization + allowlist validation. A path that can't be
  canonicalized is **denied**, never guessed-as-abs (46.21 #8, #13).
- `buildBubblewrapArgs` refusal is **fail-closed**: network allowlists that
  enforce only against the gateway (and not the OS) are refused at
  construction with `SANDBOX_POLICY_INVALID`, not silently downgraded
  (`linux.test.ts` "refuses network allowlists it cannot enforce").
- **Windows runner** — `scripts/windows-runner.ps1` shipped in-tree (no
  `approve=true` bypass — CI greps and fails if a bypass appears). The note
  here: the Windows AppContainer is the REAL backend, and
  `tests/sandbox/windows.test.ts` `describeMaybe`-skips the Linux/`/usr`
  tests so the suite works when the OS doesn't ship `/usr`.

## Security invariants (tests/sandbox/* enforce on the real OS)

The sandbox suite (§46.21 #1–#14, §46.22 #1–#8, §13) is written to FAIL the
pipeline when enforcement is missing:

- Real-OS test on each platform verifies the actual backend ran (file
  effects landed in a private tmpfs, not the host); skip is **explicit and
  reported** in CI (`sandbox.yml` uploads an explicit skip suite
  provenance artifact), never a silent "¥passed".
- The shipped `windows-runner.ps1` is checked to contain no `approve=true`
  secret bypass and to exist on the Windows runner (real OS measure).
- `buildBubblewrapArgs` is **namespace-safe by construction**: it unshares
  user/PID/net/mount, binds only allowlisted paths, gives the process its
  own `/dev`/`/tmp`, and — critically — **never passes `--share-net`**.

## Note on platform *truthfulness*

Cross-platform CI (`sandbox.yml`) runs the enforcement suite on every OS
in the matrix. The Linux bubblewrap tests **skip cleanly on Windows** with a
reported skip (the OS deliberately can't prove `/usr`), so a red state means
"the backend is genuinely broken on this OS," never "the test file doesn't
exist for this platform."

## License

Apache-2.0
