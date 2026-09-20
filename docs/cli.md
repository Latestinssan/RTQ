# rtq CLI reference

The CLI exists to answer questions an operator or reviewer must answer, and
to do nothing else. Every command prints what you need to decide and exits
nonzero when the answer is "not OK".

Exit codes:

| Code | Meaning                                       |
| ---- | --------------------------------------------- |
| 0    | OK                                            |
| 2    | usage / unknown command / bad argument        |
| 3    | policy check result is a denial               |
| 4    | verification failed (ticket invalid/tampered) |
| 1    | internal error                                |

## Global setup

Most commands read the signing key from `RTQ_SIGNING_KEY`. It must be a
high-entropy secret **outside the repository**.

```sh
export RTQ_SIGNING_KEY="$(openssl rand -hex 32)"
```

## `rtq capabilities --config <file>`

Lists every **registered** capability with its declared base risk, derived
approval strategy, and sandbox requirement. Read-only inspection of the
explicit surface.

```sh
RTQ_SIGNING_KEY=$KEY npx rtq capabilities --config settings/config.js
```

Output includes `BASE RISK`, `APPROVAL`, and `SANDBOX` columns per
capability. Exit 0 when at least one capability is registered; exits nonzero
if the config fails to load or registers nothing.

## `rtq policy check <command.json> --config <file> [--origin <origin>]`

Evaluates one command through the pipeline and prints the JSON decision:

```json
{ "decision": "allowed" | "denied" | "clarification_required" | "approval_required", ... }
```

- `--origin local|remote|mobile|unknown` — the command's origin **hint**.
  `remote`/`mobile`/`unknown` escalate risk; `unknown` is never local.
- Exit `0` on `allowed`, `3` on `denied`.

Command file shape:

```json
{
  "capability": "files.read",
  "version": 1,
  "input": { "path": "/workspace/report.md" }
}
```

## `rtq sandbox test`

Diagnoses the OS sandbox backend on this machine: Seatbelt presence
(macOS), bwrap (Linux), AppContainer runner (Windows), per-layer
enforcement report. It **does not** execute arbitrary commands — it reports
what enforcement the runtime can construct here, with the same
fail-closed logic the runtime uses.

```sh
npx rtq sandbox test
```

Exit 0 when a verified backend exists, nonzero otherwise.

## `rtq verify signature --ticket <ticket.json>`

Verifies a ticket cryptogram: recomputes the HMAC over the canonical body
and checks the bindings. One file, one answer.

```sh
RTQ_SIGNING_KEY=$KEY npx rtq verify signature --ticket ticket.json
# VALID ...  (exit 0)
# INVALID ... (exit 4)
```

Rejects tampered fields, expired tickets, and tickets whose capability
version is stale. It does **not** redeem the ticket (execution is the only
redeemer, by design).

## `rtq diagnostics`

JSON report of the runtime environment: `platform`, `sandbox-exec` presence
(macOS), `bwrap` presence (Linux), node version. Used by CI to print what a
green run actually exercised.

```sh
npx rtq diagnostics
```

## What the CLI deliberately does NOT do

- No interactive approval (no pretending to be a human).
- No sandbox execution of user-supplied commands (that is the library's
  job, behind a policy).
- No key generation or storage (keys stay in platform secret storage).
- No network calls.

Tests: `tests/cli/cli.test.ts` (exit codes 0/2/3/4, `--origin` handling,
tampered-ticket rejection, diagnostics shape).
