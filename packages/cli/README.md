# @rtq/cli

**Operate RTQ from a terminal.** `@rtq/cli` is the CLI surface over the whole
pipeline — `rtq`, plus its `mcp` admin subcommand tree (§46.33 §46.31–46.33):
operators see what RTQ holds, before and after a tool runs.

`@rtq/cli` ships as the `rtq` bin (full pipeline operator console) and exposes
`runCli`/`runMcpCli` programmatically so scripts and CI flows can bind the same
fail-closed commands without a subprocess.

## What's inside

- **`runCli(argv)`** — main entry: runs the RTQ operator console and returns a
  process exit code. Fail-closed: unknown command, unknown flag → non-zero,
  never a silent no-op pass.
- **`rtq mcp` admin subcommand tree** (§46.33 §46.31–#33):
  - `rtq mcp servers` — list §46-registered MCP servers
  - `rtq mcp tools` — list discovered tools (per server)
  - `rtq mcp contracts` — run per-server contract checks (§46.29)
  - `rtq mcp revoke <serverId>` — revoke a server (single-use ticket
    revocation, fail-closed)
  - `rtq mcp metrics` — gateway metrics + ticket/approval/risk counters
  - `--json` on every subcommand for audit-pipe consumption
- **`runMcpCli(argv)`** — the `rtq mcp *` tree standalone, same exit-code
  contract as `runCli`.

## Why a CLI at all?

§46.33 is RTQ's *observer surface*: the gateway (§46.30) does the enforcement,
but human operators actually **see** the result from a terminal — servers,
tools, contract-check verdicts, revocations, metrics. `@rtq/cli` is where
"does the gateway really hold this?" becomes visible as `rtq mcp tools`.
Everything the CLI prints is a fact RTQ already audited; the CLI never
re-classifies.

## Related

`@rtq/mcp` (the gateway + contract checks the CLI reports on), `@rtq/security`
(`createRTQ` facade the CLI binds), `@rtq/audit` (the sink trails the CLI
observes with `rtq mcp metrics`).

## License

Apache-2.0
