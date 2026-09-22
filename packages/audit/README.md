# @rtq/audit

**Structured audit sink layer for RTQ.** Every decision the RTQ pipeline makes
— authorize, deny, approve, override, execute, clarify, revoke — flows through
an `Auditor`, and RTQ ships the sinks your compliance story needs as real,
tested adapters (`tests/mcp/unit/security-matrix.test.ts` #28–#31 =
credential isolation; `tests/security/*` = audit-on-every-decision, never best
effort). RTQ's audit contract is **audit-on-compromise**: an event that cannot
be written to the configured sink fails the pipeline closed rather than
proceeding silently. There is no "best-effort audit" in RTQ.

## Install

```bash
npm install @rtq/audit
```

## Quick start

```ts
import { AuditLogger, MemorySink, FileSink, NoopSink } from "@rtq/audit";

// 1. In tests / single-process tools: keep events in memory
const memory = new MemorySink();
const logger = new AuditLogger({ sink: memory });
logger.record({ type: "authorize", capability: "mcp://srv1/read_file", allowed: true });

// 2. Production: append to a newline-delimited JSONL file
const file = new FileSink({ path: "/var/log/rtq/audit.jsonl", mode: "append" });

// 3. Feature toggling a sink OFF is STILL an explicit choice (never implicit)
const off = new NoopSink();
```

`FileSink` rotates when approaching a size cap, and every sink is a real
adapter with `record()` that returns a promise — RTQ's audit path never
swallows I/O failures.

## API

- `Auditor` (interface) / `AuditLogger` — write structured events.
- `AuditSink` (interface) + `MemorySink` / `FileSink` / `NoopSink` —
  the three concrete destinations.
- `FileSinkOptions` — path, append mode, rotation cap.

## Used by

`@rtq/mcp` (§46 gateway `onAudit`), `@rtq/security` (RTQ pipeline audit /
attackcraft tracing), `@rtq/approval` (approval-ticket audit trail),
`@rtq/cli` (`rtq audit tail`).

## RTQ spec

Docs: [docs/mcp/security.md](../../docs/mcp/security.md) and the audit
invariant suite in [tests/security/invariants](../../tests/security) —
**"fail closed on an un-auditable pipeline" is spec §46, not a tagline.**
