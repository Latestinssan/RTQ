# @rtq/core

**The heart of RTQ: the capability registry, ticket store, schema dialect,
and the shared Decision/Authorization/Execution types that every RTQ package
(§46 pipeline, §46.16 policy, §46 risk, §46 security) speaks.**

`@rtq/core` is where RTQ's capability model becomes concrete:

- **Capability registry** — first-class, versioned, hash-pinned capability
  definitions (`CapabilityRegistrar`, `RegisteredCapability`,
  `McpCapabilitySummary`) so every downstream gate — policy, risk, sandbox,
  approval — reasons about the *same* normalized capability, never a
  server's unsanitized claim.
- **Ticket store** — single-use, non-replayable, argument-bound authorization
  tickets (`McpTicket`, `McpTicketStore`) with parking (`ticketStore.park` /
  `.peek`) + TTL + audit. The §46 gateway parks an `approval-required` ticket
  and executes ONLY when the matching single-use ticket authorizes it.
- **Schema dialect** — `McpToolSchema` / normalization helpers
  (`normalizeMcpToolSchema`, `toolSchemaHash_`) that all tool documents are
  normalized against before *anything* is evaluated. RTQ normalizes tool
  schemas **before** hashing (schema normalization is idempotent; a tool is
  never hashed from raw operator bytes — §46.26 #16 #17).
- **Decision types** — `McpDecision`, `McpAuthorization`, `McpExecution`,
  `McpAuditEvent`, `McpTicket` + the `authorize → approve → execute` shapes
  the whole RTQ pipeline is built on.

Everything in `@rtq/core` is **fail-closed by default**: unknown capability,
absent registry entry, unowned ticket → deny. There is no "implicit any" and no
"best-effort" in the core contract.

## Security posture

- Ticket identity is **argument-hash-bound**; replaying the same ticket with
  different arguments is rejected (ticket hygiene #8–#12).
- Registry and store are **final**: once registered, a capability's schemaHash
  never silently changes; mismatch = fail-closed deny (§46.10 hash identity).
- The canonical schema dialect is RTQ's *single source of truth* — server
  tool text is normalized INTO it or the tool is `incomplete`; never evaluated
  as raw JSON (46.30 safety-matrix #13–#17).

## Relevant spec

§46.10 (schema hash identity), §46.16 (capability registry), §46.19–46.20
(tickets), §46.21 (limits, normalization), §46.30 (schema hardening).

## License

Apache-2.0
