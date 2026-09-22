# Rtq (Mobile)

**RTQ on a phone.** `@rtq/mobile` is the operator's mobile approval/pairing
host: a small, isolated, RTQ-hosted server + a device simulator that proves the
§46 pairing + approval flow end-to-end on the mobile form factor — without a
real OS sandbox (that's `@rtq/sandbox`'s job, kept separate).

The mobile host is **approval-carrier only**: it can require, present, and
submit approval — it can **never enforce** RTQ policy on the device itself.
Enforcement stays in the §46 gateway (§46.30) and `@rtq/security`.

## What's inside

- **`createMobileApprovalServer(options)` + `startMobileApprovalServer(...)`**
  — spin up the RTQ mobile approval host (HTTP transport, paired + verified
  device channel). Returns a `StartedServer` handle: `close()` it to drop
  every approval ticket (single-use, fail-closed).
- **`MobileApprovalService`** (+ `MobileApprovalServiceOptions`) — the service
  logic: issue approval-required challenges, verify a device pairing response
  (RTQ crypto §46.29), and submit an approval result bound to a ticket —
  `SubmitApprovalResult`.
- **`SimulatedDevice`** (+ `SimulatedDeviceOptions`) — a test-only device that
  actually *walks* the pairing challenge → response → signed approval path
  against a live server (used by `tests/mobile/protocol` + `tests/mobile`).
- **`HttpTransportOptions`** — transport config for the approval server.

## Example

```ts
import { createMobileApprovalServer, SimulatedDevice } from "@rtq/mobile";

const server = await createMobileApprovalServer({
  port: 0, // ephemeral; bind from StartedServer
  defaultLimits: { maxChallengeAgeMs: 5 * 60 * 1000 },
});

// A device completes pairing + submits a signed approval for a parked ticket
const device = new SimulatedDevice({ deviceId: "dev-7f3a", host: "my-host" });
await device.connect(server.url);
await device.answerChallenge(server.pendingChallenge());
const submitted = await device.approve("ticket_id_42", { tenant: "acme" });
```

## RTQ invariant

_On RTQ, enforcement is where the operator is enforced; a phone can carry an
approval, it cannot override a deny._ The mobile host never fabricates policy
factales and never grants a ticket — it only presents the operator's approval
decision back to the gateway that already owns the ticket (§46.19–46.20,
§46.30 #11).

## Related

`@rtq/approval` (challenge/response + signing protocol the device uses),
`@rtq/mcp` + `@rtq/security` (the gateway the approval feeds back into).

## License

Apache-2.0
