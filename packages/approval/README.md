# @rtq/approval

**Operator approval turns RTQ judgment into a human fact.** Every high-risk
RTQ action is parked as a single-use, non-replayable approval ticket that only
an operator can sign — never auto-executed by the pipeline, never raised by
server text (§46.5 `McpGateway` approval_required, §46.20 single-use tickets).

`@rtq/approval` is the §46 pairing + approval **protocol and device layer**: it
defines the challenge/response handshake, the QR-pairing channel, the signed
approval record (`SignedApprovalV1`), and the verifier that checks a signature
against a bound device — all fail-closed.

## What's inside

- **Pairing** — `createPairingChallenge*`, `parsePairingResponse*`,
  `verifyPairingHostSignature*`, `verifyPairingResponse*`, `PairingChallengeV1`,
  `PairingResponse`, RTQ approval QR channel with a versioned
  `PAIRING_QR_PREFIX` + TTL + clock-skew guards (replay/skew →
  fail-closed).
- **Approval records** — `SignedApprovalV1` / `UnsignedApprovalV1`,
  `signApprovalV1`, `verifyApprovalSignatureV1`, `approvalBody`,
  `parseSignedApprovalV1`, plus `DeviceApproval` / `DeviceVerificationApprovalV1`
  for the §46 device + credential-class-bound approval path.
- **Protocols** — versioned `RTQ_APPROVAL_PROTOCOL`, `createChallengeV1`,
  `encodeChallengeV1`, `signPairingResponseV1`, `verifyHostSignatureV1` and
  the `McpApprovalProvider`/`AutomaticApproval` pieces used by
  `@rtq/mobile`'s `MobileApprovalVerifier` and `@rtq/security`'s pipeline.

## Quick start — verify an operator-signed approval

```ts
import { verifyApprovalSignatureV1, parseSignedApprovalV1 } from "@rtq/approval";

const raw = await fs.readFile("approvals/approval-01.json", "utf8");
const signed = parseSignedApprovalV1(raw副本);
const ok = verifyApprovalSignatureV1(signed, { publicKey, expectedApprovalHash });
if (!ok) throw new Error("stale / tampered approval — fail closed");
```

## Security posture

- **Never trust the token's text** — RTQ verifies the RTQ **fact** (the
  capability + hash + scope), never a string claim (§46.28 #2, §46.30).
- **Fail-closed** — unknown protocol version, skew beyond tolerance, or a
  signature that doesn't bind to the expected ticket/device hash → denied.
- **No recall-by-sympathy** — an approval that doesn't exactly match the
  parked ticket's arguments hash cannot be applied; idempotent, not
  replayable (§46.20 #10–#11).

## Used by

`@rtq/mobile` (device approval + pairing), `@rtq/security` (§46 pipeline →
`approval_required` tickets), `@rtq/mcp` (gateway `approvalRequired` ticket
parking), `@rtq/cli` (`rtq mcp tickets` approval inbox).

## License

Apache-2.0
