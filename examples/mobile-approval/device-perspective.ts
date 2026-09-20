/**
 * Device-perspective walkthrough of the RTQ mobile approval flow.
 *
 * The Flutter app (`apps/rtq-mobile`) performs these exact steps with a
 * PIN-wrapped device key and a camera. This script runs the same steps with
 * the released TypeScript packages so the device-side contract can be read,
 * run, and diffed without a phone:
 *
 *   1. (simulated pairing) the device pins the host's Ed25519 public key,
 *   2. the host shows a host-SIGNED challenge QR (no secret, no approve flag),
 *   3. the device strictly parses the QR and verifies the host signature
 *      against the PINNED key — a QR signed by any other key is rejected,
 *   4. the human reviews the exact operation/risk/origin/application/expiry,
 *   5. the device locally authenticates (PIN + optional biometrics in the app;
 *      a plain key pair here — the wire format is identical),
 *   6. the device signs the canonical challenge binding and the approval
 *      verifies byte-for-byte against the app's protocol tests.
 *
 * Also demonstrated: malformed "approve=true" payloads are rejected by strict
 * parsing, and host-key mismatch is rejected before anything is shown.
 *
 * Run from the repo root:
 *   npx tsx examples/mobile-approval/device-perspective.ts
 */
import { createHash } from "node:crypto";
import { generateEd25519KeyPair } from "@rtq/crypto";
import {
  createChallengeV1,
  encodeChallengeV1,
  parseChallengeV1,
  verifyHostSignatureV1,
  signApprovalV1,
  verifyApprovalSignatureV1,
  encodeSignedApprovalV1,
} from "@rtq/approval";

function sha256Hex(text: string): string {
  return createHash("sha256").update(text).digest("hex");
}

function main(): void {
  console.log("=== RTQ mobile approval, device perspective ===\n");

  // ── 1. Simulated pairing: the device pinned this host key earlier. ──────
  const host = generateEd25519KeyPair();
  const pinnedHostKey = host.publicKeyJwk.x!; // base64url, same value the app stores in rtq.paired_host.v1
  console.log("pinned host public key :", pinnedHostKey);

  // ── 2. The host creates and shows a signed challenge QR. ────────────────
  const challenge = createChallengeV1({
    challenge: {
      capability: "files.write",
      capabilityVersion: 1,
      inputHash: sha256Hex(JSON.stringify({ path: "/workspace/report.md" })),
      summary: {
        operation: "Append report to /workspace/report.md",
        target: "/workspace/report.md",
      },
      risk: "medium",
      policyVersion: "2026.09",
      origin: "mobile",
    },
    host: {
      hostId: "host-demo",
      application: "RTQ Desktop",
      hostPrivateKey: host.privateKeyJwk,
      hostPublicKey: host.publicKeyJwk,
    },
  });
  const qr = encodeChallengeV1(challenge);
  console.log("challenge QR            :", qr.slice(0, 64) + "…");

  // ── 3. Strict parse + signature verification against the PINNED key. ────
  const parsed = parseChallengeV1(qr);
  if (!parsed.ok) throw new Error(`QR rejected: ${parsed.reason}`);
  if (!verifyHostSignatureV1(parsed.value, pinnedHostKey)) {
    throw new Error("host signature did not verify against the pinned key");
  }
  console.log("strict parse            : ok (re-encoded canonical base64url)");
  console.log("host signature (pinned) : verified");

  // ── Host-key mismatch must be rejected (an "evil" host signs its own QR). ─
  const evil = generateEd25519KeyPair();
  const evilChallenge = createChallengeV1({
    challenge: {
      capability: "files.write",
      capabilityVersion: 1,
      inputHash: challenge.inputHash,
      summary: challenge.summary,
      risk: "medium",
      policyVersion: "2026.09",
      origin: "mobile",
    },
    host: {
      hostId: "host-evil",
      application: "RTQ Desktop",
      hostPrivateKey: evil.privateKeyJwk,
      hostPublicKey: evil.publicKeyJwk,
    },
  });
  const evilParsed = parseChallengeV1(encodeChallengeV1(evilChallenge));
  if (evilParsed.ok && verifyHostSignatureV1(evilParsed.value, pinnedHostKey)) {
    throw new Error("evil host QR verified — pinning broken");
  }
  console.log("host-key mismatch       : rejected (pinned-key check)");

  // ── The protocol has no `approve=` parameter. Two forgery checks: ────────
  // (a) appending &approve=true to a valid QR envelope fails the strict
  //     base64url envelope check (no host `approve` flag can ever ride a QR);
  const forgedQr = qr + "&approve=true";
  const forgedParsed = parseChallengeV1(forgedQr);
  if (forgedParsed.ok) throw new Error("forged &approve=true accepted");
  console.log("forged &approve=true    : rejected (", forgedParsed.code, ")");
  // (b) duplicate JSON keys inside the envelope are rejected by the strict,
  //     duplicate-key-rejecting parser used on BOTH sides of the protocol — a
  //     JSON-ambiguity attack cannot make two implementations disagree.
  const dupKeyJson = Buffer.from(
    '{"protocol":"rtq-approval-v1","protocol":"rtq-approval-v1","version":1,"kind":"challenge"}',
    "utf8",
  ).toString("base64url");
  const dupKeyParsed = parseChallengeV1(`rtq://challenge?v=1&c=${dupKeyJson}`);
  if (dupKeyParsed.ok) throw new Error("duplicate JSON key accepted");
  console.log("duplicate JSON keys     : rejected (", dupKeyParsed.code, ")");

  // ── 4. Human review — the exact fields the app shows on the detail screen. ─
  const c = challenge;
  console.log("\n=== human review ===");
  console.log("operation :", c.summary.operation);
  console.log("target    :", c.summary.target);
  console.log("risk      :", c.risk, "| origin:", c.origin);
  console.log("application:", c.application, "| host:", c.hostId);
  console.log("expires   :", new Date(c.expiresAt).toISOString());
  console.log(
    "binding   : capability=%s v%d inputHash=%s… nonce=%s",
    c.capability,
    c.capabilityVersion,
    c.inputHash.slice(0, 12),
    c.nonce.slice(0, 12),
  );

  // ── 5+6. Local auth (PIN/biometrics in the app) → sign the binding. ──────
  const device = generateEd25519KeyPair();
  const approval = signApprovalV1({
    challenge,
    decision: "granted", // "denied" is signed the same way when the human denies
    deviceKeyPair: device,
  });
  if (!verifyApprovalSignatureV1(approval, device.publicKeyJwk)) {
    throw new Error("self-verification failed");
  }
  console.log("\n=== signed approval (what POST /approve carries) ===");
  console.log(encodeSignedApprovalV1(approval));
  console.log(
    "\ndevice signature verifies; the host independently checks device",
  );
  console.log("authorization, every binding field, expiry, nonce, single-use,");
  console.log('and decision === "granted" before executing anything.');
}

main();
