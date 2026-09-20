import { describe, expect, it, beforeAll } from "vitest";
import { createRTQ, type RTQ } from "@rtq/security";
import { signDeviceApproval } from "@rtq/approval";
import { MemorySink } from "@rtq/audit";

const SIGNING_KEY = "pipeline-test-signing-key-0001";
const DEVICE_KEY = "device-secret-key-0001";
const DEVICE_KEY_ID = "device-0001";

function makeRTQ(opts: { sandboxCap?: boolean } = {}): RTQ {
  const rtq = createRTQ({
    signingKey: SIGNING_KEY,
    auditor: undefined, // use default MemorySink
    deviceKeyStore: {
      getDeviceKey: (id) => (id === DEVICE_KEY_ID ? DEVICE_KEY : null),
    },
    onUserConfirmation: () => true,
  });

  rtq.registerCapability({
    name: "files.read",
    version: 1,
    description: "Read a file within the workspace",
    inputSchema: {
      type: "object",
      properties: { path: { type: "string" } },
      required: ["path"],
      additionalProperties: false,
    },
    risk: { base: "low" },
    execute: async (ctx, input) => ({
      ok: true,
      data: { input, ticketId: ctx.ticketId },
    }),
  });

  rtq.registerCapability({
    name: "files.delete",
    version: 1,
    description: "Delete a file",
    inputSchema: {
      type: "object",
      properties: { path: { type: "string" } },
      required: ["path"],
      additionalProperties: false,
    },
    risk: { base: "high" },
    execute: async () => ({ ok: true }),
  });

  rtq.registerCapability({
    name: "net.notify",
    version: 1,
    description: "Send a notification",
    inputSchema: {
      type: "object",
      properties: { recipient: { type: "string" } },
      required: ["recipient"],
      additionalProperties: false,
    },
    risk: { base: "medium" },
    execute: async () => ({ ok: true }),
  });

  // Policy: allow files.* and net.notify (explicit allow rules; default deny
  // for everything else).
  rtq.registerPolicy([
    { kind: "allow", capability: "files.**", reason: "test allow files" },
    { kind: "allow", capability: "net.notify", reason: "test allow notify" },
  ]);
  return rtq;
}

describe("RTQ authorization pipeline", () => {
  let rtq: RTQ;

  beforeAll(() => {
    rtq = makeRTQ();
  });

  it("denies unregistered capabilities (no implicit surface)", async () => {
    const result = await rtq.authorize({
      capability: "tools.exec",
      version: 1,
      input: {},
    });
    expect(result.decision).toBe("denied");
    if (result.decision === "denied")
      expect(result.code).toBe("capability.not_registered");
  });

  it("denies version mismatch", async () => {
    const result = await rtq.authorize({
      capability: "files.read",
      version: 99,
      input: { path: "/w/a" },
    });
    expect(result.decision).toBe("denied");
    if (result.decision === "denied")
      expect(result.code).toBe("capability.version_mismatch");
  });

  it("denies schema-invalid input", async () => {
    const result = await rtq.authorize({
      capability: "files.read",
      version: 1,
      input: { path: 42 },
    });
    expect(result.decision).toBe("denied");
    if (result.decision === "denied") expect(result.code).toBe("input.invalid");
  });

  it("denies when no policy rule matches (missing policy != allow)", async () => {
    // register a capability with no matching policy rule
    const rtq2 = makeRTQ();
    rtq2.registerCapability({
      name: "tools.exec",
      version: 1,
      description: "x",
      inputSchema: {
        type: "object",
        properties: {},
        additionalProperties: false,
      },
      risk: { base: "low" },
      execute: async () => ({ ok: true }),
    });
    const result = await rtq2.authorize({
      capability: "tools.exec",
      version: 1,
      input: {},
    });
    expect(result.decision).toBe("denied");
  });

  it("allows low-risk capability with automatic approval and executes", async () => {
    const result = await rtq.authorize({
      capability: "files.read",
      version: 1,
      input: { path: "/w/a.txt" },
    });
    if (result.decision !== "allowed") throw new Error("expected allowed");
    expect(result.approvalMethod).toBe("automatic");
    const ticket = result.ticketId;

    const outcome = await rtq.execute(ticket);
    expect(outcome.ok).toBe(true);
    if (outcome.ok && outcome.result.ok) {
      expect((outcome.result.data as { input: unknown }).input).toEqual({
        path: "/w/a.txt",
      });
    }
  });

  it("issues single-use tickets: second execute is replay-denied", async () => {
    const result = await rtq.authorize({
      capability: "files.read",
      version: 1,
      input: { path: "/w/a.txt" },
    });
    if (result.decision !== "allowed") throw new Error("expected allowed");
    const ticket = result.ticketId;
    expect((await rtq.execute(ticket)).ok).toBe(true);
    const second = await rtq.execute(ticket);
    expect(second.ok).toBe(false);
    if (!second.ok) expect(second.code).toBe("ticket.replay");
  });

  it("returns the frozen input, not caller mutation, at execution", async () => {
    const input = { path: "/w/original.txt" };
    const result = await rtq.authorize({
      capability: "files.read",
      version: 1,
      input,
    });
    if (result.decision !== "allowed") throw new Error("expected allowed");
    // attacker mutates the object after authorization
    input.path = "/etc/passwd";
    const outcome = await rtq.execute(result.ticketId);
    expect(outcome.ok).toBe(true);
    if (outcome.ok && outcome.result.ok) {
      expect(
        (outcome.result.data as { input: { path: string } }).input.path,
      ).toBe("/w/original.txt");
    }
  });

  it("rejects unknown tickets", async () => {
    const outcome = await rtq.execute("does-not-exist");
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) expect(outcome.code).toBe("ticket.not_found");
  });

  it("high-risk capability requires approval (never automatic)", async () => {
    const result = await rtq.authorize({
      capability: "files.delete",
      version: 1,
      input: { path: "/w/x" },
    });
    expect(result.decision).toBe("approval_required");
    if (result.decision === "approval_required") {
      expect(["qr", "device_verification", "biometric"]).toContain(
        result.strategy,
      );
      expect(result.challengeId).toBeTruthy();
    }
  });

  it("completes the QR/device-verification flow end-to-end", async () => {
    const result = await rtq.authorize({
      capability: "files.delete",
      version: 1,
      input: { path: "/w/x" },
    });
    expect(result.decision).toBe("approval_required");
    if (result.decision !== "approval_required") return;
    const challengeId = result.challengeId!;

    // Host renders a QR payload for the mobile verifier
    const payload = rtq.getApprovalPayload(challengeId);
    expect(payload).toMatch(/^rtq:\/\/challenge/);

    // mobile verifier (after its own local auth) signs the exact challenge
    const approval = signDeviceApproval(
      DEVICE_KEY,
      challengeId,
      "granted",
      DEVICE_KEY_ID,
    );
    const granted = await rtq.submitApproval(challengeId, {
      type: "device_approval",
      approval,
    });
    expect(granted.decision).toBe("allowed");
    if (granted.decision !== "allowed") return;

    const outcome = await rtq.execute(granted.ticketId!);
    expect(outcome.ok).toBe(true);
  });

  it("rejects approval substitution (approval for operation A used for B)", async () => {
    const a = await rtq.authorize({
      capability: "files.delete",
      version: 1,
      input: { path: "/w/a" },
    });
    const b = await rtq.authorize({
      capability: "files.delete",
      version: 1,
      input: { path: "/w/b" },
    });
    expect(a.decision).toBe("approval_required");
    expect(b.decision).toBe("approval_required");
    if (
      a.decision !== "approval_required" ||
      b.decision !== "approval_required"
    )
      return;

    // attacker has an approval signed for challenge A (maybe via a different
    // pending authorization they were allowed to see) and tries to use it for B
    const approvalForA = signDeviceApproval(
      DEVICE_KEY,
      a.challengeId!,
      "granted",
      DEVICE_KEY_ID,
    );
    const stolen = await rtq.submitApproval(b.challengeId!, {
      type: "device_approval",
      approval: approvalForA,
    });
    expect(stolen.decision).toBe("denied");
    if (stolen.decision === "denied") {
      expect([
        "approval.challenge_mismatch",
        "approval.binding_mismatch",
      ]).toContain(stolen.code);
    }
  });

  it("rejects QR replay: the same device approval cannot be reused", async () => {
    const result = await rtq.authorize({
      capability: "files.delete",
      version: 1,
      input: { path: "/w/r" },
    });
    expect(result.decision).toBe("approval_required");
    if (result.decision !== "approval_required") return;
    const challengeId = result.challengeId!;
    const approval = signDeviceApproval(
      DEVICE_KEY,
      challengeId,
      "granted",
      DEVICE_KEY_ID,
    );

    const first = await rtq.submitApproval(challengeId, {
      type: "device_approval",
      approval,
    });
    expect(first.decision).toBe("allowed");
    const second = await rtq.submitApproval(challengeId, {
      type: "device_approval",
      approval,
    });
    expect(second.decision).toBe("denied");
    if (second.decision === "denied")
      expect(second.code).toBe("approval.unknown_challenge");
  });

  it("rejects approvals for unknown challenges", async () => {
    const approval = signDeviceApproval(
      DEVICE_KEY,
      "never-issued",
      "granted",
      DEVICE_KEY_ID,
    );
    const result = await rtq.submitApproval("never-issued", {
      type: "device_approval",
      approval,
    });
    expect(result.decision).toBe("denied");
    if (result.decision === "denied")
      expect(result.code).toBe("approval.unknown_challenge");
  });

  it("rejects a denied device decision", async () => {
    const result = await rtq.authorize({
      capability: "files.delete",
      version: 1,
      input: { path: "/w/d" },
    });
    if (result.decision !== "approval_required") return;
    const approval = signDeviceApproval(
      DEVICE_KEY,
      result.challengeId!,
      "denied",
      DEVICE_KEY_ID,
    );
    const denied = await rtq.submitApproval(result.challengeId!, {
      type: "device_approval",
      approval,
    });
    expect(denied.decision).toBe("denied");
  });

  it("user_confirmation strategy prompts and can be declined", async () => {
    const rtq2 = createRTQ({
      signingKey: SIGNING_KEY,
      onUserConfirmation: () => false,
    });
    rtq2.registerCapability({
      name: "files.read",
      version: 1,
      description: "read",
      inputSchema: {
        type: "object",
        properties: { path: { type: "string" } },
        required: ["path"],
      },
      risk: { base: "medium" },
      execute: async () => ({ ok: true }),
    });
    rtq2.registerPolicy({
      kind: "allow",
      capability: "files.read",
      reason: "ok",
    });
    const result = await rtq2.authorize({
      capability: "files.read",
      version: 1,
      input: { path: "/w/a" },
    });
    expect(result.decision).toBe("denied");
    if (result.decision === "denied")
      expect(result.code).toBe("approval.denied");
  });

  it("caller-claimed low risk never downgrades an elevated risk", async () => {
    // The risk engine is authoritative: a metadata claim of 'low' cannot
    // downgrade a capability whose base risk is high.
    const result = await rtq.authorize({
      capability: "files.delete",
      version: 1,
      input: { path: "/w/z" },
      metadata: { claimedRisk: "low" },
    });
    expect(result.decision).toBe("approval_required");
    if (result.decision === "approval_required")
      expect(result.risk).toBe("high");
  });

  it("origin escalation: remote origin lifts low risk to medium", async () => {
    const rtq2 = makeRTQ();
    const result = await rtq2.authorize(
      {
        capability: "files.read",
        version: 1,
        input: { path: "/w/a" },
        origin: "remote",
      },
      { riskContext: { origin: "remote" } },
    );
    expect(result.decision).toBe("approval_required");
    if (result.decision === "approval_required")
      expect(result.risk).toBe("medium");
  });

  it("replacing a capability invalidates its outstanding tickets", async () => {
    const rtq2 = makeRTQ();
    const result = await rtq2.authorize({
      capability: "files.read",
      version: 1,
      input: { path: "/w/x" },
    });
    expect(result.decision).toBe("allowed");
    if (result.decision !== "allowed") return;
    rtq2.replaceCapability({
      name: "files.read",
      version: 2,
      description: "new version",
      inputSchema: {
        type: "object",
        properties: { path: { type: "string" } },
        required: ["path"],
      },
      risk: { base: "low" },
      execute: async () => ({ ok: true }),
    });
    const outcome = await rtq2.execute(result.ticketId!);
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) expect(outcome.code).toBe("ticket.invalidated");
  });

  it("custom approval providers are honored", async () => {
    const rtq2 = createRTQ({
      signingKey: SIGNING_KEY,
      approvalProviders: [
        {
          strategy: "custom",
          requestApproval: async () => ({
            decision: "granted" as const,
            method: "custom" as const,
          }),
        },
      ],
    });
    rtq2.registerCapability({
      name: "files.read",
      version: 1,
      description: "read",
      inputSchema: {
        type: "object",
        properties: { path: { type: "string" } },
        required: ["path"],
      },
      risk: { base: "medium" },
      approval: { strategy: "custom" },
      execute: async () => ({ ok: true }),
    });
    rtq2.registerPolicy({
      kind: "allow",
      capability: "files.read",
      reason: "ok",
    });
    const result = await rtq2.authorize({
      capability: "files.read",
      version: 1,
      input: { path: "/w/a" },
    });
    expect(result.decision).toBe("allowed");
    if (result.decision === "allowed")
      expect(result.approvalMethod).toBe("custom");
  });

  it("clarification required for ambiguous security-critical params", async () => {
    const rtq2 = makeRTQ();
    rtq2.registerClarification({
      capability: "files.delete",
      field: "recursive",
      reason: "recursive deletion must be explicit",
    });
    const result = await rtq2.authorize({
      capability: "files.delete",
      version: 1,
      input: { path: "/w/r" },
    });
    expect(result.decision).toBe("clarification_required");
    if (result.decision === "clarification_required") {
      expect(result.questions![0]!.field).toBe("recursive");
    }
  });
});

describe("RTQ audit trail", () => {
  it("records the full authorization lifecycle without secrets", async () => {
    // Own runtime whose schema legitimately admits a secret-shaped field, so
    // we can prove the audit layer redacts secrets wherever they pass through.
    const rtq = createRTQ({
      signingKey: SIGNING_KEY,
      deviceKeyStore: {
        getDeviceKey: (id) => (id === DEVICE_KEY_ID ? DEVICE_KEY : null),
      },
    });
    rtq.registerCapability({
      name: "files.delete",
      version: 1,
      description: "Delete a file",
      inputSchema: {
        type: "object",
        properties: { path: { type: "string" }, apiToken: { type: "string" } },
        required: ["path"],
        additionalProperties: false,
      },
      risk: { base: "high" },
      execute: async () => ({ ok: true }),
    });
    rtq.registerPolicy({
      kind: "allow",
      capability: "files.delete",
      reason: "ok",
    });

    const result = await rtq.authorize({
      capability: "files.delete",
      version: 1,
      input: { path: "/w/sec", apiToken: "sk-live-abcdefghijk" },
    });
    if (result.decision !== "approval_required")
      throw new Error("expected approval_required");
    await rtq.submitApproval(result.challengeId, {
      type: "device_approval",
      approval: signDeviceApproval(
        DEVICE_KEY,
        result.challengeId,
        "granted",
        DEVICE_KEY_ID,
      ),
    });
    const events = rtq.auditor.snapshot();
    const names = events.map((e) => e.event);
    for (const expected of [
      "AUTHORIZATION_REQUESTED",
      "RISK_EVALUATED",
      "POLICY_EVALUATED",
      "APPROVAL_REQUESTED",
      "VERIFICATION_STARTED",
      "APPROVAL_GRANTED",
      "TICKET_ISSUED",
    ]) {
      expect(names).toContain(expected);
    }
    for (const event of events) {
      expect(JSON.stringify(event)).not.toContain("sk-live-abcdefghijk");
    }
  });

  it("emits EXECUTION_DENIED on replay", async () => {
    const rtq = makeRTQ();
    const result = await rtq.authorize({
      capability: "files.read",
      version: 1,
      input: { path: "/w/a" },
    });
    if (result.decision !== "allowed") return;
    await rtq.execute(result.ticketId!);
    await rtq.execute(result.ticketId!);
    const names = (rtq.auditor.sink as MemorySink)
      .snapshot()
      .map((e) => e.event);
    // the ticket store records the replay itself...
    expect(names).toContain("TICKET_REPLAYED");
    // ...and the executor denies the execution
    expect(
      names.filter((n) => n === "EXECUTION_DENIED").length,
    ).toBeGreaterThan(0);
  });

  it("audit events carry capability and ticket references for tracing", async () => {
    const rtq = makeRTQ();
    await rtq.authorize({
      capability: "files.read",
      version: 1,
      input: { path: "/w/a" },
    });
    const events = (rtq.auditor.sink as MemorySink).snapshot();
    const ev = events.find((e) => e.event === "AUTHORIZATION_REQUESTED");
    expect(ev).toBeDefined();
    expect(ev!.capability).toBe("files.read");
  });
});
