/**
 * End-to-end tests for the host transport + service + simulated device.
 *
 * These prove the contract the Flutter client relies on: pair over an untrusted
 * HTTP channel, complete a challenge/approval round trip, and fail closed on
 * replay, tampering, and misroute.
 */
import { afterEach, describe, expect, it } from "vitest";
import { generateEd25519KeyPair } from "@rtq/crypto";
import { PROTOCOL_ERROR, type ApprovalRequest } from "@rtq/approval";
import {
  MobileApprovalService,
  SimulatedDevice,
  startMobileApprovalServer,
  type MobileApprovalServiceOptions,
  type StartedServer,
} from "@rtq/mobile";

const HOST = generateEd25519KeyPair();
const HOST_ID = "rtq-host-test";
const APPLICATION = "RTQ Desktop";

let running: StartedServer | null = null;

afterEach(async () => {
  if (running) {
    await running.close();
    running = null;
  }
});

function makeService(
  overrides: Partial<MobileApprovalServiceOptions> = {},
): MobileApprovalService {
  return new MobileApprovalService({
    hostId: HOST_ID,
    application: APPLICATION,
    hostPrivateKey: HOST.privateKeyJwk,
    hostPublicKey: HOST.publicKeyJwk,
    ...overrides,
  });
}

function approvalRequest(challengeId: string): ApprovalRequest {
  return {
    challengeId,
    capability: "files.delete",
    capabilityVersion: 1,
    inputHash: "d".repeat(64),
    summary: { action: "Delete file", path: "/w/x" },
    risk: "high",
    origin: "local",
    strategy: "device_verification",
  };
}

function newDevice(): SimulatedDevice {
  return new SimulatedDevice({
    keyPair: generateEd25519KeyPair(),
    name: "iPhone",
    pinnedHostPublicKey: HOST.publicKeyJwk.x as string,
  });
}

async function pair(
  server: StartedServer,
  device: SimulatedDevice,
): Promise<string> {
  const start = await fetch(`${server.url}/pair/start`, { method: "POST" });
  expect(start.status).toBe(200);
  const startBody = (await start.json()) as { payload: string };
  const response = device.respondToPairing(startBody.payload);
  const complete = await fetch(`${server.url}/pair/complete`, {
    method: "POST",
    body: JSON.stringify(response),
  });
  const completeBody = (await complete.json()) as {
    ok: boolean;
    deviceId?: string;
  };
  expect(completeBody.ok).toBe(true);
  return completeBody.deviceId as string;
}

describe("mobile approval HTTP transport", () => {
  it("reports health", async () => {
    running = await startMobileApprovalServer(makeService());
    const res = await fetch(`${running.url}/health`);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true, protocol: "rtq-approval-v1" });
  });

  it("pairs a device, then verifies a signed approval exactly once", async () => {
    let presented: string | null = null;
    const service = makeService({
      onPresentChallenge: (payload) => {
        presented = payload;
      },
    });
    running = await startMobileApprovalServer(service);
    const device = newDevice();
    const deviceId = await pair(running, device);
    expect(deviceId).toMatch(/^[0-9a-f]{64}$/);

    const pending = service.requestApproval(approvalRequest("ch-e2e-1"));
    expect(presented).toMatch(/^rtq:\/\/challenge\?v=1&c=/);
    const approval = device.approve(presented as unknown as string);
    const submit = await fetch(`${running.url}/approve`, {
      method: "POST",
      body: JSON.stringify(approval),
    });
    expect(submit.status).toBe(200);
    expect((await pending).decision).toBe("granted");

    // Replay of the exact same approval must fail closed.
    const replay = await fetch(`${running.url}/approve`, {
      method: "POST",
      body: JSON.stringify(approval),
    });
    expect(replay.status).toBe(400);
    const replayBody = (await replay.json()) as { code: string };
    expect(replayBody.code).toBe(PROTOCOL_ERROR.CHALLENGE_REDEEMED);
  });

  it("fails closed on a direct tampered approval body", async () => {
    let presented: string | null = null;
    const service = makeService({
      onPresentChallenge: (payload) => {
        presented = payload;
      },
    });
    running = await startMobileApprovalServer(service);
    const device = newDevice();
    await pair(running, device);

    const pending = service.requestApproval(approvalRequest("ch-e2e-3"));
    const approval = device.approve(presented as unknown as string);
    const tampered = { ...approval, signedAt: approval.signedAt + 1 };
    const submit = await fetch(`${running.url}/approve`, {
      method: "POST",
      body: JSON.stringify(tampered),
    });
    expect(submit.status).toBe(400);
    const body = (await submit.json()) as { code: string };
    expect(body.code).toBe(PROTOCOL_ERROR.DEVICE_SIGNATURE_INVALID);
    expect((await pending).decision).toBe("denied");
  });

  it("rejects malformed bodies and unknown routes", async () => {
    running = await startMobileApprovalServer(makeService());
    const badJson = await fetch(`${running.url}/approve`, {
      method: "POST",
      body: "{not json",
    });
    expect(badJson.status).toBe(400);
    const notFound = await fetch(`${running.url}/nope`);
    expect(notFound.status).toBe(404);
    const wrongMethod = await fetch(`${running.url}/approve`, {
      method: "GET",
    });
    expect(wrongMethod.status).toBe(405);
    expect(wrongMethod.headers.get("allow")).toBe("POST");
  });

  it("enforces the optional pairing bearer token", async () => {
    running = await startMobileApprovalServer(makeService(), {
      pairingToken: "pair-secret",
    });
    const denied = await fetch(`${running.url}/pair/start`, { method: "POST" });
    expect(denied.status).toBe(401);
    const allowed = await fetch(`${running.url}/pair/start`, {
      method: "POST",
      headers: { authorization: "Bearer pair-secret" },
    });
    expect(allowed.status).toBe(200);
  });

  it("fails closed for oversized bodies", async () => {
    running = await startMobileApprovalServer(makeService(), {
      maxBodyBytes: 32,
    });
    const res = await fetch(`${running.url}/approve`, {
      method: "POST",
      body: "x".repeat(1024),
    });
    expect(res.status).toBe(413);
  });
});
