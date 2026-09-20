import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import fs from "fs";
import os from "os";
import path from "path";
import { runCli } from "@rtq/cli";
import { createRTQ } from "@rtq/security";

const KEY = "cli-test-signing-key";

function tempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "rtq-cli-test-"));
}

/** Run a CLI command, capturing stdout and returning [exitCode, stdout]. */
async function run(argv: string[]): Promise<{ code: number; out: string }> {
  let out = "";
  const spy = vi.spyOn(process.stdout, "write").mockImplementation(((
    chunk: string | Uint8Array,
  ) => {
    out += String(chunk);
    return true;
  }) as never);
  const errSpy = vi.spyOn(process.stderr, "write").mockImplementation(((
    chunk: string | Uint8Array,
  ) => {
    return true;
  }) as never);
  try {
    const code = await runCli(argv);
    return { code, out };
  } finally {
    spy.mockRestore();
    errSpy.mockRestore();
  }
}

function writeConfig(): string {
  const dir = tempDir();
  const cfg = path.join(dir, "config.js");
  fs.writeFileSync(
    cfg,
    `module.exports = {
  capabilities: [{
    name: "files.read",
    version: 1,
    description: "Read a file in the workspace",
    inputSchema: { type: "object", properties: { path: { type: "string" } }, required: ["path"], additionalProperties: false },
    risk: { base: "low" },
    execute: async () => ({ ok: true }),
  }, {
    name: "files.delete",
    version: 1,
    description: "Delete a file",
    inputSchema: { type: "object", properties: { path: { type: "string" } }, required: ["path"], additionalProperties: false },
    risk: { base: "high" },
    execute: async () => ({ ok: true }),
  }],
  policy: [
    { kind: "allow", capability: "files.read", reason: "read is fine" },
    { kind: "allow", capability: "files.delete", reason: "delete is allowed" },
  ],
};`,
  );
  return cfg;
}

describe("rtq CLI", () => {
  let dir: string;

  beforeAll(() => {
    dir = tempDir();
    process.env.RTQ_SIGNING_KEY = KEY;
  });

  afterAll(() => {
    fs.rmSync(dir, { recursive: true, force: true });
    delete process.env.RTQ_SIGNING_KEY;
  });

  it("help prints usage and exits 0", async () => {
    const { code, out } = await run(["help"]);
    expect(code).toBe(0);
    expect(out).toContain("Usage: rtq");
  });

  it("unknown command exits 2", async () => {
    const { code } = await run(["frobnicate"]);
    expect(code).toBe(2);
  });

  it("capabilities lists the registered surface with derived risk/approval", async () => {
    const cfg = writeConfig();
    const { code, out } = await run(["capabilities", "--config", cfg]);
    expect(code).toBe(0);
    expect(out).toContain("files.read");
    expect(out).toContain("files.delete");
    expect(out).toMatch(/BASE RISK/);
    expect(out).toMatch(/low/);
    expect(out).toMatch(/high/);
  });

  it("policy check allows a command matching an allow rule", async () => {
    const cfg = writeConfig();
    const cmd = path.join(dir, "cmd-read.json");
    fs.writeFileSync(
      cmd,
      JSON.stringify({
        capability: "files.read",
        version: 1,
        input: { path: "/workspace/a.txt" },
      }),
    );
    const { code, out } = await run(["policy", "check", cmd, "--config", cfg]);
    expect(code).toBe(0);
    const parsed = JSON.parse(out) as { decision: string };
    expect(parsed.decision).toBe("allowed");
  });

  it("policy check reports denial exit 3 for a denied command", async () => {
    const cfg = writeConfig();
    const cmd = path.join(dir, "cmd-missing.json");
    // capability not covered by any allow rule (default deny)
    fs.writeFileSync(
      cmd,
      JSON.stringify({
        capability: "tools.exec",
        version: 1,
        input: {},
      }),
    );
    const { code } = await run(["policy", "check", cmd, "--config", cfg]);
    expect(code).toBe(3);
  });

  it("policy check honors --origin (remote escalates risk to approval_required)", async () => {
    const cfg = writeConfig();
    const cmd = path.join(dir, "cmd-origin.json");
    fs.writeFileSync(
      cmd,
      JSON.stringify({
        capability: "files.read",
        version: 1,
        input: { path: "/workspace/a.txt" },
      }),
    );
    const { code, out } = await run([
      "policy",
      "check",
      cmd,
      "--config",
      cfg,
      "--origin",
      "remote",
    ]);
    expect(code).toBe(0);
    expect(JSON.parse(out) as { decision: string }).toMatchObject({
      decision: "approval_required",
      risk: "medium",
    });
  });

  it("verify signature accepts a genuine ticket and rejects a tampered one", async () => {
    const { TicketStore } = await import("@rtq/core");
    const store = new TicketStore({ signingKey: KEY });
    // A ticket is opaque by design; issue it through the same public core
    // machinery the pipeline uses (canonical body + HMAC signature).
    const signed = store.issue({
      capability: "files.read",
      capabilityVersion: 1,
      input: { path: "/w/x" },
      actor: "local-user",
      resource: null,
      risk: "low",
      policyVersion: "test",
      approvalMethod: "automatic",
      origin: "local",
      challengeId: "",
      nonce: "abc",
    });
    const ticketFile = path.join(dir, "ticket.json");
    fs.writeFileSync(ticketFile, JSON.stringify(signed));
    const okRes = await run(["verify", "signature", "--ticket", ticketFile]);
    expect(okRes.code).toBe(0);
    expect(okRes.out).toContain("VALID");

    const tampered = { ...signed, inputHash: "1".repeat(64) };
    const badFile = path.join(dir, "ticket-tampered.json");
    fs.writeFileSync(badFile, JSON.stringify(tampered));
    const badRes = await run(["verify", "signature", "--ticket", badFile]);
    expect(badRes.code).toBe(4);
    expect(badRes.out).toContain("INVALID");
  });

  it("diagnostics reports the platform and backend availability", async () => {
    const { code, out } = await run(["diagnostics"]);
    expect(code).toBe(0);
    const parsed = JSON.parse(out) as {
      platform: string;
      sandboxExec: boolean;
      bwrap: boolean;
    };
    expect(parsed.platform).toBe(process.platform);
    expect(typeof parsed.sandboxExec).toBe("boolean");
    expect(typeof parsed.bwrap).toBe("boolean");
  });
});
