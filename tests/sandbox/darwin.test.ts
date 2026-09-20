import { describe, expect, it, beforeAll, afterAll } from "vitest";
import fs from "fs";
import os from "os";
import path from "path";
import { createSandbox } from "@rtq/sandbox";

const hasSeatbelt = fs.existsSync("/usr/bin/sandbox-exec");

function describeMaybe(name: string, fn: () => void) {
  hasSeatbelt ? describe(name, fn) : describe.skip(name, fn);
}

const workspace = path.join(os.tmpdir(), `rtq-darwin-test-${process.pid}`);

beforeAll(() => {
  fs.mkdirSync(workspace, { recursive: true });
  fs.writeFileSync(path.join(workspace, "allowed.txt"), "allowed");
  fs.mkdirSync(path.join(workspace, "writable"), { recursive: true });
});

afterAll(() => {
  fs.rmSync(workspace, { recursive: true, force: true });
});

describeMaybe("macOS Seatbelt real enforcement", () => {
  it("exists: /usr/bin/sandbox-exec is present (otherwise these tests are skipped)", () => {
    expect(fs.existsSync("/usr/bin/sandbox-exec")).toBe(true);
  });

  it("runs a command inside the sandbox", async () => {
    const handle = createSandbox(
      {
        filesystem: {
          read: ["/usr/bin", "/usr/lib", workspace],
          write: [path.join(workspace, "writable")],
        },
        network: "none",
        environment: { allow: ["PATH", "HOME"] },
      },
      { workspace },
    );
    const result = await handle.execute("/usr/bin/true", []);
    expect(result.sandboxed).toBe(true);
    expect(result.exitCode).toBe(0);
  });

  it("allows reading a read-authorized file", async () => {
    const handle = createSandbox(
      {
        filesystem: { read: [workspace] },
        network: "none",
        environment: { allow: [] },
      },
      { workspace },
    );
    const result = await handle.execute("/bin/cat", [
      path.join(workspace, "allowed.txt"),
    ]);
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain("allowed");
  });

  it("blocks WRITE to a read-only directory (write not authorized)", async () => {
    const handle = createSandbox(
      {
        filesystem: { read: [workspace] },
        network: "none",
        environment: { allow: [] },
      },
      { workspace },
    );
    // attempt to create a file in the workspace where write is NOT granted
    const target = path.join(workspace, "should-not-exist.txt");
    const result = await handle.execute("/usr/bin/touch", [target]);
    expect(result.exitCode).not.toBe(0);
    expect(fs.existsSync(target)).toBe(false);
  });

  it("allows WRITE inside an authorized writable directory", async () => {
    const writableDir = path.join(workspace, "writable");
    const handle = createSandbox(
      {
        filesystem: {
          read: ["/usr/bin", "/usr/lib", workspace],
          write: [writableDir],
        },
        network: "none",
        environment: { allow: ["PATH", "HOME"] },
      },
      { workspace },
    );
    const target = path.join(writableDir, "created.txt");
    const result = await handle.execute("/usr/bin/touch", [target]);
    expect(result.exitCode).toBe(0);
    expect(fs.existsSync(target)).toBe(true);
  });

  it("blocks network egress when network=none (fail toward denial)", async () => {
    const curl = fs.existsSync("/usr/bin/curl");
    if (!curl) return;
    const handle = createSandbox(
      {
        filesystem: { read: ["/usr/bin", "/usr/lib", "/System/Library"] },
        network: "none",
        environment: { allow: ["PATH", "HOME", "DYLD_*"] },
      },
      { workspace },
    );
    const result = await handle.execute("/usr/bin/curl", [
      "-s",
      "--max-time",
      "5",
      "http://127.0.0.1:1/",
    ]);
    expect(result.exitCode).not.toBe(0);
    expect(result.stdout).not.toContain("200");
  });

  it("reports per-layer isolation honestly (never just sandboxed:true)", () => {
    const handle = createSandbox(
      {
        filesystem: { read: [workspace] },
        network: "none",
        processes: { spawn: false },
        environment: { allow: ["PATH"] },
      },
      { workspace },
    );
    const r = handle.report;
    expect(r.backend).toBe("seatbelt");
    expect(r.verified).toBe(true);
    expect(typeof r.isolation.filesystem).toBe("boolean");
    expect(typeof r.isolation.process).toBe("boolean");
    expect(r.isolation.network).toBe(true);
    expect(r.isolation.environment).toBe(true);
  });

  it("fail-closed: unsupported network allowlist is refused, never silently downgraded to unsandboxed", async () => {
    const handle = createSandbox(
      {
        filesystem: {
          read: [workspace],
          write: [path.join(workspace, "writable")],
        },
        network: { allow: ["example.com"] },
        environment: { allow: [] },
      },
      { workspace },
    );
    const result = await handle.execute("/usr/bin/true", []);
    // the backend must refuse to construct a sandbox it cannot fully enforce
    expect(result.sandboxed).toBe(false);
    expect(result.error).toBeTruthy();
    expect(result.report.verified).toBe(false);
  });

  it("reports sandboxed:false when the explicit escape hatch is used (never automatic)", async () => {
    const handle = createSandbox(
      {
        filesystem: { read: [workspace] },
        network: "none",
        environment: { allow: [] },
      },
      { workspace },
    );
    // explicit, host-requested opt-out for dev/test only
    const result = await handle.execute("/usr/bin/true", [], {
      useSandbox: false,
    });
    expect(result.sandboxed).toBe(false);
    expect(result.report.backend).toBe("none");
  });

  it("environment allowlist: secrets are NOT visible to the sandboxed child", async () => {
    const handle = createSandbox(
      {
        filesystem: { read: ["/usr/bin", "/usr/lib", workspace] },
        network: "none",
        environment: { allow: ["PATH"] },
      },
      { workspace },
    );
    const child = await handle.execute(
      "/bin/sh",
      [
        "-c",
        'printf "has_token=%s" "$([ -n "$RTQ_TEST_TOKEN" ] && echo yes || echo no)"',
      ],
      {
        extraEnv: {
          RTQ_TEST_TOKEN: "super-secret",
          PATH: process.env.PATH ?? "",
        },
      },
    );
    expect(child.stdout).toContain("has_token=no");
  });

  it("env sanitization: API keys passed to the host are not leaked to children", async () => {
    const handle = createSandbox(
      {
        filesystem: { read: ["/usr/bin", "/usr/lib", workspace] },
        network: "none",
        environment: { allow: ["PATH"] },
      },
      { workspace },
    );
    const child = await handle.execute(
      "/bin/sh",
      [
        "-c",
        'printf "aws=%s" "$([ -n "$AWS_SECRET_ACCESS_KEY" ] && echo yes || echo no)"',
      ],
      {
        extraEnv: {
          AWS_SECRET_ACCESS_KEY: "AKIA-SECRET",
          PATH: process.env.PATH ?? "",
        },
      },
    );
    expect(child.stdout).toContain("aws=no");
  });
});
