import { describe, expect, it } from "vitest";
import fs from "fs";
import path from "path";
import { parseWindowsRunnerOutput, windowsReport } from "@rtq/sandbox";

describe("parseWindowsRunnerOutput", () => {
  it("parses a successful sandboxed result that proves job + appcontainer assignment", () => {
    const stdout =
      'noise before\nRTQ_SANDBOX_RESULT:{"sandboxed":true,"exitCode":0,"jobAssigned":true,"appContainer":true,"timedOut":false}\n';
    const parsed = parseWindowsRunnerOutput(stdout, "");
    expect(parsed.sandboxed).toBe(true);
    if (parsed.sandboxed) {
      expect(parsed.exitCode).toBe(0);
      expect(parsed.jobAssigned).toBe(true);
      expect(parsed.appContainer).toBe(true);
      expect(parsed.timedOut).toBe(false);
    }
  });

  it("reports sandboxed:false (never claims isolation) when the marker is missing", () => {
    const parsed = parseWindowsRunnerOutput(
      "powershell said: nope",
      "error text",
    );
    expect(parsed.sandboxed).toBe(false);
    if (!parsed.sandboxed) expect(parsed.code).toBe("SANDBOX_SETUP_FAILED");
  });

  it("surfaces setup errors with their code", () => {
    const stdout =
      'RTQ_SANDBOX_RESULT:{"sandboxed":false,"code":"SANDBOX_SETUP_FAILED","error":"could not create AppContainer profile"}\n';
    const parsed = parseWindowsRunnerOutput(stdout, "");
    expect(parsed.sandboxed).toBe(false);
    if (!parsed.sandboxed) {
      expect(parsed.code).toBe("SANDBOX_SETUP_FAILED");
      expect(parsed.error).toContain("AppContainer");
    }
  });

  it("rejects malformed result JSON", () => {
    const parsed = parseWindowsRunnerOutput("RTQ_SANDBOX_RESULT:not-json", "");
    expect(parsed.sandboxed).toBe(false);
  });
});

describe("windowsReport", () => {
  it("reports honest per-layer isolation statements", () => {
    const report = windowsReport({
      filesystem: { read: ["C:\\x"] },
      network: "none",
    });
    expect(report.backend).toBe("appcontainer-job");
    expect(report.isolation).toEqual({
      filesystem: true,
      network: true,
      process: true,
      environment: true,
    });
    // honest limitation: target stdout/stderr are not captured
    expect(report.notes.join(" ")).toMatch(/stdout\/stderr/);
  });
});

describe("windows-runner.ps1 invariants", () => {
  it("ships in the package scripts directory", () => {
    const script = path.resolve(
      __dirname,
      "../../packages/sandbox/scripts/windows-runner.ps1",
    );
    expect(fs.existsSync(script)).toBe(true);
    const content = fs.readFileSync(script, "utf8");
    // must print the result marker that parseWindowsRunnerOutput depends on
    expect(content).toContain("RTQ_SANDBOX_RESULT");
  });

  it("contains no automatic approval bypass: sandbox failure must abort, never fall back", () => {
    const content = fs.readFileSync(
      path.resolve(
        __dirname,
        "../../packages/sandbox/scripts/windows-runner.ps1",
      ),
      "utf8",
    );
    // failure paths must report sandboxed=$false and exit nonzero, never
    // run the untrusted target uncontained
    expect(content).toContain("sandboxed = $false");
    expect(content).toContain("exit 1");
    // the only success marker must be emitted after job+appcontainer proof
    expect(content).toContain("jobAssigned = $true");
    expect(content).toContain("appContainer = $true");
  });
});
