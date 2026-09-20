import fs from "fs";
import os from "os";
import path from "path";
import crypto from "crypto";
import {
  SandboxError,
  type EnforcementReport,
  type SandboxSpec,
} from "./types";
import {
  flattenAllowlist,
  validateAllowlistPaths,
  type AllowlistEntry,
} from "./path";

/**
 * Windows AppContainer + Job Object backend.
 *
 * The target is staged to a temporary JSON payload and a PowerShell runner
 * script. The runner:
 *   1. creates a Job Object (KILL_ON_JOB_CLOSE + process/memory limits),
 *   2. creates an AppContainer profile (zero capabilities => NO network),
 *   3. grants the package SID filesystem rights ONLY for allowlisted
 *      directories + workspace + the target executable (icacls),
 *   4. creates the target SUSPENDED with the SECURITY_CAPABILITIES
 *      proc-thread attribute, verifies job assignment, then resumes it,
 *   5. removes grants + profile afterwards.
 *
 * stdout/stderr of the target are not captured by the runner; callers that
 * need output should write files inside the allowlisted workspace.
 */
export function windowsReport(spec: SandboxSpec): EnforcementReport {
  return {
    isolation: {
      filesystem: true,
      network: true,
      process: true,
      environment: true,
    },
    platform: "win32",
    backend: "appcontainer-job",
    verified: true,
    notes: [
      "Target stdout/stderr are not captured by the runner.",
      "AppContainer grants are OS-enforced via package-SID ACLs.",
    ],
  };
}

export interface WindowsSandboxConfig {
  command: string;
  args: string[];
  spawnOptions: Record<string, unknown>;
  report: EnforcementReport;
  cleanup: () => void;
}

function runnerScriptPath(): string {
  const inDist = path.join(__dirname, "..", "scripts", "windows-runner.ps1");
  if (fs.existsSync(inDist)) return inDist;
  const inSrc = path.join(__dirname, "scripts", "windows-runner.ps1");
  if (fs.existsSync(inSrc)) return inSrc;
  // Development: src dir of the package
  const dev = path.join(
    __dirname,
    "..",
    "src",
    "..",
    "scripts",
    "windows-runner.ps1",
  );
  if (fs.existsSync(dev)) return dev;
  throw new SandboxError(
    "SANDBOX_UNAVAILABLE",
    "windows-runner.ps1 is missing from the package",
  );
}

function resolveWindowsPowershell(): string {
  if (process.env.SystemRoot) {
    const candidate = path.join(
      process.env.SystemRoot,
      "System32",
      "WindowsPowerShell",
      "v1.0",
      "powershell.exe",
    );
    if (fs.existsSync(candidate)) return candidate;
  }
  return "powershell.exe";
}

export function createWindowsSandbox(
  spec: SandboxSpec,
  workspace: string,
  env: Record<string, string>,
  command: string,
  args: readonly string[],
  options: {
    timeoutMs?: number;
    maxProcesses?: number;
    maxMemoryBytes?: number;
  },
): WindowsSandboxConfig {
  if (spec.network !== undefined && spec.network !== "none") {
    throw new SandboxError(
      "SANDBOX_UNAVAILABLE",
      'Per-domain network allowlisting is not supported by the AppContainer sandbox (zero capabilities => no network); use network: "none"',
    );
  }
  const allowlist: AllowlistEntry[] = [
    ...(spec.filesystem?.read ?? []).map((p) => ({
      path: p,
      access: "read" as const,
    })),
    ...(spec.filesystem?.write ?? []).map((p) => ({
      path: p,
      access: ["read", "write"] as AllowlistEntry["access"],
    })),
  ];
  validateAllowlistPaths(allowlist);
  const { read: readDirs, write: writeDirs } = flattenAllowlist(allowlist);

  const runnerScript = fs.readFileSync(runnerScriptPath(), "utf8");
  const tmpTag = `rtq-${process.pid}-${Date.now()}-${crypto.randomBytes(4).toString("hex")}`;
  const payloadPath = path.join(os.tmpdir(), `${tmpTag}-payload.json`);
  const runnerPath = path.join(os.tmpdir(), `${tmpTag}-runner.ps1`);

  const payload = {
    command,
    args: [...args],
    env,
    cwd: workspace,
    timeoutMs: options.timeoutMs ?? 30_000,
    sandbox: {
      useAppContainer: true,
      integrityLevel: "appcontainer",
      workspace,
      maxProcesses: options.maxProcesses ?? 64,
      maxMemoryBytes: options.maxMemoryBytes ?? 0,
      readDirs,
      writeDirs,
    },
  };

  try {
    // PowerShell 5.1 requires a UTF-8 BOM on script files; the payload stays
    // BOM-free UTF-8 and is read with -Encoding UTF8.
    fs.writeFileSync(payloadPath, JSON.stringify(payload), {
      encoding: "utf8",
      mode: 0o600,
    });
    fs.writeFileSync(runnerPath, "\uFEFF" + runnerScript, {
      encoding: "utf8",
      mode: 0o600,
    });
  } catch (e) {
    try {
      fs.unlinkSync(payloadPath);
    } catch {
      /* best effort */
    }
    try {
      fs.unlinkSync(runnerPath);
    } catch {
      /* best effort */
    }
    throw new SandboxError(
      "SANDBOX_SETUP_FAILED",
      `Failed to stage Windows sandbox files: ${(e as Error).message}`,
    );
  }

  return {
    command: resolveWindowsPowershell(),
    args: [
      "-NoProfile",
      "-NonInteractive",
      "-ExecutionPolicy",
      "Bypass",
      "-File",
      runnerPath,
      payloadPath,
    ],
    spawnOptions: {
      env: { ...process.env, RTQ_SANDBOXED: "1" },
      windowsHide: true,
      timeout: (options.timeoutMs ?? 30_000) + 10_000,
    },
    report: windowsReport(spec),
    cleanup: () => {
      try {
        fs.unlinkSync(payloadPath);
      } catch {
        /* best effort */
      }
      try {
        fs.unlinkSync(runnerPath);
      } catch {
        /* best effort */
      }
    },
  };
}

export function parseWindowsRunnerOutput(
  stdout: string,
  stderr: string,
):
  | {
      sandboxed: true;
      exitCode: number;
      jobAssigned: boolean;
      appContainer: boolean;
      timedOut: boolean;
    }
  | { sandboxed: false; code: string; error: string } {
  const marker = "RTQ_SANDBOX_RESULT:";
  const out = String(stdout || "");
  const idx = out.lastIndexOf(marker);
  if (idx === -1) {
    return {
      sandboxed: false,
      code: "SANDBOX_SETUP_FAILED",
      error: (stderr || stdout || "runner produced no result").trim(),
    };
  }
  const after = out.slice(idx + marker.length);
  const firstLine = after.split("\n").find((l) => l.trim().length > 0) || "";
  let parsed: Record<string, unknown> | null = null;
  try {
    parsed = JSON.parse(firstLine.trim());
  } catch {
    parsed = null;
  }
  if (!parsed) {
    return {
      sandboxed: false,
      code: "SANDBOX_SETUP_FAILED",
      error: (stderr || firstLine).trim(),
    };
  }
  if (parsed.sandboxed === true) {
    return {
      sandboxed: true,
      exitCode: typeof parsed.exitCode === "number" ? parsed.exitCode : -1,
      jobAssigned: parsed.jobAssigned === true,
      appContainer: parsed.appContainer === true,
      timedOut: parsed.timedOut === true,
    };
  }
  return {
    sandboxed: false,
    code:
      typeof parsed.code === "string" ? parsed.code : "SANDBOX_SETUP_FAILED",
    error: String(parsed.error || "Windows sandbox setup failed"),
  };
}
