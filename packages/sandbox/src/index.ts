import fs from "fs";
import path from "path";
import { spawn } from "child_process";
import {
  NO_ISOLATION,
  SandboxError,
  type EnforcementReport,
  type SandboxExecutionOptions,
  type SandboxExecutionResult,
  type SandboxHandle,
  type SandboxSpec,
} from "./types";
import { defaultWorkspace } from "./path";
import { buildSandboxEnvironment, describeEnvironmentDrops } from "./env";
import { createDarwinSandbox } from "./darwin";
import { createLinuxSandbox } from "./linux";
import {
  createWindowsSandbox,
  parseWindowsRunnerOutput,
  windowsReport,
} from "./windows";
import { linuxReport } from "./linux";
import { darwinReport } from "./darwin";

export type {
  SandboxSpec,
  SandboxHandle,
  SandboxExecutionResult,
  SandboxExecutionOptions,
  EnforcementReport,
  BackendName,
} from "./types";

export interface SandboxRuntimeOptions {
  /** Sandbox workspace; default: <tmp>/rtq-workspace-<pid>. */
  workspace?: string;
  /** Default timeout for executions (ms). */
  timeoutMs?: number;
  /** Windows Job Object process limit. */
  maxProcesses?: number;
  /** Windows Job Object memory cap (bytes; 0 = none). */
  maxMemoryBytes?: number;
}

const DEFAULT_TIMEOUT_MS = 30_000;

function ensureWorkspace(workspace: string): void {
  try {
    fs.mkdirSync(path.join(workspace, "tmp"), { recursive: true });
  } catch (e) {
    throw new SandboxError(
      "SANDBOX_SETUP_FAILED",
      `Failed to create workspace ${workspace}: ${(e as Error).message}`,
    );
  }
}

/**
 * Create a sandbox handle for the given spec. FAIL-CLOSED: throws
 * SandboxError when the platform has no sandbox backend or the backend
 * cannot be verified. The handle's report states exactly which isolation
 * layers are enforced and how.
 */
export function createSandbox(
  spec: SandboxSpec,
  options: SandboxRuntimeOptions = {},
): SandboxHandle {
  const workspace = options.workspace ?? defaultWorkspace();
  ensureWorkspace(workspace);
  const runtime = { ...options, workspace };

  const envBuilder = (execOptions: SandboxExecutionOptions | undefined) =>
    buildSandboxEnvironment({
      spec: spec.environment,
      extraEnv: { ...(execOptions?.extraEnv ?? {}) },
    });

  const baseReport = (): EnforcementReport => {
    switch (process.platform) {
      case "darwin":
        try {
          return darwinReport(spec);
        } catch (e) {
          return {
            ...NO_ISOLATION,
            platform: "darwin",
            backend: "none",
            verified: false,
            notes: [(e as Error).message],
          };
        }
      case "linux":
        return linuxReport(spec);
      case "win32":
        return windowsReport(spec);
      default:
        return {
          ...NO_ISOLATION,
          platform: process.platform,
          backend: "none",
          verified: false,
          notes: ["unsupported platform"],
        };
    }
  };

  const report = baseReport();

  const execute = async (
    command: string,
    args: readonly string[] = [],
    execOptions: SandboxExecutionOptions = {},
  ): Promise<SandboxExecutionResult> => {
    const useSandbox = execOptions.useSandbox !== false;
    if (!command || typeof command !== "string") {
      throw new SandboxError("SANDBOX_POLICY_INVALID", "A command is required");
    }
    if (!Array.isArray(args)) {
      throw new SandboxError("SANDBOX_POLICY_INVALID", "args must be an array");
    }

    const timeoutMs =
      execOptions.timeoutMs ?? runtime.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    const env = envBuilder(execOptions);

    if (!useSandbox) {
      // Explicit escape hatch (development/testing). NEVER an automatic
      // fallback. Reported as unsandboxed.
      return runUnsandboxed(command, args, env, workspace, timeoutMs, report);
    }

    const spawned = await runSandboxed(
      command,
      args,
      env,
      workspace,
      timeoutMs,
      runtime,
      spec,
    );
    return spawned;
  };

  return {
    report,
    execute,
    close: () => {
      /* per-execution resources are cleaned by backends */
    },
  };
}

function runSandboxed(
  command: string,
  args: readonly string[],
  env: Record<string, string>,
  workspace: string,
  timeoutMs: number,
  runtime: SandboxRuntimeOptions,
  spec: SandboxSpec,
): Promise<SandboxExecutionResult> {
  return new Promise((resolve) => {
    let config:
      | {
          command: string;
          args: string[];
          spawnOptions: Record<string, unknown>;
          cleanup: () => void;
          report: EnforcementReport;
        }
      | undefined;

    try {
      switch (process.platform) {
        case "darwin":
          config = createDarwinSandbox(
            spec,
            workspace,
            env,
            timeoutMs,
            command,
            args,
          );
          break;
        case "linux":
          config = createLinuxSandbox(
            spec,
            workspace,
            env,
            timeoutMs,
            command,
            args,
          );
          break;
        case "win32":
          config = createWindowsSandbox(spec, workspace, env, command, args, {
            timeoutMs,
            maxProcesses: runtime.maxProcesses,
            maxMemoryBytes: runtime.maxMemoryBytes,
          });
          break;
        default:
          throw new SandboxError(
            "SANDBOX_UNSUPPORTED_PLATFORM",
            `Platform ${process.platform} has no sandbox backend`,
          );
      }
    } catch (e) {
      resolve({
        success: false,
        exitCode: null,
        stdout: "",
        stderr: "",
        sandboxed: false,
        report: {
          ...NO_ISOLATION,
          platform: process.platform,
          backend: "none",
          verified: false,
          notes: [(e as Error).message],
        },
        error:
          e instanceof SandboxError
            ? e.message
            : `Sandbox setup failed: ${(e as Error).message}`,
      });
      return;
    }

    let stdout = "";
    let stderr = "";
    let settled = false;
    const finish = (result: SandboxExecutionResult) => {
      if (settled) return;
      settled = true;
      resolve(result);
    };

    let child;
    try {
      child = spawn(
        config.command,
        config.args,
        config.spawnOptions as Record<string, unknown>,
      );
    } catch (e) {
      finish({
        success: false,
        exitCode: null,
        stdout: "",
        stderr: "",
        sandboxed: false,
        report: config.report,
        error: `Failed to spawn sandbox: ${(e as Error).message}`,
      });
      return;
    }

    child.stdout?.on("data", (d: Buffer) => {
      stdout += d;
    });
    child.stderr?.on("data", (d: Buffer) => {
      stderr += d;
    });
    child.on("error", (err: NodeJS.ErrnoException & { code?: string }) => {
      finish({
        success: false,
        exitCode: null,
        stdout,
        stderr,
        sandboxed: false,
        report: config!.report,
        error: `Failed to launch sandbox: ${err.message}`,
      });
    });
    child.on("close", (code: number | null) => {
      try {
        config!.cleanup();
      } catch {
        /* best effort */
      }
      if (process.platform === "win32") {
        const parsed = parseWindowsRunnerOutput(stdout, stderr);
        if (parsed.sandboxed) {
          finish({
            success: parsed.exitCode === 0,
            exitCode: parsed.exitCode,
            stdout,
            stderr,
            sandboxed: true,
            report: config!.report,
            ...(parsed.timedOut
              ? { error: "Sandboxed process timed out" }
              : {}),
          });
        } else {
          finish({
            success: false,
            exitCode: null,
            stdout,
            stderr,
            sandboxed: false,
            report: {
              ...NO_ISOLATION,
              platform: "win32",
              backend: "none",
              verified: false,
              notes: [parsed.error],
            },
            error: parsed.error,
          });
        }
        return;
      }
      finish({
        success: code === 0,
        exitCode: code,
        stdout: stdout.trim(),
        stderr: stderr.trim(),
        sandboxed: true,
        report: config!.report,
      });
    });
  });
}

function runUnsandboxed(
  command: string,
  args: readonly string[],
  env: Record<string, string>,
  workspace: string,
  timeoutMs: number,
  handleReport: EnforcementReport,
): Promise<SandboxExecutionResult> {
  return new Promise((resolve) => {
    let stdout = "";
    let stderr = "";
    let settled = false;
    const finish = (result: SandboxExecutionResult) => {
      if (settled) return;
      settled = true;
      resolve(result);
    };
    let child;
    try {
      child = spawn(command, [...args], {
        env,
        cwd: workspace,
        timeout: timeoutMs,
      });
    } catch (e) {
      finish({
        success: false,
        exitCode: null,
        stdout: "",
        stderr: "",
        sandboxed: false,
        report: NO_ISOLATION,
        error: `Failed to spawn: ${(e as Error).message}`,
      });
      return;
    }
    child.stdout?.on("data", (d: Buffer) => {
      stdout += d;
    });
    child.stderr?.on("data", (d: Buffer) => {
      stderr += d;
    });
    child.on("error", (err: Error) => {
      finish({
        success: false,
        exitCode: null,
        stdout,
        stderr,
        sandboxed: false,
        report: NO_ISOLATION,
        error: err.message,
      });
    });
    child.on("close", (code: number | null) => {
      finish({
        success: code === 0,
        exitCode: code,
        stdout: stdout.trim(),
        stderr: stderr.trim(),
        sandboxed: false,
        report: NO_ISOLATION,
      });
    });
  });
}

export { describeEnvironmentDrops };
export { SandboxError, SANDBOX_ERROR_CODES } from "./types";
export * from "./types";
export * from "./env";
export * from "./path";
export {
  generateSeatbeltProfile,
  darwinReport,
  createDarwinSandbox,
} from "./darwin";
export {
  buildBubblewrapArgs,
  checkBwrapCapability,
  createLinuxSandbox,
  linuxReport,
} from "./linux";
export {
  createWindowsSandbox,
  parseWindowsRunnerOutput,
  windowsReport,
} from "./windows";
