/**
 * Sandbox types.
 *
 * The sandbox provides the OS-level ENFORCEMENT boundary. A policy layer
 * (capability declaration, directory allowlist, environment allowlist)
 * DECIDES the boundary; the sandbox ENFORCES it. If the boundary cannot be
 * constructed AND verified, execution must not proceed (fail-closed).
 */

export type BackendName =
  "seatbelt" | "bubblewrap" | "appcontainer-job" | "none";

export interface FilesystemAccess {
  /** Directories readable by the sandboxed process. */
  read?: readonly string[];
  /** Directories writable by the sandboxed process. */
  write?: readonly string[];
  /** Reserved: paths the capability may delete. Policy layer enforcement. */
  delete?: readonly string[];
  /** Paths the sandboxed process may execute from. */
  execute?: readonly string[];
}

export type NetworkSpec = "none" | { allow: readonly string[] };

export interface ProcessesSpec {
  /** Whether the sandboxed process may spawn children (default true). */
  spawn?: boolean;
}

export interface EnvironmentSpec {
  /** Environment keys inherited from the host (allowlist). Default: []. */
  allow?: readonly string[];
  /** Keys that must never be present, even if allow-listed. */
  deny?: readonly string[];
}

export interface SandboxSpec {
  filesystem?: FilesystemAccess;
  network?: NetworkSpec;
  processes?: ProcessesSpec;
  environment?: EnvironmentSpec;
}

export interface EnforcementReport {
  isolation: {
    filesystem: boolean;
    network: boolean;
    process: boolean;
    environment: boolean;
  };
  platform: string;
  backend: BackendName;
  /** Whether the constructed sandbox was verified before any execution. */
  verified: boolean;
  /** Honest caveats about what this backend does and does not enforce. */
  notes: string[];
}

export interface SandboxExecutionOptions {
  cwd?: string;
  env?: Record<string, string>;
  timeoutMs?: number;
  /** Windows Job Object active-process limit (default 64). */
  maxProcesses?: number;
  /** Windows Job Object memory cap in bytes (0 = none). */
  maxMemoryBytes?: number;
  extraEnv?: Record<string, string>;
  /**
   * Explicit escape hatch for development/testing (default true). When false
   * the command runs directly WITHOUT isolation and the result reports
   * sandboxed:false. This is never an automatic fallback.
   */
  useSandbox?: boolean;
}

export interface SandboxExecutionResult {
  success: boolean;
  exitCode: number | null;
  stdout: string;
  stderr: string;
  /** True when the process ran inside the verified OS sandbox. */
  sandboxed: boolean;
  report: EnforcementReport;
  error?: string;
}

export interface SandboxHandle {
  readonly report: EnforcementReport;
  execute(
    command: string,
    args?: readonly string[],
    options?: SandboxExecutionOptions,
  ): Promise<SandboxExecutionResult>;
  close(): void;
}

export const NO_ISOLATION: EnforcementReport = {
  isolation: {
    filesystem: false,
    network: false,
    process: false,
    environment: false,
  },
  platform: process.platform,
  backend: "none",
  verified: false,
  notes: ["no isolation: this sandbox was not constructed"],
};

export const SANDBOX_ERROR_CODES = [
  "SANDBOX_UNAVAILABLE",
  "SANDBOX_SETUP_FAILED",
  "SANDBOX_VERIFICATION_FAILED",
  "SANDBOX_POLICY_INVALID",
  "SANDBOX_UNSUPPORTED_PLATFORM",
] as const;

export type SandboxErrorCode = (typeof SANDBOX_ERROR_CODES)[number];

export class SandboxError extends Error {
  readonly code: SandboxErrorCode;
  constructor(code: SandboxErrorCode, message: string) {
    super(message);
    this.name = "SandboxError";
    this.code = code;
  }
}
