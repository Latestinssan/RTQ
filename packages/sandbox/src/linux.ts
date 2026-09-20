import { spawnSync } from "child_process";
import path from "path";
import {
  SandboxError,
  type EnforcementReport,
  type SandboxSpec,
} from "./types";
import {
  canonicalizePath,
  flattenAllowlist,
  validateAllowlistPaths,
  defaultWorkspace,
  type AllowlistEntry,
} from "./path";

/**
 * Linux bubblewrap backend.
 *
 * Namespaces: pid, net, ipc, uts, user, cgroup + new session. System mounts
 * read-only. Allowlisted directories bound read-only or read-write. Private
 * /tmp. Network disabled via --unshare-net. --die-with-parent.
 *
 * HONEST LIMITATIONS:
 *   - bwrap is an unprivileged userns-based boundary against everything the
 *     same user can reach; it is NOT a boundary against root.
 *   - Requires user namespaces to be enabled (probed before use; fails
 *     closed when unavailable).
 *   - Domain allowlisting is not supported; network is all-or-nothing
 *     (`none`).
 */

let _capabilityCache = new Map<string, boolean>();

/** Verify bwrap can actually create the namespaces we depend on. */
export function checkBwrapCapability(bwrapPath: string): boolean {
  if (_capabilityCache.has(bwrapPath)) return _capabilityCache.get(bwrapPath)!;
  let result;
  try {
    result = spawnSync(
      bwrapPath,
      [
        "--ro-bind",
        "/",
        "/",
        "--unshare-pid",
        "--unshare-net",
        "--unshare-ipc",
        "--unshare-uts",
        "--unshare-user",
        "--unshare-cgroup",
        "--new-session",
        "/bin/true",
      ],
      { encoding: "utf8", timeout: 15_000 },
    );
  } catch {
    _capabilityCache.set(bwrapPath, false);
    return false;
  }
  const ok = !result.error && result.status === 0;
  _capabilityCache.set(bwrapPath, ok);
  return ok;
}

export function buildBubblewrapArgs(
  command: string,
  args: readonly string[],
  spec: SandboxSpec,
  workspace: string,
): string[] {
  if (spec.network !== undefined && spec.network !== "none") {
    throw new SandboxError(
      "SANDBOX_UNAVAILABLE",
      'Domain-level network allowlisting is not supported by bubblewrap (--unshare-net only); use network: "none"',
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

  const bwrapArgs = [
    "--unshare-pid",
    "--unshare-net",
    "--unshare-ipc",
    "--unshare-uts",
    "--unshare-cgroup",
    "--unshare-user",
    "--new-session",
    "--ro-bind",
    "/usr",
    "/usr",
    "--ro-bind",
    "/bin",
    "/bin",
    "--ro-bind",
    "/sbin",
    "/sbin",
    "--ro-bind",
    "/lib",
    "/lib",
    "--ro-bind",
    "/lib64",
    "/lib64",
    "--ro-bind",
    "/etc",
    "/etc",
    "--dev",
    "/dev",
    "--proc",
    "/proc",
    "--tmpfs",
    "/tmp",
  ];

  if (spec.processes?.spawn === false) {
    // Note: bwrap confines the pid namespace; spawn control beyond that is
    // not enforced on Linux at the OS layer and is not claimed.
  }

  for (const dir of writeDirs) bwrapArgs.push("--bind", dir, dir);
  for (const dir of readDirs) {
    if (!writeDirs.includes(dir)) bwrapArgs.push("--ro-bind", dir, dir);
  }

  const workspaceCanonical =
    canonicalizePath(workspace).canonical || path.normalize(workspace);
  bwrapArgs.push("--bind", workspaceCanonical, workspaceCanonical);
  bwrapArgs.push("--chdir", workspaceCanonical);
  bwrapArgs.push("--die-with-parent");

  bwrapArgs.push(command, ...args);
  return bwrapArgs;
}

export function linuxReport(spec: SandboxSpec): EnforcementReport {
  return {
    isolation: {
      filesystem: true,
      network: true,
      process: true,
      environment: true,
    },
    platform: "linux",
    backend: "bubblewrap",
    verified: true,
    notes: [
      "bwrap is not a boundary against root.",
      "Requires user namespaces enabled (verified by probe).",
    ],
  };
}

/** Create a verified bubblewrap launch config (throws SandboxError -> fail closed). */
export function createLinuxSandbox(
  spec: SandboxSpec,
  workspace: string,
  env: Record<string, string>,
  timeoutMs: number,
  command: string,
  args: readonly string[],
  bwrapPath = "bwrap",
): {
  command: string;
  args: string[];
  spawnOptions: Record<string, unknown>;
  cleanup: () => void;
  report: EnforcementReport;
} {
  let check;
  try {
    check = spawnSync(bwrapPath, ["--version"], {
      encoding: "utf8",
      timeout: 5000,
    });
  } catch (e) {
    throw new SandboxError(
      "SANDBOX_UNAVAILABLE",
      `Failed to check bubblewrap: ${(e as Error).message}`,
    );
  }
  if (check.error) {
    if ((check.error as NodeJS.ErrnoException).code === "ENOENT") {
      throw new SandboxError(
        "SANDBOX_UNAVAILABLE",
        `bubblewrap (bwrap) is not available at ${bwrapPath}`,
      );
    }
    throw new SandboxError(
      "SANDBOX_UNAVAILABLE",
      `bubblewrap check failed: ${check.error.message}`,
    );
  }
  if (check.status !== 0) {
    throw new SandboxError(
      "SANDBOX_UNAVAILABLE",
      `bubblewrap is not functional (exit ${check.status})`,
    );
  }
  if (!checkBwrapCapability(bwrapPath)) {
    throw new SandboxError(
      "SANDBOX_UNAVAILABLE",
      "bubblewrap cannot create the required namespaces (user namespaces may be disabled). " +
        "Refusing to run uncontained.",
    );
  }

  const bwrapArgs = buildBubblewrapArgs(command, args, spec, workspace);
  return {
    command: bwrapPath,
    args: bwrapArgs,
    spawnOptions: {
      env,
      cwd: process.cwd(),
      timeout: timeoutMs,
    },
    cleanup: () => {
      /* bwrap cleans up with --die-with-parent */
    },
    report: linuxReport(spec),
  };
}

export { defaultWorkspace };
