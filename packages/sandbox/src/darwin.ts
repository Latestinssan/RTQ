import fs from "fs";
import os from "os";
import path from "path";
import { spawnSync } from "child_process";
import crypto from "crypto";
import {
  SandboxError,
  type EnforcementReport,
  type SandboxSpec,
} from "./types";
import {
  canonicalizePath,
  flattenAllowlist,
  validateAllowlistPaths,
  type AllowlistEntry,
} from "./path";

/**
 * macOS Seatbelt backend (sandbox-exec).
 *
 * The generated profile is closed by default:
 *   - full network denial (IP + AF_UNIX sockets),
 *   - file-read* / file-write* default-denied with explicit re-allows,
 *   - process-exec and file-map-executable confined to an allowlist,
 *   - mount/umount denied,
 *   - signals confined to the sandbox's own self/children.
 *
 * HONEST LIMITATIONS (unchanged from the Aartiq audit):
 *   - profiles start from `(allow default)`; Mach IPC remains default-allowed.
 *   - sandbox-exec is deprecated by Apple.
 *   - Apple Events cannot be filtered by current sandbox-exec.
 */

const SYSTEM_READ_PATHS = [
  "/usr",
  "/bin",
  "/sbin",
  "/System",
  "/Library",
  "/opt",
  "/private/etc",
  "/private/tmp",
  "/private/var/db",
  "/dev",
];
const SYSTEM_EXEC_PATHS = [
  "/usr",
  "/bin",
  "/sbin",
  "/System",
  "/Library",
  "/opt",
];
export const ROOT_LITERALS = [
  "/",
  "/var",
  "/etc",
  "/tmp",
  "/private",
  "/dev",
  "/usr",
  "/bin",
  "/sbin",
  "/System",
  "/private/var/folders",
];

function quote(p: string): string {
  return String(p).replace(/\\/g, "\\\\").replace(/"/g, '\\"');
}

export function generateSeatbeltProfile(
  spec: SandboxSpec,
  workspace: string,
): string {
  if (spec.network !== undefined && spec.network !== "none") {
    throw new SandboxError(
      "SANDBOX_UNAVAILABLE",
      'Domain-level network allowlisting is not supported by macOS Seatbelt; use network: "none"',
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

  const workspaceCanonical =
    canonicalizePath(workspace).canonical || path.normalize(workspace);
  const tmpCanonical = canonicalizePath(os.tmpdir()).canonical || os.tmpdir();
  const sub = (p: string) => `  (subpath "${quote(p)}")`;
  const lit = (p: string) => `  (literal "${quote(p)}")`;

  const readBlock = [
    ...SYSTEM_READ_PATHS.map(sub),
    ...ROOT_LITERALS.map(lit),
    sub("/private/var/folders"),
    sub(workspaceCanonical),
    ...readDirs.map(sub),
  ].join("\n");

  const writeBlock = [
    sub(workspaceCanonical),
    sub("/private/tmp"),
    sub(tmpCanonical),
    lit("/dev/null"),
    ...writeDirs.map(sub),
  ].join("\n");

  // Read-only allowlist entries can never be written (Seatbelt grants deny
  // rules precedence over allow rules, so a deny on the same subpath beats an
  // allow). CRITICAL: a read-only dir that CONTAINS a writable dir must NOT be
  // carved out — its deny would defeat the writable allow beneath it. The RTQ
  // workspace is such an ancestor in the common case, so it remains writable
  // inside the sandbox. That is safe by contract: the workspace is ephemeral
  // and RTQ-owned (see path.ts); user-reachable writable dirs are granted
  // explicitly and are expected to live OUTSIDE the sandbox workspace.
  const carveOuts = readDirs
    .filter((d) => {
      if (writeDirs.includes(d)) return false;
      return !writeDirs.some((w) => w.startsWith(d + path.sep));
    })
    .map((d) => `(deny file-write* (subpath "${quote(d)}"))`)
    .join("\n");

  const execPaths = (spec.filesystem?.execute ?? []).map(
    (p) => canonicalizePath(p).canonical || p,
  );
  const execBlock = [
    ...SYSTEM_EXEC_PATHS.map(sub),
    sub(workspaceCanonical),
    ...execPaths.map(sub),
  ].join("\n");

  const allowExec =
    spec.processes?.spawn === false
      ? "; process spawning denied by policy"
      : `
(allow process-exec*
${execBlock}
)
(allow file-map-executable
${execBlock}
)
(allow process-fork)
`;

  return `
(version 1)
(allow default)

(deny network*)
(deny system-socket)

(deny file-read*)
(deny file-write*)
(deny file-write-mount file-write-umount)

(allow file-read*
${readBlock}
)

(allow file-write*
${writeBlock}
)

${carveOuts}

(deny process-exec*)
(deny file-map-executable)
${allowExec}

(deny signal)
(allow signal (target self))
(allow signal (target children))
`.trim();
}

function validateSeatbeltProfile(
  profilePath: string,
  workspace: string,
): { ok: boolean; code?: string; error?: string } {
  let result;
  try {
    result = spawnSync(
      "/usr/bin/sandbox-exec",
      ["-f", profilePath, "/usr/bin/true"],
      {
        timeout: 10_000,
        encoding: "utf8",
        cwd: workspace,
      },
    );
  } catch (e) {
    return {
      ok: false,
      code: "SANDBOX_SETUP_FAILED",
      error: (e as Error).message,
    };
  }
  if (result.error) {
    if ((result.error as NodeJS.ErrnoException).code === "ENOENT") {
      return {
        ok: false,
        code: "SANDBOX_UNAVAILABLE",
        error: "sandbox-exec not found",
      };
    }
    return {
      ok: false,
      code: "SANDBOX_SETUP_FAILED",
      error: result.error.message,
    };
  }
  if (result.status !== 0) {
    return {
      ok: false,
      code: "SANDBOX_POLICY_INVALID",
      error: (
        result.stderr ||
        result.stdout ||
        "profile failed to compile"
      ).trim(),
    };
  }
  return { ok: true };
}

export function darwinReport(spec: SandboxSpec): EnforcementReport {
  return {
    isolation: {
      filesystem: true,
      network: true,
      process: spec.processes?.spawn === false ? false : true,
      environment: true,
    },
    platform: "darwin",
    backend: "seatbelt",
    verified: true,
    notes: [
      "Mach IPC is default-allowed (cannot be fully denied by sandbox-exec).",
      "Apple Events cannot be filtered by sandbox-exec.",
      "sandbox-exec is deprecated by Apple.",
    ],
  };
}

/* Build a verified Seatbelt launch config (throws SandboxError -> fail closed). */
export function createDarwinSandbox(
  spec: SandboxSpec,
  workspace: string,
  env: Record<string, string>,
  timeoutMs: number,
  command: string,
  args: readonly string[],
): {
  command: string;
  args: string[];
  spawnOptions: Record<string, unknown>;
  cleanup: () => void;
  report: EnforcementReport;
} {
  if (!fs.existsSync("/usr/bin/sandbox-exec")) {
    throw new SandboxError(
      "SANDBOX_UNAVAILABLE",
      "sandbox-exec is not available on this system",
    );
  }
  try {
    fs.accessSync("/usr/bin/sandbox-exec", fs.constants.X_OK);
  } catch {
    throw new SandboxError(
      "SANDBOX_UNAVAILABLE",
      "sandbox-exec is not executable",
    );
  }

  const profile = generateSeatbeltProfile(spec, workspace);
  const profilePath = path.join(
    os.tmpdir(),
    `rtq-sandbox-${process.pid}-${Date.now()}-${crypto.randomBytes(4).toString("hex")}.sb`,
  );
  fs.writeFileSync(profilePath, profile, { encoding: "utf8", mode: 0o600 });

  const validation = validateSeatbeltProfile(profilePath, workspace);
  if (!validation.ok) {
    try {
      fs.unlinkSync(profilePath);
    } catch {
      /* best effort */
    }
    throw new SandboxError(
      (validation.code as SandboxError["code"]) ?? "SANDBOX_SETUP_FAILED",
      `Seatbelt profile validation failed: ${validation.error}`,
    );
  }

  return {
    command: "/usr/bin/sandbox-exec",
    args: ["-f", profilePath, command, ...args],
    spawnOptions: {
      env,
      cwd: workspace,
      timeout: timeoutMs,
    },
    cleanup: () => {
      try {
        fs.unlinkSync(profilePath);
      } catch {
        /* best effort */
      }
    },
    report: darwinReport(spec),
  };
}
