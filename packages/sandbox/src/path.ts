import fs from "fs";
import os from "os";
import path from "path";
import { SandboxError } from "./types";

/**
 * Filesystem policy layer.
 *
 * Paths are canonicalized before authorization:
 *   - `~` expansion,
 *   - absolute resolution,
 *   - symlink following via realpath (with parent-resolution fallback for
 *     not-yet-existing targets),
 *   - separator-boundary prefix matching (so `/workspace` never authorizes
 *     `/workspace-evil`).
 *
 * The allowlist is the POLICY layer. The OS sandbox provides the actual
 * enforcement boundary wherever the platform supports it.
 */

export interface CanonicalPath {
  canonical: string;
  resolved: boolean;
  exists: boolean;
}

/** Canonicalize a path: expand `~`, resolve symlinks, normalize. */
export function canonicalizePath(requestedPath: string): CanonicalPath {
  if (!requestedPath || typeof requestedPath !== "string") {
    throw new SandboxError(
      "SANDBOX_POLICY_INVALID",
      "Path must be a non-empty string",
    );
  }
  const expanded = requestedPath.replace(/^~(?=\/|$)|^~(?=\\|$)/, os.homedir());
  const abs = path.resolve(expanded);
  try {
    const real = fs.realpathSync(abs);
    return { canonical: real, resolved: true, exists: true };
  } catch {
    try {
      const parent = fs.realpathSync(path.dirname(abs));
      return {
        canonical: path.join(parent, path.basename(abs)),
        resolved: false,
        exists: false,
      };
    } catch {
      try {
        fs.statSync(abs);
        return { canonical: abs, resolved: false, exists: true };
      } catch {
        return {
          canonical: path.normalize(abs),
          resolved: false,
          exists: false,
        };
      }
    }
  }
}

export type AccessOp = "read" | "write" | "delete" | "execute";

export interface AllowlistEntry {
  path: string;
  access: AccessOp | AccessOp[];
  recursive?: boolean;
}

export interface PathCheckResult {
  allowed: boolean;
  reason: string;
  canonical: string;
  matchedEntry: AllowlistEntry | null;
}

const ACCESS_RANK: Record<AccessOp, number> = {
  read: 0,
  execute: 1,
  write: 2,
  delete: 3,
};

function entryGrants(entry: AllowlistEntry, op: AccessOp): boolean {
  const ops = Array.isArray(entry.access) ? entry.access : [entry.access];
  if (ops.includes(op)) return true;
  // write implies delete for entities inside a writable tree? NO. RTQ keeps
  // delete separate from write: a write grant does NOT imply delete.
  return false;
}

function isWithin(
  canonical: string,
  entryCanonical: string,
  recursive: boolean,
): boolean {
  if (canonical === entryCanonical) return true;
  if (!recursive) return path.dirname(canonical) === entryCanonical;
  const sep = path.sep;
  return canonical.startsWith(entryCanonical + sep);
}

/**
 * Check whether a path is allowed for an operation given an allowlist.
 * Denies when any segment is a symlink that escapes the boundary (the policy
 * layer uses canonical paths; enforcement lives in the OS sandbox).
 */
export function isPathAllowed(
  requestedPath: string,
  allowlist: readonly AllowlistEntry[],
  operation: AccessOp,
): PathCheckResult {
  const { canonical } = canonicalizePath(requestedPath);
  if (!canonical) {
    return {
      allowed: false,
      reason: "Could not resolve path",
      canonical,
      matchedEntry: null,
    };
  }
  if (!allowlist || allowlist.length === 0) {
    return {
      allowed: false,
      reason: "Empty allowlist",
      canonical,
      matchedEntry: null,
    };
  }
  for (const entry of allowlist) {
    const entryCanonical = canonicalizePath(entry.path).canonical;
    if (!entryCanonical) continue;
    const recursive = entry.recursive !== false;
    if (
      isWithin(canonical, entryCanonical, recursive) &&
      entryGrants(entry, operation)
    ) {
      return { allowed: true, reason: "", canonical, matchedEntry: entry };
    }
  }
  return {
    allowed: false,
    reason: `Path "${requestedPath}" is not authorized for ${operation}`,
    canonical,
    matchedEntry: null,
  };
}

/** Split an allowlist into distinct read/write/delete/execute directory sets. */
export function flattenAllowlist(
  allowlist: readonly AllowlistEntry[],
): Record<AccessOp, string[]> {
  const sets: Record<AccessOp, Set<string>> = {
    read: new Set(),
    write: new Set(),
    delete: new Set(),
    execute: new Set(),
  };
  for (const entry of allowlist) {
    const canonical = canonicalizePath(entry.path).canonical;
    if (!canonical) continue;
    const ops = Array.isArray(entry.access) ? entry.access : [entry.access];
    for (const op of ops) sets[op].add(canonical);
  }
  return {
    read: [...sets.read],
    write: [...sets.write],
    delete: [...sets.delete],
    execute: [...sets.execute],
  };
}

/** Validate that every allowlist path exists and is a directory (fail-closed policy errors). */
export function validateAllowlistPaths(
  allowlist: readonly AllowlistEntry[],
): void {
  for (const entry of allowlist) {
    const c = canonicalizePath(entry.path);
    if (!c.exists || !fs.statSync(c.canonical).isDirectory()) {
      throw new SandboxError(
        "SANDBOX_POLICY_INVALID",
        `Allowlisted path does not exist or is not a directory: ${entry.path}`,
      );
    }
  }
}

/** Default workspace for sandbox cwd. */
export function defaultWorkspace(): string {
  return path.join(os.tmpdir(), `rtq-workspace-${process.pid}`);
}
