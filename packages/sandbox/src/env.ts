import os from "os";
import type { EnvironmentSpec } from "./types";

/**
 * Environment security.
 *
 * Sandboxed processes never inherit arbitrary host environment variables.
 * The environment is CONSTRUCTED explicitly from an allowlist. Variables that
 * carry ambient credentials (api keys, tokens, cloud credentials, private
 * keys, passwords) are never exposed, even if present in the host
 * environment. `deny` entries are removed even when allowlisted.
 *
 * This is a policy construction layer: the OS sandbox additionally isolates
 * the environment where the platform supports it.
 */

/** Default safe keys — functional, non-secret host variables. */
export const DEFAULT_SAFE_ENV_KEYS: readonly string[] = [
  "PATH",
  "HOME",
  "USER",
  "LANG",
  "LC_ALL",
  "TMPDIR",
  "SHELL",
  "TERM",
  "COLORTERM",
  "EDITOR",
  "VISUAL",
];

/** Windows bootstrap keys required to launch native processes; never credentials. */
export const WINDOWS_SAFE_ENV_KEYS: readonly string[] = [
  "SystemRoot",
  "SYSTEMROOT",
  "WINDIR",
  "SYSTEMDRIVE",
  "PATHEXT",
  "COMSPEC",
  "TEMP",
  "TMP",
  "USERPROFILE",
  "APPDATA",
  "LOCALAPPDATA",
  "PROGRAMDATA",
  "NUMBER_OF_PROCESSORS",
  "PROCESSOR_ARCHITECTURE",
  "PROCESSOR_IDENTIFIER",
];

const SECRET_NAME_PATTERN =
  /(?:key|secret|token|password|passwd|pwd|pin|credential|auth|bearer|cookie|session)/i;

export interface BuildEnvironmentOptions {
  spec?: EnvironmentSpec;
  /** Explicit extra variables the CALLER wants the process to see. Only
   *  allow-listed keys are honored; secret-shaped keys are dropped. */
  extraEnv?: Record<string, string>;
  platform?: string;
}

/** Drop duplicate keys case-insensitively (Windows env is case-insensitive). */
function dedupe(env: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  const seen = new Map<string, string>();
  for (const [key, value] of Object.entries(env)) {
    const folded = key.toLowerCase();
    if (!seen.has(folded)) seen.set(folded, key);
    out[seen.get(folded)!] = value;
  }
  return out;
}

function looksSecret(name: string): boolean {
  return SECRET_NAME_PATTERN.test(name);
}

export function buildSandboxEnvironment(
  options: BuildEnvironmentOptions = {},
): Record<string, string> {
  const platform = options.platform ?? process.platform;
  const spec = options.spec ?? {};
  const allow = new Set<string>(spec.allow ?? []);
  const deny = new Set<string>((spec.deny ?? []).map((d) => d.toLowerCase()));

  const safe: Record<string, string> = {};
  const allowedKeys = new Set<string>();

  const consider = (key: string): boolean => {
    const folded = key.toLowerCase();
    if (deny.has(folded)) return false;
    if (looksSecret(key)) return false;
    return true;
  };

  // Base safe keys are always eligible when present in the host env.
  for (const key of [
    ...DEFAULT_SAFE_ENV_KEYS,
    ...(platform === "win32" ? WINDOWS_SAFE_ENV_KEYS : []),
  ]) {
    if (allow.has(key) || DEFAULT_SAFE_ENV_KEYS.includes(key)) {
      allowedKeys.add(key);
    }
  }
  for (const key of allow) allowedKeys.add(key);

  for (const key of allowedKeys) {
    if (!consider(key)) continue;
    const value = process.env[key];
    if (value !== undefined) safe[key] = value;
  }

  safe.HOME = process.env.HOME ?? os.homedir();
  safe.TMPDIR = process.env.TMPDIR ?? os.tmpdir();

  // Extra env from the caller: only allow-listed, non-secret keys pass.
  for (const [key, value] of Object.entries(options.extraEnv ?? {})) {
    const folded = key.toLowerCase();
    if (deny.has(folded)) continue;
    if (!allowedKeys.has(key) && !DEFAULT_SAFE_ENV_KEYS.includes(key)) continue;
    if (looksSecret(key)) continue;
    safe[key] = value;
  }

  return dedupe(safe);
}

/** Report which host variables were dropped (for audit/diagnostics). */
export function describeEnvironmentDrops(
  spec: EnvironmentSpec | undefined,
  extraEnv: Record<string, string> | undefined,
): string[] {
  const drops: string[] = [];
  const allowed = new Set<string>([
    ...(spec?.allow ?? []),
    ...DEFAULT_SAFE_ENV_KEYS,
  ]);
  for (const key of Object.keys(extraEnv ?? {})) {
    if (!allowed.has(key) || looksSecret(key)) drops.push(key);
  }
  for (const deny of spec?.deny ?? []) {
    if (
      process.env[deny] !== undefined ||
      (extraEnv && extraEnv[deny] !== undefined)
    ) {
      drops.push(deny);
    }
  }
  return drops;
}
