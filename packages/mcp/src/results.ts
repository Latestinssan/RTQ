/**
 * MCP result normalization (spec 46.12).
 *
 * MCP results are UNTRUSTED DATA. This module enforces:
 *   - maximum serialized result size (denied or truncated per configuration)
 *   - maximum nested depth
 *   - JSON serializability (no BigInt/functions/cycles)
 *   - secret detection + redaction (data never leaves with raw secret-shaped
 *     values unless the deployment explicitly configures otherwise)
 *   - prompt-injection-like content detection (ADVISORY flag only — a flag
 *     NEVER authorizes anything and never changes RTQ state)
 *   - provenance metadata (server, tool, invocation, ticket, schema hash)
 */
import { redactValue, canonicalStringify } from "@rtq/crypto";
import { uuidV4 } from "@rtq/crypto";
import type {
  McpNormalizedResult,
  McpQualityFlags,
  McpResultProvenance,
} from "./types";

export interface NormalizeResultOptions {
  maxBytes?: number;
  maxDepth?: number;
  /** When true, oversized results are truncated to fit; otherwise denied. */
  truncate?: boolean;
  strictJson?: boolean;
}

export interface NormalizeResultOutcome {
  result: McpNormalizedResult;
  denied: false;
}

export interface NormalizeResultDenied {
  denied: true;
  code: string;
  reason: string;
  rawRejected: boolean;
}

export type NormalizeResult = NormalizeResultOutcome | NormalizeResultDenied;

function isPlainRecord(v: unknown): v is Record<string, unknown> {
  if (v === null || typeof v !== "object") return false;
  const proto = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
}

/** True when the value is fully JSON-serializable (no functions, BigInt, cycles). */
export function isJsonSerializable(
  value: unknown,
  depth = 0,
  seen = new Set<object>(),
): boolean {
  if (value === null || value === undefined) return true;
  if (typeof value === "string" || typeof value === "boolean") return true;
  if (typeof value === "number") return Number.isFinite(value);
  if (
    typeof value === "bigint" ||
    typeof value === "function" ||
    typeof value === "symbol"
  )
    return false;
  if (depth > 512) return false;
  if (typeof value === "object") {
    if (seen.has(value)) return false; // cycle
    seen.add(value);
    if (Array.isArray(value)) {
      return value.every((item) => isJsonSerializable(item, depth + 1, seen));
    }
    if (isPlainRecord(value)) {
      return Object.values(value).every((item) =>
        isJsonSerializable(item, depth + 1, seen),
      );
    }
    return false; // Date/Map/Set/custom class instances are not plain JSON data
  }
  return false;
}

const INJECTION_PATTERNS: RegExp[] = [
  /\bignore\s+(?:all\s+)?previous\s+(?:instructions|prompts)\b/i,
  /\bignore\s+your\s+(?:instructions|system\s+prompt|prompt)\b/i,
  /\bnew\s+instructions?\s*[:=]/i,
  /\bdo\s+not\s+(?:follow|obey)\b/i,
  /\bdisregard\b/i,
  /\bupload\s+(?:~\/\.ssh|c:\\)/i,
  /\bexfiltrat/i,
  /\bsend\s+(?:my\s+)?(?:credentials|passwords?|api\s+keys?|tokens?)\b/i,
  /\bdisable\s+(?:the\s+)?(?:security|sandbox|firewall|audit)/i,
  /\bleak\s+(?:all\s+)?(?:your\s+)?(?:env|environment variables|secrets)\b/i,
];

const SECRET_PATTERNS: RegExp[] = [
  /\bBearer\s+[A-Za-z0-9\-._~+/]+=*\b/i,
  /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
  /\bsk-[A-Za-z0-9]{16,}\b/,
  /\b[A-Za-z0-9\-._~+/]{40,}\b/,
];

/** Advisory: does this string contain prompt-injection-like content? */
export function containsInjectionLikeContent(text: string): boolean {
  if (typeof text !== "string" || text.length === 0) return false;
  return INJECTION_PATTERNS.some((re) => re.test(text));
}

/** Advisory: does this string look like it contains secret material? */
export function containsSecretLikeContent(text: string): boolean {
  if (typeof text !== "string" || text.length === 0) return false;
  return SECRET_PATTERNS.some((re) => re.test(text));
}

/** Scan a normalized, JSON-serializable value for flagged content. */
export function scanFlags(value: unknown, flags: McpQualityFlags): void {
  if (value === null || value === undefined) return;
  if (typeof value === "string") {
    if (containsSecretLikeContent(value)) flags.secretsDetected = true;
    if (containsInjectionLikeContent(value)) flags.injectionLike = true;
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) scanFlags(item, flags);
    return;
  }
  if (isPlainRecord(value)) {
    for (const v of Object.values(value)) scanFlags(v, flags);
  }
}

/**
 * Normalize a raw MCP result. Denies (or truncates, when configured) oversized
 * results, redacts secret-shaped values, attaches provenance and flags content.
 */
export function normalizeMcpResult(
  raw: unknown,
  options: NormalizeResultOptions = {},
  provenance: McpResultProvenance,
): NormalizeResult {
  const maxBytes = options.maxBytes ?? 1 * 1024 * 1024;
  const maxDepth = options.maxDepth ?? 12;

  if (!isJsonSerializable(raw)) {
    return {
      denied: true,
      code: "mcp.result.non_json",
      reason: "MCP result is not JSON-serializable",
      rawRejected: true,
    };
  }
  const rawDepth = valueDepthRaw(raw);
  if (rawDepth > maxDepth) {
    return {
      denied: true,
      code: "mcp.result.too_deep",
      reason: `MCP result exceeds max depth ${maxDepth}`,
      rawRejected: true,
    };
  }
  const serialized = canonicalStringify(raw);
  const size = Buffer.byteLength(serialized, "utf8");
  const contentTooLarge = size > maxBytes;
  if (contentTooLarge && !options.truncate) {
    return {
      denied: true,
      code: "mcp.result.too_large",
      reason: `MCP result exceeds max size ${maxBytes} bytes (${size} actual)`,
      rawRejected: true,
    };
  }

  let data: unknown = raw;
  let truncated = false;
  if (contentTooLarge && options.truncate) {
    data = truncateToBytes(raw, maxBytes, maxDepth);
    truncated = true;
  }

  const flags: McpQualityFlags = {
    truncated,
    secretsDetected: false,
    injectionLike: false,
    contentTooLarge,
  };
  // Advisory flags are detected on the RAW result as it arrived from the
  // server; redaction happens afterwards for the data delivered to callers.
  // A flag NEVER authorizes anything and never changes RTQ state.
  scanFlags(data, flags);

  // Redaction: secret-shaped values are scrubbed from the data that reaches
  // the consuming application. This is data protection, not authorization.
  const redacted = redactValue(data) as unknown;

  return {
    denied: false,
    result: {
      data: redacted,
      provenance: {
        ...provenance,
        invocationId:
          typeof provenance.invocationId === "string" &&
          provenance.invocationId.length > 0
            ? provenance.invocationId
            : uuidV4(),
      },
      flags,
    },
  };
}

/** Depth of a value (objects/arrays count as one level each). */
function valueDepthRaw(value: unknown, current = 0): number {
  if (current > 100_000) return current;
  if (Array.isArray(value)) {
    let max = current + 1;
    for (const item of value)
      max = Math.max(max, valueDepthRaw(item, current + 1));
    return max;
  }
  if (isPlainRecord(value)) {
    let max = current + 1;
    for (const v of Object.values(value))
      max = Math.max(max, valueDepthRaw(v, current + 1));
    return max;
  }
  return current + 1;
}

/** Truncate a value to fit within maxBytes by trimming strings and arrays. */
function truncateToBytes(
  value: unknown,
  maxBytes: number,
  maxDepth: number,
): unknown {
  const budget = maxBytes;
  return clamp(value, budget, maxDepth, 0);
}

function clamp(
  value: unknown,
  budget: number,
  maxDepth: number,
  depth: number,
): unknown {
  if (depth > maxDepth) return "...";
  if (typeof value === "string") {
    const bytes = Buffer.byteLength(value, "utf8");
    if (bytes <= budget) return value;
    // Shrink the string until it fits (UTF-8 aware-ish: cut and re-measure).
    let end = Math.floor(value.length / 2);
    let step = Math.floor(value.length / 4);
    while (step >= 1) {
      while (
        end + step < value.length &&
        Buffer.byteLength(value.slice(0, end + step), "utf8") <= budget
      ) {
        end += step;
      }
      step = Math.floor(step / 2);
    }
    return value.slice(0, end) + "…[truncated]";
  }
  if (Array.isArray(value)) {
    const out: unknown[] = [];
    let used = 0;
    for (const item of value) {
      const serialized = canonicalStringify(item);
      const size = Buffer.byteLength(serialized, "utf8");
      if (used + size > budget) {
        out.push("…[truncated]");
        break;
      }
      used += size;
      out.push(clamp(item, budget - used, maxDepth, depth + 1));
    }
    return out;
  }
  if (isPlainRecord(value)) {
    const out: Record<string, unknown> = {};
    let used = 0;
    for (const [key, v] of Object.entries(value)) {
      const serialized = canonicalStringify(v);
      const size = Buffer.byteLength(serialized, "utf8");
      if (used + size > budget) {
        out["$truncated"] = true;
        break;
      }
      used += size;
      out[key] = clamp(v, budget - used, maxDepth, depth + 1);
    }
    return out;
  }
  return value;
}
