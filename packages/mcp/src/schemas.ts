/**
 * MCP tool schema normalization and validation (spec 46.4).
 *
 * The server-provided schema is UNTRUSTED. RTQ normalizes it into the RTQ
 * schema dialect with hardening applied:
 *   - `additionalProperties: false` by default (unexpected fields denied)
 *   - bounded string/array lengths (RTQ caps applied when the server declares
 *     none)
 *   - depth limits on both the schema itself and validated values
 *   - prototype-pollution keys and non-finite numbers rejected
 *   - unsupported/ambiguous constructs ($ref, anyOf with overlaps, unknown
 *     types) mark the schema INCOMPLETE -> the tool fails closed at
 *     registration unless policy explicitly approves it
 *
 * Schema VALIDITY is never authorization (46.4): a valid argument can still be
 * a dangerous operation. This module only shapes and validates arguments.
 */
import { canonicalStringify, sha256Hex } from "@rtq/crypto";
import { validateAgainstSchema, type ValidationResult } from "@rtq/core";
import { DEFAULT_MCP_LIMITS, type McpLimits } from "./types";

export interface SchemaNormalizationLimits {
  maxSchemaDepth?: number;
  maxValueDepth?: number;
  maxStringLength?: number;
  maxItems?: number;
  maxProperties?: number;
}

export interface NormalizedToolSchema {
  schema: Record<string, unknown>;
  incomplete: boolean;
  reasons: string[];
}

const UNSAFE_KEYS = new Set(["__proto__", "constructor", "prototype"]);

function isObject(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

function checkSafeKeys(
  node: Record<string, unknown>,
  path: string,
  reasons: string[],
): boolean {
  for (const key of Object.keys(node)) {
    if (UNSAFE_KEYS.has(key)) {
      reasons.push(`${path}.${key}: unsafe schema key`);
      return false;
    }
  }
  return true;
}

function hasFiniteNumbers(
  node: unknown,
  path: string,
  reasons: string[],
): boolean {
  if (typeof node === "number") {
    if (!Number.isFinite(node)) {
      reasons.push(`${path}: non-finite number in schema`);
      return false;
    }
    return true;
  }
  if (Array.isArray(node)) {
    return node.every((item, i) =>
      hasFiniteNumbers(item, `${path}[${i}]`, reasons),
    );
  }
  if (isObject(node)) {
    return Object.entries(node).every(([k, v]) =>
      hasFiniteNumbers(v, `${path}.${k}`, reasons),
    );
  }
  return true;
}

function depthOf(node: unknown, current = 0): number {
  if (current > 100) return current;
  if (Array.isArray(node)) {
    let max = current + 1;
    for (const item of node) max = Math.max(max, depthOf(item, current + 1));
    return max;
  }
  if (isObject(node)) {
    let max = current + 1;
    for (const v of Object.values(node))
      max = Math.max(max, depthOf(v, current + 1));
    return max;
  }
  return current + 1;
}

/**
 * Normalize a raw JSON-Schema-ish tool schema into the RTQ dialect.
 * Returns `incomplete: true` with reasons when constructs cannot be mapped
 * safely; the caller decides whether to fail closed or require policy approval.
 */
export function normalizeToolSchema(
  raw: unknown,
  limits: SchemaNormalizationLimits = {},
): NormalizedToolSchema {
  const reasons: string[] = [];
  const maxDepth = limits.maxSchemaDepth ?? 24;
  const maxStringLength = limits.maxStringLength ?? 64 * 1024;
  const maxItems = limits.maxItems ?? 1000;
  const maxProperties = limits.maxProperties ?? 256;

  const emptySchema: Record<string, unknown> = {
    type: "object",
    properties: {},
    required: [],
    additionalProperties: false,
  };

  if (!isObject(raw)) {
    return {
      schema: emptySchema,
      incomplete: true,
      reasons: ["top-level schema must be an object"],
    };
  }
  if (depthOf(raw) > maxDepth) {
    return {
      schema: emptySchema,
      incomplete: true,
      reasons: [`schema exceeds max depth ${maxDepth}`],
    };
  }
  if (
    !checkSafeKeys(raw, "$", reasons) ||
    !hasFiniteNumbers(raw, "$", reasons)
  ) {
    return { schema: emptySchema, incomplete: true, reasons };
  }

  const ctx: NodeCtx = {
    maxDepth,
    maxStringLength,
    maxItems,
    maxProperties,
    reasons,
  };

  let top: Record<string, unknown>;
  if (raw.type === undefined) {
    top = {
      type: "object",
      properties: normalizeProperties(raw["properties"], "$", ctx),
      required: normalizeRequired(raw["required"], "$", ctx),
      additionalProperties: false,
    };
  } else if (raw.type === "object") {
    top = normalizeNode(raw, "$", ctx);
  } else {
    return {
      schema: emptySchema,
      incomplete: true,
      reasons: [
        `top-level schema type must be an object (got ${JSON.stringify(raw.type)})`,
      ],
    };
  }
  const propCount = Object.keys(
    top["properties"] as Record<string, unknown>,
  ).length;
  if (propCount > maxProperties) {
    reasons.push(`$: more than ${maxProperties} properties`);
    return { schema: emptySchema, incomplete: true, reasons };
  }
  return { schema: top, incomplete: reasons.length > 0, reasons };
}

interface NodeCtx {
  maxDepth: number;
  maxStringLength: number;
  maxItems: number;
  maxProperties: number;
  reasons: string[];
}

function normalizeRequired(
  required: unknown,
  path: string,
  ctx: NodeCtx,
): string[] {
  if (required === undefined) return [];
  if (!Array.isArray(required)) {
    ctx.reasons.push(`${path}: required must be an array of strings`);
    return [];
  }
  const out: string[] = [];
  for (const r of required) {
    if (typeof r !== "string") {
      ctx.reasons.push(`${path}: required entries must be strings`);
    } else if (!UNSAFE_KEYS.has(r)) {
      out.push(r);
    }
  }
  return out;
}

function normalizeNode(
  node: Record<string, unknown>,
  path: string,
  ctx: NodeCtx,
): Record<string, unknown> {
  const out: Record<string, unknown> = {};

  // Unsupported constructs: fail closed (mark incomplete) rather than guess.
  if ("$ref" in node)
    ctx.reasons.push(`${path}: "$ref" is not supported (fail closed)`);
  if ("if" in node || "then" in node || "else" in node) {
    ctx.reasons.push(
      `${path}: conditional schemas (if/then/else) are not supported`,
    );
  }
  if ("allOf" in node)
    ctx.reasons.push(`${path}: "allOf" is not supported (fail closed)`);
  if ("not" in node)
    ctx.reasons.push(`${path}: "not" schemas are not supported (fail closed)`);
  if ("anyOf" in node) {
    const variants = node["anyOf"];
    if (
      Array.isArray(variants) &&
      variants.length > 0 &&
      variants.every(
        (v) =>
          isObject(v) &&
          typeof (v as Record<string, unknown>)["type"] === "string" &&
          Object.keys(v as Record<string, unknown>).every(
            (k) => k === "type" || k === "description",
          ),
      )
    ) {
      // Simple disjoint type unions map cleanly onto oneOf.
      out["oneOf"] = variants.map((v) =>
        normalizeNode(v as Record<string, unknown>, `${path}.anyOf`, ctx),
      );
    } else {
      ctx.reasons.push(
        `${path}: "anyOf" with non-simple variants is not supported (fail closed)`,
      );
    }
  }

  const rawType = node["type"];
  if (
    rawType !== undefined &&
    typeof rawType !== "string" &&
    !(Array.isArray(rawType) && rawType.every((t) => typeof t === "string"))
  ) {
    ctx.reasons.push(`${path}: type must be a string or an array of strings`);
    return {
      ...out,
      type: "any",
      description: "invalid type field (fail closed)",
    };
  }

  let effectiveType: string | undefined;
  if (Array.isArray(rawType)) {
    const unique = [...new Set(rawType as string[])];
    effectiveType = "oneOf";
    const oneOf = unique
      .filter((t) =>
        [
          "string",
          "number",
          "integer",
          "boolean",
          "null",
          "object",
          "array",
          "any",
        ].includes(t),
      )
      .map((t) => normalizeNode({ type: t }, `${path}.type`, ctx));
    out["oneOf"] = oneOf;
    if (oneOf.length === 0) {
      ctx.reasons.push(`${path}: type array contains no supported types`);
    }
  } else if (typeof rawType === "string") {
    effectiveType = rawType;
    out["type"] = rawType;
  }

  switch (effectiveType) {
    case "object": {
      out["properties"] = normalizeProperties(
        node["properties"],
        `${path}.properties`,
        ctx,
      );
      const required = normalizeRequired(node["required"], path, ctx);
      if (required.length > 0) out["required"] = required;
      // RTQ default: unexpected fields are denied. Explicit object-valued
      // additionalProperties is honored as a hardened sub-schema; `true` is
      // rejected (fail closed).
      if ("additionalProperties" in node) {
        const ap = node["additionalProperties"];
        if (ap === true) {
          ctx.reasons.push(
            `${path}: additionalProperties:true is not supported by default (fail closed)`,
          );
          out["additionalProperties"] = false;
        } else if (isObject(ap)) {
          out["additionalProperties"] = normalizeNode(
            ap,
            `${path}.additionalProperties`,
            ctx,
          );
        } else if (ap === false) {
          out["additionalProperties"] = false;
        } else {
          ctx.reasons.push(
            `${path}: additionalProperties must be boolean or object`,
          );
        }
      } else {
        out["additionalProperties"] = false;
      }
      break;
    }
    case "array": {
      if ("items" in node) {
        if (isObject(node["items"])) {
          out["items"] = normalizeNode(
            node["items"] as Record<string, unknown>,
            `${path}.items`,
            ctx,
          );
        } else if (Array.isArray(node["items"])) {
          ctx.reasons.push(
            `${path}: tuple-form items is not supported (fail closed)`,
          );
        }
      }
      const declaredMax =
        typeof node["maxItems"] === "number" ? node["maxItems"] : undefined;
      out["maxItems"] =
        declaredMax !== undefined
          ? Math.min(declaredMax, ctx.maxItems)
          : ctx.maxItems;
      if (typeof node["minItems"] === "number")
        out["minItems"] = node["minItems"];
      break;
    }
    case "string": {
      const declaredMax =
        typeof node["maxLength"] === "number" ? node["maxLength"] : undefined;
      out["maxLength"] =
        declaredMax !== undefined
          ? Math.min(declaredMax, ctx.maxStringLength)
          : ctx.maxStringLength;
      if (typeof node["minLength"] === "number")
        out["minLength"] = node["minLength"];
      if (typeof node["pattern"] === "string") out["pattern"] = node["pattern"];
      if (Array.isArray(node["enum"])) out["enum"] = node["enum"];
      break;
    }
    case "number":
    case "integer": {
      out["type"] = "number";
      if (effectiveType === "integer") out["integer"] = true;
      if (typeof node["min"] === "number") out["min"] = node["min"];
      if (typeof node["max"] === "number") out["max"] = node["max"];
      if (Array.isArray(node["enum"])) out["enum"] = node["enum"];
      break;
    }
    case "boolean":
    case "null":
    case "any":
      break;
    default:
      if (effectiveType !== undefined) {
        ctx.reasons.push(`${path}: unsupported schema type "${effectiveType}"`);
        out["type"] = "any";
      }
  }

  if (
    Array.isArray(node["enum"]) &&
    out["enum"] === undefined &&
    out["oneOf"] === undefined
  ) {
    out["oneOf"] = node["enum"].map((v) => ({ type: "literal", value: v }));
  }
  if ("const" in node) {
    out["type"] = "literal";
    out["value"] = node["const"];
    delete out["enum"];
    delete out["oneOf"];
  }
  if (node["nullable"] === true) {
    if (out["type"] !== undefined && out["type"] !== "null") {
      // Keep the hardened type constraints in the base variant so oneOf
      // validation enforces them against non-null values.
      const base = { ...out };
      out["oneOf"] = [base, { type: "null" }];
      delete out["type"];
    } else if (out["oneOf"] !== undefined) {
      out["oneOf"] = [...(out["oneOf"] as unknown[]), { type: "null" }];
    }
  }
  if (Object.keys(out).length === 0) {
    ctx.reasons.push(`${path}: schema node has no supported constraints`);
    out["type"] = "any";
  }
  return out;
}

function normalizeProperties(
  properties: unknown,
  path: string,
  ctx: NodeCtx,
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  if (!isObject(properties)) {
    if (properties !== undefined)
      ctx.reasons.push(`${path}: properties must be an object`);
    return out;
  }
  for (const [key, value] of Object.entries(properties)) {
    if (UNSAFE_KEYS.has(key)) {
      ctx.reasons.push(`${path}.${key}: unsafe property key`);
      continue;
    }
    if (isObject(value)) {
      out[key] = normalizeNode(value, `${path}.${key}`, ctx);
    } else {
      ctx.reasons.push(`${path}.${key}: property schema must be an object`);
    }
  }
  return out;
}

/** SHA-256 over canonical, security-relevant tool metadata (46.7). */
export function computeToolSchemaHash(params: {
  name: string;
  description: string;
  normalizedSchema: Record<string, unknown>;
  declaredCapabilities?: readonly string[];
}): string {
  return sha256Hex(
    canonicalStringify({
      name: params.name,
      description: params.description,
      schema: params.normalizedSchema,
      declaredCapabilities: params.declaredCapabilities ?? [],
    }),
  );
}

/** Validate arguments against the RTQ-normalized schema. */
export function validateToolArguments(
  args: unknown,
  schema: Record<string, unknown>,
): ValidationResult {
  return validateAgainstSchema(args, schema);
}

/** Serialized byte size of canonicalized arguments (enforced pre-auth). */
export function canonicalInputSize(args: unknown): number {
  const canonical = canonicalStringify(args);
  return Buffer.byteLength(canonical, "utf8");
}

export function valueDepth(value: unknown, current = 0): number {
  if (current > 100_000) return current;
  if (Array.isArray(value)) {
    let max = current + 1;
    for (const item of value)
      max = Math.max(max, valueDepth(item, current + 1));
    return max;
  }
  if (isObject(value)) {
    let max = current + 1;
    for (const v of Object.values(value))
      max = Math.max(max, valueDepth(v, current + 1));
    return max;
  }
  return current + 1;
}

export function buildSchemaNormalizationLimits(
  limits: McpLimits | undefined,
  _allowIncomplete: boolean,
): SchemaNormalizationLimits {
  return {
    maxSchemaDepth: 24,
    maxValueDepth: limits?.maxDepth ?? DEFAULT_MCP_LIMITS.maxDepth,
    maxStringLength: 64 * 1024,
    maxItems: 1000,
    maxProperties: 256,
  };
}
