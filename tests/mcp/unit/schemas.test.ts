import { describe, expect, it } from "vitest";
import {
  buildSchemaNormalizationLimits,
  canonicalInputSize,
  computeToolSchemaHash,
  normalizeToolSchema,
  validateToolArguments,
  valueDepth,
} from "@rtq/mcp";

type Props = Record<string, unknown>;
function propsOf(schema: Record<string, unknown>): Props {
  return (schema.properties as Props) ?? {};
}

describe("normalizeToolSchema", () => {
  it("normalizes a simple object schema with additionalProperties:false by default", () => {
    const result = normalizeToolSchema({
      type: "object",
      properties: { path: { type: "string" } },
      required: ["path"],
    });
    expect(result.incomplete).toBe(false);
    expect(result.schema.additionalProperties).toBe(false);
    expect(propsOf(result.schema)).toMatchObject({
      path: { type: "string", maxLength: 65536 },
    });
    expect(result.schema.required).toEqual(["path"]);
  });

  it("treats schemas without a top-level type as objects", () => {
    const result = normalizeToolSchema({
      properties: { a: { type: "string" } },
    });
    expect(result.incomplete).toBe(false);
    expect(result.schema.type).toBe("object");
  });

  it("marks non-object top-level schemas incomplete (fail closed)", () => {
    const result = normalizeToolSchema({ type: "string" });
    expect(result.incomplete).toBe(true);
    expect(result.reasons.length).toBeGreaterThan(0);
  });

  it("rejects non-object input entirely", () => {
    const result = normalizeToolSchema("nope");
    expect(result.incomplete).toBe(true);
    expect(result.schema).toMatchObject({
      type: "object",
      additionalProperties: false,
    });
  });

  it("flags $ref as unsupported (fail closed)", () => {
    const result = normalizeToolSchema({
      type: "object",
      properties: { ref: { $ref: "#/definitions/x" } },
    });
    expect(result.incomplete).toBe(true);
    expect(result.reasons.some((r) => r.includes("$ref"))).toBe(true);
  });

  it("flags conditional schemas as unsupported", () => {
    const result = normalizeToolSchema({
      type: "object",
      properties: { a: { type: "string", if: { type: "string" } } },
    });
    expect(result.incomplete).toBe(true);
  });

  it("flags anyOf with complex variants as unsupported, maps simple unions", () => {
    const complex = normalizeToolSchema({
      type: "object",
      properties: {
        a: {
          anyOf: [
            { type: "string" },
            { type: "object", properties: { x: { type: "number" } } },
          ],
        },
      },
    });
    expect(complex.incomplete).toBe(true);
    const simple = normalizeToolSchema({
      type: "object",
      properties: {
        b: { anyOf: [{ type: "string" }, { type: "number" }] },
      },
    });
    expect(simple.incomplete).toBe(false);
    expect(propsOf(simple.schema).b).toHaveProperty("oneOf");
  });

  it("caps declared maxLength/maxItems at RTQ limits", () => {
    const result = normalizeToolSchema({
      type: "object",
      properties: {
        s: { type: "string", maxLength: 10_000_000 },
        arr: { type: "array", items: { type: "string" }, maxItems: 10_000 },
      },
    });
    const s = propsOf(result.schema).s as Record<string, unknown>;
    const arr = propsOf(result.schema).arr as Record<string, unknown>;
    expect(s.maxLength).toBe(64 * 1024);
    expect(arr.maxItems).toBe(1000);
  });

  it("applies default caps when the server declares none", () => {
    const result = normalizeToolSchema({
      type: "object",
      properties: {
        raw: { type: "string" },
        items: { type: "array", items: { type: "string" } },
      },
    });
    const props = propsOf(result.schema);
    expect((props.raw as Record<string, unknown>).maxLength).toBe(64 * 1024);
    expect((props.items as Record<string, unknown>).maxItems).toBe(1000);
  });

  it("rejects prototype-pollution keys", () => {
    // The attack arrives as parsed JSON wire data, where "__proto__" is a
    // genuine own property (an object literal would set the prototype).
    const wire = JSON.parse(
      '{"type":"object","properties":{"__proto__":{"type":"string"}}}',
    ) as Record<string, unknown>;
    const result = normalizeToolSchema(wire);
    expect(result.incomplete).toBe(true);
    expect(Object.keys(propsOf(result.schema))).not.toContain("__proto__");
  });

  it("rejects non-finite numbers in schemas", () => {
    const result = normalizeToolSchema({
      type: "object",
      properties: { n: { type: "number", max: NaN } },
    });
    expect(result.incomplete).toBe(true);
  });

  it("flags additionalProperties:true as unsupported by default", () => {
    const result = normalizeToolSchema({
      type: "object",
      properties: { a: { type: "string" } },
      additionalProperties: true,
    });
    expect(result.incomplete).toBe(true);
  });

  it("preserves explicit additionalProperties:false as a no-op", () => {
    const result = normalizeToolSchema({
      type: "object",
      properties: { a: { type: "string" } },
      additionalProperties: false,
    });
    expect(result.incomplete).toBe(false);
    expect(result.schema.additionalProperties).toBe(false);
  });

  it("rejects tuple-form array items (fail closed)", () => {
    const result = normalizeToolSchema({
      type: "object",
      properties: {
        pair: {
          type: "array",
          items: [{ type: "string" }, { type: "number" }],
        },
      },
    });
    expect(result.incomplete).toBe(true);
  });

  it("maps const to a literal schema", () => {
    const result = normalizeToolSchema({
      type: "object",
      properties: { mode: { const: "read" } },
    });
    const mode = propsOf(result.schema).mode as Record<string, unknown>;
    expect(mode.type).toBe("literal");
    expect(mode.value).toBe("read");
  });

  it("handles nullable via oneOf", () => {
    const result = normalizeToolSchema({
      type: "object",
      properties: { maybe: { type: "string", nullable: true } },
    });
    const maybe = propsOf(result.schema).maybe as Record<string, unknown>;
    expect(maybe.oneOf).toEqual([
      { type: "string", maxLength: 65536 },
      { type: "null" },
    ]);
  });

  it("flags schemas exceeding the depth limit as incomplete", () => {
    const deep: { type: "object"; properties: Record<string, unknown> } = {
      type: "object",
      properties: {},
    };
    let node = deep;
    for (let i = 0; i < 40; i++) {
      node.properties = { n: deep };
      node = node.properties.n as typeof deep;
    }
    const result = normalizeToolSchema(deep);
    expect(result.incomplete).toBe(true);
    expect(result.reasons.some((r) => r.includes("depth"))).toBe(true);
  });

  it("flags an empty node as incomplete but still returns a usable schema", () => {
    const result = normalizeToolSchema({
      type: "object",
      properties: { loose: {} },
    });
    expect(result.incomplete).toBe(true);
    const loose = propsOf(result.schema).loose as Record<string, unknown>;
    expect(loose.type).toBe("any");
  });
});

describe("validateToolArguments", () => {
  it("validates arguments against normalized schema and rejects unknown keys", () => {
    const { schema } = normalizeToolSchema({
      type: "object",
      properties: { a: { type: "string" }, b: { type: "number" } },
      required: ["a"],
    });
    expect(validateToolArguments({ a: "x", b: 2 }, schema).valid).toBe(true);
    const r = validateToolArguments({ a: "x", b: 2, evil: true }, schema);
    expect(r.valid).toBe(false);
    if (!r.valid)
      expect(r.errors[0].message).toMatch(
        /unknown property|additionalProperties/,
      );
    expect(validateToolArguments({ b: 2 }, schema).valid).toBe(false); // missing required
  });

  it("enforces capped string lengths", () => {
    const { schema } = normalizeToolSchema({
      type: "object",
      properties: { s: { type: "string" } },
    });
    const r = validateToolArguments({ s: "x".repeat(70_000) }, schema);
    expect(r.valid).toBe(false);
  });
});

describe("computeToolSchemaHash", () => {
  it("is stable for identical inputs", () => {
    const a = computeToolSchemaHash({
      name: "t",
      description: "d",
      normalizedSchema: { type: "object" },
    });
    const b = computeToolSchemaHash({
      name: "t",
      description: "d",
      normalizedSchema: { type: "object" },
    });
    expect(a).toBe(b);
  });

  it("changes when security-relevant metadata changes", () => {
    const base = {
      name: "t",
      description: "d",
      normalizedSchema: { type: "object" },
    };
    const n1 = computeToolSchemaHash(base);
    const n2 = computeToolSchemaHash({ ...base, description: "changed" });
    const n3 = computeToolSchemaHash({
      ...base,
      declaredCapabilities: ["write"],
    });
    expect(n1).not.toBe(n2);
    expect(n1).not.toBe(n3);
  });
});

describe("buildSchemaNormalizationLimits and valueDepth", () => {
  it("builds defaults", () => {
    const limits = buildSchemaNormalizationLimits(undefined, false);
    expect(limits.maxSchemaDepth).toBe(24);
    expect(limits.maxStringLength).toBe(64 * 1024);
    expect(limits.maxItems).toBe(1000);
    expect(limits.maxProperties).toBe(256);
  });

  it("measures depth with cycles bounded", () => {
    expect(valueDepth(null)).toBe(1);
    expect(valueDepth({ a: { b: { c: 1 } } })).toBe(4);
    expect(valueDepth([1, [2, [3]]])).toBe(4);
  });

  it("measures canonical input size", () => {
    // canonicalStringify({ a: "hello" }) === '{"a":"hello"}' (13 bytes)
    expect(canonicalInputSize({ a: "hello" })).toBe(13);
    expect(canonicalInputSize(null)).toBe(4);
  });
});
