import { describe, expect, it } from "vitest";
import { validateAgainstSchema } from "@rtq/core";

const fileSchema = {
  type: "object",
  properties: {
    path: { type: "string", minLength: 1, maxLength: 4096 },
    recursive: { type: "boolean" },
    mode: { type: "number", integer: true, min: 0, max: 0o7777 },
    tags: {
      type: "array",
      items: { type: "string" },
      minItems: 0,
      maxItems: 10,
    },
    kind: { type: "string", enum: ["file", "dir"] },
    target: {
      oneOf: [{ type: "string" }, { type: "null" }],
    },
  },
  required: ["path"],
  additionalProperties: false,
};

describe("schema validation", () => {
  it("accepts a valid object", () => {
    const r = validateAgainstSchema(
      {
        path: "/a/b.txt",
        recursive: false,
        tags: ["x"],
        kind: "file",
        target: null,
      },
      fileSchema,
    );
    expect(r.valid).toBe(true);
  });

  it("rejects missing required fields", () => {
    const r = validateAgainstSchema({ recursive: true }, fileSchema);
    expect(r.valid).toBe(false);
    expect(
      (r as { errors: { path: string; message: string }[] }).errors[0]!.message,
    ).toMatch(/missing required field "path"/);
  });

  it("rejects unknown fields when additionalProperties=false", () => {
    const r = validateAgainstSchema({ path: "/a", extra: 1 }, fileSchema);
    expect(r.valid).toBe(false);
  });

  it("rejects prototype-pollution keys", () => {
    const r = validateAgainstSchema(
      { path: "/a", ["__proto__"]: { polluted: 1 } } as never,
      fileSchema,
    );
    expect(r.valid).toBe(false);
  });

  it("rejects non-finite numbers", () => {
    const r = validateAgainstSchema({ path: "/a", mode: NaN }, fileSchema);
    expect(r.valid).toBe(false);
  });

  it("enforces enum and type constraints", () => {
    expect(
      validateAgainstSchema({ path: "/a", kind: "symlink" }, fileSchema).valid,
    ).toBe(false);
    expect(
      validateAgainstSchema({ path: "/a", recursive: "yes" }, fileSchema).valid,
    ).toBe(false);
    expect(
      validateAgainstSchema({ path: "/a", target: "str" }, fileSchema).valid,
    ).toBe(true);
  });

  it("enforces array bounds", () => {
    expect(
      validateAgainstSchema(
        { path: "/a", tags: Array(11).fill("x") },
        fileSchema,
      ).valid,
    ).toBe(false);
  });

  it("enforces oneOf exactly-one semantics", () => {
    const r = validateAgainstSchema({ path: "/a", target: 5 }, fileSchema);
    expect(r.valid).toBe(false); // number matches neither string nor null
  });

  it("rejects unsupported schema types defensively", () => {
    const r = validateAgainstSchema(
      {},
      {
        type: "object",
        properties: { x: { type: "future" } },
        required: ["x"],
      },
    );
    expect(r.valid).toBe(false);
  });
});
