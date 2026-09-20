import { describe, expect, it } from "vitest";
import { CapabilityRegistry } from "@rtq/core";

const def = {
  name: "shell.read",
  version: 1,
  description: "Read a file",
  inputSchema: {
    type: "object",
    properties: { path: { type: "string" } },
    required: ["path"],
  },
  risk: { base: "low" as const },
  execute: async () => ({ ok: true as const }),
};

describe("CapabilityRegistry", () => {
  it("registers capabilities explicitly", () => {
    const r = new CapabilityRegistry();
    r.register(def);
    expect(r.has("shell.read")).toBe(true);
    expect(r.get("shell.read")?.version).toBe(1);
  });

  it("rejects duplicate registration (unregistered surface is not executer-able)", () => {
    const r = new CapabilityRegistry();
    r.register(def);
    expect(() => r.register(def)).toThrow(/already registered/);
  });

  it("replace bumps version and preserves history", () => {
    const r = new CapabilityRegistry();
    r.register(def);
    const next = r.replace({
      ...def,
      execute: async () => ({ ok: true as const }),
    });
    expect(next.version).toBe(2);
    expect(r.get("shell.read")?.version).toBe(2);
    expect(r.getVersion("shell.read", 1)?.version).toBe(1);
  });

  it("throws when replacing an unregistered capability", () => {
    const r = new CapabilityRegistry();
    expect(() => r.replace({ ...def, name: "nope" })).toThrow(/not registered/);
  });

  it("rejects capabilities without an execute function", () => {
    const r = new CapabilityRegistry();
    expect(() => r.register({ ...def, execute: undefined as never })).toThrow(
      /execute/,
    );
  });

  it("rejects invalid versions", () => {
    const r = new CapabilityRegistry();
    expect(() => r.register({ ...def, version: 0 })).toThrow(/version/);
  });

  it("lists a non-empty surface only for registered capabilities", () => {
    const r = new CapabilityRegistry();
    expect(r.getRegisteredCapabilities()).toHaveLength(0);
    r.register(def);
    expect(r.getRegisteredCapabilities()).toHaveLength(1);
  });
});
