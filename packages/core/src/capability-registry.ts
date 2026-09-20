import type {
  CapabilityDef,
  RegisteredCapabilitySummary,
  Schema,
} from "./types";

export const DUPLICATE_CAPABILITY = "capability.already.registered";
export const UNKNOWN_CAPABILITY = "capability.not.registered";

/**
 * Capability registry.
 *
 * An unregistered capability must not exist as an executable surface.
 * `register` rejects duplicate names; `replace` is the ONLY way to change a
 * registered capability and it bumps the version, invalidating every ticket
 * bound to the previous version.
 */
export class CapabilityRegistry {
  private readonly capabilities = new Map<string, CapabilityDef>();
  private readonly byVersion = new Map<string, Map<number, CapabilityDef>>();

  register(def: CapabilityDef): void {
    if (!def || typeof def.name !== "string" || def.name.length === 0) {
      throw new Error("Capability must have a non-empty name");
    }
    if (!Number.isInteger(def.version) || def.version < 1) {
      throw new Error(
        `Capability "${def.name}" version must be a positive integer`,
      );
    }
    if (this.capabilities.has(def.name)) {
      const err = new Error(
        `Capability "${def.name}" is already registered`,
      ) as Error & {
        code: string;
      };
      err.code = DUPLICATE_CAPABILITY;
      throw err;
    }
    if (typeof def.execute !== "function") {
      throw new Error(
        `Capability "${def.name}" must declare an execute function`,
      );
    }
    this.validateSchema(def.name, def.inputSchema);
    this.capabilities.set(def.name, def);
    if (!this.byVersion.has(def.name)) this.byVersion.set(def.name, new Map());
    this.byVersion.get(def.name)!.set(def.version, def);
  }

  /**
   * Replace a capability, bumping its version. Any previously issued ticket
   * bound to the old version fails at redemption (version-bound tickets).
   */
  replace(def: CapabilityDef): CapabilityDef {
    const existing = this.capabilities.get(def.name);
    if (!existing) {
      throw new Error(
        `Cannot replace capability "${def.name}": not registered`,
      );
    }
    const next = { ...def, version: existing.version + 1 };
    if (typeof next.execute !== "function") {
      throw new Error(
        `Capability "${def.name}" must declare an execute function`,
      );
    }
    this.validateSchema(def.name, next.inputSchema);
    this.capabilities.set(def.name, next);
    if (!this.byVersion.has(def.name)) this.byVersion.set(def.name, new Map());
    this.byVersion.get(def.name)!.set(next.version, next);
    return next;
  }

  /** The active (latest) version of a capability, or undefined. */
  get(name: string): CapabilityDef | undefined {
    return this.capabilities.get(name);
  }

  /** A specific version, or undefined. */
  getVersion(name: string, version: number): CapabilityDef | undefined {
    return this.byVersion.get(name)?.get(version);
  }

  /** Whether a capability name is registered. */
  has(name: string): boolean {
    return this.capabilities.has(name);
  }

  getRegisteredCapabilities(): RegisteredCapabilitySummary[] {
    return Array.from(this.capabilities.values()).map((c) => ({
      name: c.name,
      version: c.version,
      description: c.description,
      baseRisk: c.risk.base,
      approvalStrategy: c.approval?.strategy ?? "automatic",
      sandboxRequirement: c.sandbox?.requirement ?? "optional",
    }));
  }

  private validateSchema(name: string, schema: Schema): void {
    if (!schema || typeof schema !== "object") {
      throw new Error(`Capability "${name}" must declare an inputSchema`);
    }
    if (schema.type === "object" && typeof schema.properties !== "object") {
      throw new Error(
        `Capability "${name}" object schema must declare properties`,
      );
    }
  }

  clear(): void {
    this.capabilities.clear();
    this.byVersion.clear();
  }
}
