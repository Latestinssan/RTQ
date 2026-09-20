import { Auditor, AuditLogger, MemorySink } from "@rtq/audit";
import {
  ChallengeRegistry,
  type ApprovalChallenge,
  type ApprovalProvider,
  type ApprovalRequest,
  type DeviceApproval,
  createChallenge,
  encodeChallenge,
} from "@rtq/approval";
import {
  CapabilityRegistry,
  TicketStore,
  validateAgainstSchema,
  type ApprovalStrategy,
  type AuthorizationResult,
  type CapabilityDef,
  type Command,
  type ExecutionResult,
  type McpTicketBindings,
  type Origin,
  type RiskLevel,
  type SandboxSpec,
  type Schema,
  RISK_LEVELS,
  riskRank,
} from "@rtq/core";
import {
  ClarificationEngine,
  type ClarificationRule,
} from "@rtq/clarification";
import { PolicyEngine, type PolicyRule } from "@rtq/policy";
import { RiskEngine, type RiskContext } from "@rtq/risk";
import {
  createSandbox,
  type EnforcementReport,
  type SandboxHandle,
  type SandboxSpec as SandboxPackageSpec,
} from "@rtq/sandbox";
import { inputHash } from "@rtq/crypto";

export * from "@rtq/core";
export * from "@rtq/risk";
export * from "@rtq/policy";
export * from "@rtq/clarification";
export * from "@rtq/approval";
export * from "@rtq/audit";

// NOTE: @rtq/sandbox is re-exported explicitly (not via *) because both
// @rtq/core and @rtq/sandbox export a `SandboxSpec`. @rtq/core's is the
// canonical security-model type used across the pipeline.
export {
  createSandbox,
  SandboxError,
  SANDBOX_ERROR_CODES,
  describeEnvironmentDrops,
  buildSandboxEnvironment,
  canonicalizePath,
  isPathAllowed,
  validateAllowlistPaths,
  flattenAllowlist,
  defaultWorkspace,
  generateSeatbeltProfile,
  createDarwinSandbox,
  darwinReport,
  buildBubblewrapArgs,
  checkBwrapCapability,
  createLinuxSandbox,
  linuxReport,
  createWindowsSandbox,
  parseWindowsRunnerOutput,
  windowsReport,
} from "@rtq/sandbox";
export type {
  SandboxHandle,
  SandboxExecutionResult,
  SandboxExecutionOptions,
  EnforcementReport,
  BackendName,
  AllowlistEntry,
  AccessOp,
  PathCheckResult,
  CanonicalPath,
} from "@rtq/sandbox";

export interface DeviceKeyStore {
  /** Look up a device's HMAC key by its key id, or null when unknown/revoked. */
  getDeviceKey(keyId: string): string | Buffer | null;
}

/** Create an RTQ runtime. See RTQOptions for configuration. */
export function createRTQ(options: RTQOptions): RTQ {
  return new RTQ(options);
}

export interface RTQOptions {
  /**
   * HMAC-SHA256 key used to sign authorization tickets. MUST be a high-entropy
   * secret stored outside the repository (env var / secret store).
   */
  signingKey: string | Buffer;
  auditor?: Auditor;
  policyEngine?: PolicyEngine;
  riskEngine?: RiskEngine;
  /** Default origin applied when the Command carries none. */
  defaultOrigin?: Origin;
  /** Ticket lifetime in ms (default 60s). */
  ticketTTLMs?: number;
  /** Device key store used to verify device_verification / qr approvals. */
  deviceKeyStore?: DeviceKeyStore;
  /** Prompt used for user_confirmation approvals. */
  onUserConfirmation?: (request: ApprovalRequest) => Promise<boolean> | boolean;
  /** Extra approval providers keyed by strategy. */
  approvalProviders?: ApprovalProvider[];
  /** Capability-wide default sandbox (used when a capability declares none). */
  defaultSandbox?: SandboxSpec;
  /** Timeout applied to capability.execute, in ms (default 30s). */
  executeTimeoutMs?: number;
}

interface PendingAuthorization {
  command: Command;
  capability: CapabilityDef;
  risk: RiskLevel;
  policyVersion: string;
  origin: Origin;
  actor: string;
  resource: string | null;
  strategy: ApprovalStrategy;
  inputHashValue: string;
  challenge: ApprovalChallenge;
  expiresAt: number;
  mcp?: McpTicketBindings;
}

export type ExecutionOutcome =
  | {
      ok: true;
      ticketId: string;
      result: ExecutionResult;
      sandboxed: boolean;
      report?: EnforcementReport;
    }
  | { ok: false; ticketId?: string; code: string; reason: string };

/** Default approval mapping by risk. CRITICAL is never automatic. */
function riskDefaultStrategy(
  risk: RiskLevel,
  always: boolean,
): ApprovalStrategy {
  if (always) return "user_confirmation";
  switch (risk) {
    case "low":
      return "automatic";
    case "medium":
      return "user_confirmation";
    case "high":
      return "qr";
    case "critical":
      return "biometric";
    default:
      return "user_confirmation";
  }
}

/**
 * RTQ — the Risk-Adaptive Capability Security Runtime umbrella.
 *
 * Pipeline: structured command -> schema validation -> authoritative risk ->
 * clarification -> policy -> approval -> cryptographic authorization ticket ->
 * sandboxed execution -> audit.
 */
export class RTQ {
  readonly capabilities = new CapabilityRegistry();
  readonly policy: PolicyEngine;
  readonly risk: RiskEngine;
  readonly clarifier = new ClarificationEngine();
  readonly tickets: TicketStore;
  readonly auditor: Auditor;
  readonly challenges = new ChallengeRegistry();

  private readonly defaultOrigin: Origin;
  private readonly deviceKeyStore?: DeviceKeyStore;
  private readonly onUserConfirmation?: RTQOptions["onUserConfirmation"];
  private readonly defaultSandbox?: SandboxSpec;
  private readonly executeTimeoutMs: number;
  private readonly additionalProviders: Map<
    ApprovalStrategy,
    ApprovalProvider
  > = new Map();
  private readonly pendingAuth = new Map<string, PendingAuthorization>();

  constructor(options: RTQOptions) {
    if (!options.signingKey) {
      throw new Error(
        "RTQ requires a signingKey for authorization tickets. Pass a high-entropy secret (e.g. process.env.RTQ_SIGNING_KEY).",
      );
    }
    this.auditor = options.auditor ?? new AuditLogger(new MemorySink());
    this.policy = options.policyEngine ?? new PolicyEngine();
    this.risk = options.riskEngine ?? new RiskEngine();
    this.defaultOrigin = options.defaultOrigin ?? "local";
    this.deviceKeyStore = options.deviceKeyStore;
    this.onUserConfirmation = options.onUserConfirmation;
    this.defaultSandbox = options.defaultSandbox;
    this.executeTimeoutMs = options.executeTimeoutMs ?? 30_000;
    this.tickets = new TicketStore({
      signingKey: options.signingKey,
      ttlMs: options.ticketTTLMs,
      auditor: this.auditor,
    });
    for (const provider of options.approvalProviders ?? []) {
      this.additionalProviders.set(provider.strategy, provider);
    }
  }

  // =========================================================================
  // Registration
  // =========================================================================

  registerCapability(def: CapabilityDef): void {
    this.capabilities.register(def);
    this.auditor.emit(
      "CAPABILITY_REGISTERED",
      `Capability "${def.name}" v${def.version} registered`,
      {
        name: def.name,
        version: def.version,
        baseRisk: def.risk.base,
        approvalStrategy: def.approval?.strategy ?? "automatic",
      },
      { capability: def.name },
    );
  }

  replaceCapability(def: CapabilityDef): CapabilityDef {
    const next = this.capabilities.replace(def);
    const invalidated = this.tickets.invalidateForCapabilityVersion(
      next.name,
      next.version - 1,
      "capability replaced (version bumped)",
    );
    this.auditor.emit(
      "CAPABILITY_REGISTERED",
      `Capability "${next.name}" replaced -> v${next.version}; ${invalidated} outstanding ticket(s) invalidated`,
      {
        name: next.name,
        version: next.version,
        invalidatedTickets: invalidated,
      },
      { capability: next.name },
    );
    return next;
  }

  registerPolicy(rules: PolicyRule | PolicyRule[]): void {
    const list = Array.isArray(rules) ? rules : [rules];
    for (const rule of list) this.policy.add(rule);
    this.auditor.emit(
      "POLICY_CONFIGURED",
      `Registered ${list.length} policy rule(s)`,
      {
        count: list.length,
      },
    );
  }

  registerClarification(rules: ClarificationRule | ClarificationRule[]): void {
    const list = Array.isArray(rules) ? rules : [rules];
    this.clarifier.addMany(list);
  }

  setApprovalProvider(provider: ApprovalProvider): void {
    this.additionalProviders.set(provider.strategy, provider);
  }

  // =========================================================================
  // authorize()
  // =========================================================================

  async authorize(
    command: Command,
    opts: { actor?: string; resource?: string; riskContext?: RiskContext } = {},
  ): Promise<AuthorizationResult> {
    this.auditor.emit(
      "AUTHORIZATION_REQUESTED",
      `authorize(${command.capability})`,
      {
        capability: command.capability,
        version: command.version,
      },
      { capability: command.capability },
    );

    const capability = this.capabilities.get(command.capability);
    if (!capability) {
      return this.deny(
        "capability.not_registered",
        `Capability "${command.capability}" is not registered`,
      );
    }
    if (command.version !== capability.version) {
      return this.deny(
        "capability.version_mismatch",
        `Requested version ${command.version} does not match registered version ${capability.version}`,
      );
    }

    const schemaResult = validateAgainstSchema(
      command.input,
      capability.inputSchema,
    );
    if (!schemaResult.valid) {
      return this.deny(
        "input.invalid",
        `Input validation failed: ${schemaResult.errors[0]?.message ?? "invalid input"}`,
      );
    }

    const origin: Origin = command.origin ?? this.defaultOrigin;
    const riskCtx: RiskContext = {
      origin,
      resource: opts.resource,
      ...opts.riskContext,
    };
    // MCP bindings (server id, tool, schema hash, tenant, ...) are RTQ-decided
    // facts that get cryptographically bound into the ticket. They are parsed
    // from command metadata, strictly validated, and never trusted from the
    // MCP server itself. Malformed bindings fail closed.
    const mcp = parseMcpBindings(command.metadata);
    if (command.metadata?.["mcp"] !== undefined && mcp === undefined) {
      return this.deny(
        "command.mcp_bindings_invalid",
        "Invalid or incomplete MCP bindings in command metadata",
      );
    }
    // A caller-supplied claimedRisk is never allowed to LOWER risk. The engine
    // may only consult a claim to raise its baseline, never to skip factors.
    const claimed = extractClaimedRisk(command);
    const baseLevel: RiskLevel =
      capability.risk.base === "custom" ? "medium" : capability.risk.base;
    const evaluation = this.risk.evaluate(
      capability.risk,
      baseLevel,
      riskCtx,
      claimed,
    );
    this.auditor.emit(
      "RISK_EVALUATED",
      `Risk for "${capability.name}" = ${evaluation.level}`,
      {
        level: evaluation.level,
        baseLevel: evaluation.baseLevel,
        contributions: evaluation.contributions,
        policyVersion: evaluation.policyVersion,
      },
      { capability: capability.name },
    );

    // Clarification: ambiguity is a first-class state. Never authorize with
    // missing security-critical parameters.
    const questions = this.clarifier.evaluate(capability.name, command.input);
    if (questions.length > 0) {
      this.auditor.emit(
        "CLARIFICATION_REQUIRED",
        `Clarification needed for "${capability.name}"`,
        {
          questions,
        },
        { capability: capability.name },
      );
      return {
        decision: "clarification_required",
        questions,
        reason: "Security-critical parameters are missing or ambiguous",
      };
    }

    const policyDecision = this.policy.evaluate({
      capability: capability.name,
      input: command.input,
      origin,
      risk: evaluation.level,
      resource: opts.resource,
    });
    this.auditor.emit(
      "POLICY_EVALUATED",
      `Policy -> ${policyDecision.decision.decision}`,
      {
        decision: policyDecision.decision,
        matchedRules: policyDecision.matchedRules,
        policyVersion: policyDecision.policyVersion,
      },
      { capability: capability.name },
    );

    let risk = evaluation.level;
    if (policyDecision.decision.decision === "deny") {
      return this.deny(
        policyDecision.decision.code,
        policyDecision.decision.reason,
        risk,
      );
    }
    if (policyDecision.decision.decision === "clarification_required") {
      this.auditor.emit(
        "CLARIFICATION_REQUIRED",
        "Policy-mandated clarification",
        {
          questions: policyDecision.decision.questions,
        },
        { capability: capability.name },
      );
      return {
        decision: "clarification_required",
        questions: policyDecision.decision.questions,
        reason: policyDecision.decision.reason,
      };
    }
    if (policyDecision.decision.decision === "approval_required") {
      return this.handleApproval({
        command,
        capability,
        risk,
        policyVersion: policyDecision.policyVersion,
        origin,
        actor: opts.actor ?? "local-user",
        resource: opts.resource ?? null,
        strategy: policyDecision.decision.strategy,
        mcp,
      });
    }
    if (policyDecision.decision.overrides?.risk !== undefined) {
      risk = policyDecision.decision.overrides.risk;
    }

    const strategy = this.approvalStrategyFor(capability, risk, origin);
    return this.handleApproval({
      command,
      capability,
      risk,
      policyVersion: policyDecision.policyVersion,
      origin,
      actor: opts.actor ?? "local-user",
      resource: opts.resource ?? null,
      strategy,
      mcp,
    });
  }

  // =========================================================================
  // Interactive approval continuation
  // =========================================================================

  /** Get the QR-ready payload string for a pending approval challenge. */
  getApprovalPayload(challengeId: string): string | null {
    const pending = this.pendingAuth.get(challengeId);
    if (!pending) return null;
    return encodeChallenge(pending.challenge);
  }

  /**
   * Submit the result of an interactive approval:
   *  - device_verification / qr: proof = { type: 'device_approval', approval }
   *  - biometric: proof = { type: 'biometric', verifiedBy } (host has already
   *    verified the platform attestation; recorded in audit)
   *  - custom: proof = { type: 'custom', verified, detail? }
   */
  async submitApproval(
    challengeId: string,
    proof:
      | { type: "device_approval"; approval: DeviceApproval }
      | { type: "biometric"; verifiedBy: string }
      | { type: "custom"; verified: boolean; detail?: string },
  ): Promise<AuthorizationResult> {
    const pending = this.pendingAuth.get(challengeId);
    if (!pending) {
      return this.deny(
        "approval.unknown_challenge",
        "No pending approval for this challenge",
      );
    }
    if (Date.now() > pending.expiresAt) {
      this.pendingAuth.delete(challengeId);
      return this.deny("approval.expired", "Approval challenge expired");
    }

    if (
      (pending.strategy === "device_verification" ||
        pending.strategy === "qr") &&
      proof.type === "device_approval"
    ) {
      if (!this.deviceKeyStore) {
        return this.deny(
          "approval.no_device_key_store",
          "deviceKeyStore is required for device verification",
        );
      }
      // Binding check #1: the approval must name the pending challenge. This
      // prevents approval substitution (an approval signed for operation A
      // being replayed to authorize operation B).
      if (proof.approval.challengeId !== challengeId) {
        this.auditor.emit(
          "VERIFICATION_FAILED",
          "Approval challenge mismatch (substitution attempt)",
          {
            expected: challengeId,
            received: proof.approval.challengeId,
          },
        );
        return this.deny(
          "approval.challenge_mismatch",
          "Approval does not match the pending challenge",
        );
      }
      const result = this.challenges.verifyAndRedeem(proof.approval, (keyId) =>
        this.deviceKeyStore!.getDeviceKey(keyId),
      );
      if (!result.ok) {
        this.auditor.emit(
          "VERIFICATION_FAILED",
          `Device approval rejected: ${result.reason}`,
          {
            reason: result.reason,
          },
        );
        return this.deny("approval.device_verification_failed", result.reason);
      }
      // Binding check #2: the verified challenge must match the pending
      // authorization on every security-critical field.
      const verified = result.challenge;
      const bindingMismatch =
        verified.capability !== pending.capability.name ||
        verified.capabilityVersion !== pending.capability.version ||
        verified.inputHash !== pending.inputHashValue ||
        verified.nonce !== pending.challenge.nonce;
      if (bindingMismatch) {
        this.auditor.emit(
          "VERIFICATION_FAILED",
          "Verified challenge bindings do not match pending authorization",
          {},
        );
        return this.deny(
          "approval.binding_mismatch",
          "Approval bindings do not match the pending operation",
        );
      }
      this.auditor.emit(
        "VERIFICATION_STARTED",
        "Device approval signature verified",
        {
          challengeId,
          deviceKeyId: proof.approval.keyId,
        },
      );
      return this.finalizeAuthorization(pending, pending.strategy);
    }

    if (pending.strategy === "biometric" && proof.type === "biometric") {
      this.auditor.emit(
        "VERIFICATION_STARTED",
        "Biometric verification reported by host",
        {
          verifiedBy: proof.verifiedBy,
          challengeId,
        },
      );
      return this.finalizeAuthorization(pending, "biometric");
    }

    if (pending.strategy === "custom" && proof.type === "custom") {
      if (proof.verified) {
        return this.finalizeAuthorization(pending, "custom");
      }
      this.auditor.emit("APPROVAL_DENIED", "Custom approval denied", {
        detail: proof.detail,
      });
      return this.deny(
        "approval.denied",
        proof.detail ?? "Custom approval denied",
      );
    }

    return this.deny(
      "approval.proof_mismatch",
      `Proof type does not match strategy "${pending.strategy}"`,
    );
  }

  // =========================================================================
  // execute()
  // =========================================================================

  async execute(ticketId: string): Promise<ExecutionOutcome> {
    this.auditor.emit(
      "EXECUTION_STARTED",
      `execute(${ticketId})`,
      { ticketId },
      { ticketId },
    );

    const peeked = this.tickets.peek(ticketId);
    if (!peeked) {
      this.auditor.emit(
        "EXECUTION_DENIED",
        `Unknown ticket ${ticketId}`,
        { ticketId },
        { ticketId },
      );
      return { ok: false, code: "ticket.not_found", reason: "Unknown ticket" };
    }
    const capability = this.capabilities.getVersion(
      peeked.capability,
      peeked.capabilityVersion,
    );
    if (!capability) {
      this.auditor.emit(
        "EXECUTION_DENIED",
        `Capability for ticket ${ticketId} is no longer registered`,
        {
          capability: peeked.capability,
          version: peeked.capabilityVersion,
        },
        { ticketId },
      );
      return {
        ok: false,
        code: "capability.not_registered",
        reason: "Capability is no longer registered",
      };
    }

    const redeemed = this.tickets.redeem(ticketId, {
      expectedCapability: capability.name,
      expectedVersion: capability.version,
      // MCP-backed capabilities bind server/tool/schema/tenant into the ticket
      // at issue time; the executor re-validates them at redemption so a
      // ticket cannot be transplanted onto a different MCP operation.
      expectedMcp: capability.mcp,
    });
    if (!redeemed.ok) {
      this.auditor.emit(
        "EXECUTION_DENIED",
        `Ticket ${ticketId} could not be redeemed: ${redeemed.reason}`,
        {
          code: redeemed.code,
        },
        { ticketId },
      );
      return {
        ok: false,
        code: `ticket.${redeemed.code}`,
        reason: redeemed.reason,
      };
    }

    const { ticket, input } = redeemed;
    if (!capability.mcp && ticket.mcp) {
      this.auditor.emit(
        "EXECUTION_DENIED",
        `Ticket ${ticketId} carries MCP bindings but the capability does not`,
        {
          capability: capability.name,
        },
        { ticketId },
      );
      return {
        ok: false,
        code: "ticket.mcp_binding_mismatch",
        reason: "Ticket/executor MCP binding mismatch",
      };
    }

    let sandbox: SandboxHandle | null = null;
    let sandboxed = false;
    let report: EnforcementReport | undefined;

    const sandboxSpec = capability.sandbox ?? this.defaultSandbox;
    if (capability.sandbox?.requirement === "required" && !sandboxSpec) {
      this.auditor.emit(
        "EXECUTION_DENIED",
        "Capability requires a sandbox but none was declared",
        {
          capability: capability.name,
        },
        { ticketId },
      );
      return {
        ok: false,
        ticketId,
        code: "sandbox.required",
        reason: "Capability requires a sandbox configuration",
      };
    }

    if (sandboxSpec) {
      try {
        const handle = createSandbox(sandboxSpec as SandboxPackageSpec);
        sandbox = handle;
        sandboxed = true;
        this.auditor.emit(
          "SANDBOX_CREATED",
          `Sandbox created (${handle.report.backend})`,
          {
            backend: handle.report.backend,
            isolation: handle.report.isolation,
          },
          { ticketId },
        );
        report = handle.report;
      } catch (e) {
        this.auditor.emit(
          "SANDBOX_FAILED",
          `Sandbox failed: ${(e as Error).message}`,
          {
            error: (e as Error).message,
          },
          { ticketId },
        );
        this.auditor.emit(
          "EXECUTION_DENIED",
          "Execution refused: sandbox could not be constructed",
          {
            reason: (e as Error).message,
          },
          { ticketId },
        );
        return {
          ok: false,
          ticketId,
          code: "sandbox.unavailable",
          reason: `Execution refused (fail-closed): ${(e as Error).message}`,
        };
      }
    }

    const context = {
      capability: capability.name,
      capabilityVersion: capability.version,
      actor: ticket.actor,
      origin: ticket.origin,
      ticketId,
      risk: ticket.risk,
      sandbox,
      tenant: ticket.mcp?.tenant,
      mcp: ticket.mcp,
    };

    let result: ExecutionResult;
    try {
      result = await withTimeout(
        capability.execute(context, input),
        this.executeTimeoutMs,
        capability.name,
      );
    } catch (e) {
      result = {
        ok: false,
        error: (e as Error).message,
        code: "execute.failed",
      };
    }

    this.auditor.emit(
      "EXECUTION_COMPLETED",
      `Execution completed for ${capability.name}`,
      {
        ok: result.ok,
        sandboxed,
      },
      { capability: capability.name, ticketId },
    );

    if (!result.ok) {
      return {
        ok: false,
        ticketId,
        code: result.code ?? "execute.failed",
        reason: result.error,
      };
    }

    return {
      ok: true,
      ticketId,
      result,
      sandboxed,
      report,
    };
  }

  // =========================================================================
  // Diagnostics
  // =========================================================================

  diagnostics(): Record<string, unknown> {
    return {
      capabilities: this.capabilities.getRegisteredCapabilities(),
      policyVersion: this.policy.policyVersion,
      policyRuleCount: this.policy.rulesSnapshot.length,
      riskPolicyVersion: this.risk.policyVersion,
      clarificationRuleCount: this.clarifier.ruleCount,
      liveTickets: this.tickets.size,
      pendingApprovals: this.pendingAuth.size,
      auditorSink: this.auditor.sink.constructor.name,
    };
  }

  /**
   * Invalidate every live ticket bound to an MCP server (used when server
   * identity, endpoint, authentication or trust state changes). Returns the
   * number of tickets invalidated.
   */
  invalidateMcpServerTickets(serverId: string, reason: string): number {
    return this.tickets.invalidateWhere(
      (t) => t.mcp?.serverId === serverId,
      reason,
    );
  }

  /** Invalidate every live ticket for a capability name (MCP or native). */
  invalidateTicketsForCapability(capability: string, reason: string): number {
    return this.tickets.invalidateWhere(
      (t) => t.capability === capability,
      reason,
    );
  }

  // ===========================================================================
  // Internals
  // ===========================================================================

  private approvalStrategyFor(
    capability: CapabilityDef,
    risk: RiskLevel,
    origin: Origin,
  ): ApprovalStrategy {
    const always = capability.approval?.always === true;
    if (always)
      return this.escalateForOrigin(riskDefaultStrategy(risk, true), origin);
    const capStrategy = capability.approval?.strategy;
    if (capStrategy && capStrategy !== "automatic") return capStrategy;
    if (capStrategy === "automatic") {
      // Automatic approval never applies to high/critical risk.
      return riskRank(risk) >= riskRank("high")
        ? this.escalateForOrigin(riskDefaultStrategy(risk, false), origin)
        : "automatic";
    }
    return this.escalateForOrigin(riskDefaultStrategy(risk, false), origin);
  }

  /**
   * A host-side `user_confirmation` prompt is a LOCAL consent channel. For
   * operations whose origin is not local, the same risk level is approved by
   * a device-backed challenge instead, so a remote/agent/plugin origin can
   * never be satisfied by a dialog the origin itself could trigger.
   */
  private escalateForOrigin(
    strategy: ApprovalStrategy,
    origin: Origin,
  ): ApprovalStrategy {
    if (strategy === "user_confirmation" && origin !== "local")
      return "device_verification";
    return strategy;
  }

  private async handleApproval(p: {
    command: Command;
    capability: CapabilityDef;
    risk: RiskLevel;
    policyVersion: string;
    origin: Origin;
    actor: string;
    resource: string | null;
    strategy: ApprovalStrategy;
    mcp?: McpTicketBindings;
  }): Promise<AuthorizationResult> {
    this.auditor.emit(
      "APPROVAL_REQUESTED",
      `Approval requested (${p.strategy}) for "${p.capability.name}"`,
      {
        strategy: p.strategy,
        risk: p.risk,
      },
      { capability: p.capability.name },
    );

    const hostProvider = this.additionalProviders.get(p.strategy);
    if (hostProvider) {
      const challenge = this.makeChallenge(p);
      const request = this.approvalRequest(p, challenge.challengeId);
      const outcome = await hostProvider.requestApproval(request);
      if (outcome.decision === "granted") {
        return this.finalizeAuthorization(
          this.pendingFrom(p, inputHash(p.command.input), challenge),
          p.strategy,
        );
      }
      this.auditor.emit(
        "APPROVAL_DENIED",
        `Approval denied (${p.strategy})`,
        {
          reason: outcome.reason,
        },
        { capability: p.capability.name },
      );
      return this.deny(
        "approval.denied",
        outcome.reason ?? "Approval denied",
        p.risk,
      );
    }

    if (p.strategy === "automatic") {
      const challenge = this.makeChallenge(p);
      return this.finalizeAuthorization(
        this.pendingFrom(p, inputHash(p.command.input), challenge),
        "automatic",
      );
    }

    if (p.strategy === "user_confirmation") {
      if (!this.onUserConfirmation) {
        return this.deny(
          "approval.no_prompt_configured",
          "No user confirmation prompt configured",
          p.risk,
        );
      }
      const challenge = this.makeChallenge(p);
      const request = this.approvalRequest(p, challenge.challengeId);
      let granted: boolean;
      try {
        granted = await this.onUserConfirmation(request);
      } catch {
        granted = false;
      }
      if (!granted) {
        this.auditor.emit(
          "APPROVAL_DENIED",
          "User declined",
          {},
          { capability: p.capability.name },
        );
        return this.deny("approval.denied", "User declined", p.risk);
      }
      return this.finalizeAuthorization(
        this.pendingFrom(p, request.inputHash, challenge),
        "user_confirmation",
      );
    }

    // device_verification / qr / biometric: interactive flow.
    const challenge = this.makeChallenge(p);
    const pending = this.pendingFrom(p, inputHash(p.command.input), challenge);
    this.pendingAuth.set(challenge.challengeId, pending);

    return {
      decision: "approval_required",
      strategy: p.strategy,
      challengeId: challenge.challengeId,
      reason: `Approval required (${p.strategy})`,
      summary: this.describeCommand(p),
      risk: p.risk,
      origin: p.origin,
      capability: p.capability.name,
      capabilityVersion: p.capability.version,
    };
  }

  private approvalRequest(
    p: {
      command: Command;
      capability: CapabilityDef;
      risk: RiskLevel;
      origin: Origin;
      strategy: ApprovalStrategy;
      mcp?: McpTicketBindings;
    },
    challengeId: string,
  ): ApprovalRequest {
    return {
      challengeId,
      capability: p.capability.name,
      capabilityVersion: p.capability.version,
      inputHash: inputHash(p.command.input),
      summary: this.describeCommand(p),
      risk: p.risk,
      origin: p.origin,
      strategy: p.strategy,
    };
  }

  private makeChallenge(p: {
    command: Command;
    capability: CapabilityDef;
    risk: RiskLevel;
    policyVersion: string;
    origin: Origin;
    mcp?: McpTicketBindings;
  }): ApprovalChallenge {
    const challenge = createChallenge({
      capability: p.capability.name,
      capabilityVersion: p.capability.version,
      inputHash: inputHash(p.command.input),
      summary: this.describeCommand(p),
      risk: p.risk,
      policyVersion: p.policyVersion,
      origin: p.origin,
    });
    this.challenges.register(challenge);
    return challenge;
  }

  private pendingFrom(
    p: {
      command: Command;
      capability: CapabilityDef;
      risk: RiskLevel;
      policyVersion: string;
      origin: Origin;
      actor: string;
      resource: string | null;
      strategy: ApprovalStrategy;
      mcp?: McpTicketBindings;
    },
    inputHashValue: string,
    challenge: ApprovalChallenge,
  ): PendingAuthorization {
    return {
      command: p.command,
      capability: p.capability,
      risk: p.risk,
      policyVersion: p.policyVersion,
      origin: p.origin,
      actor: p.actor,
      resource: p.resource,
      strategy: p.strategy,
      inputHashValue,
      challenge,
      expiresAt: challenge.expiresAt,
      mcp: p.mcp,
    };
  }

  private finalizeAuthorization(
    pending: PendingAuthorization,
    method: ApprovalStrategy,
  ): AuthorizationResult {
    this.auditor.emit(
      "APPROVAL_GRANTED",
      `Approval granted (${method}) for "${pending.capability.name}"`,
      {
        method,
        risk: pending.risk,
      },
      { capability: pending.capability.name },
    );
    this.pendingAuth.delete(pending.challenge.challengeId);

    const ticket = this.tickets.issue({
      capability: pending.capability.name,
      capabilityVersion: pending.capability.version,
      input: pending.command.input,
      actor: pending.actor,
      resource: pending.resource,
      risk: pending.risk,
      policyVersion: pending.policyVersion,
      approvalMethod: method,
      origin: pending.origin,
      challengeId: pending.challenge.challengeId,
      nonce: pending.challenge.nonce,
      mcp: pending.mcp,
    });

    this.auditor.emit(
      "TICKET_ISSUED",
      `Ticket ${ticket.id} issued for "${pending.capability.name}"`,
      {
        capability: pending.capability.name,
        capabilityVersion: pending.capability.version,
        risk: pending.risk,
        approvalMethod: method,
        expiresAt: ticket.expiresAt,
      },
      { capability: pending.capability.name, ticketId: ticket.id },
    );

    return {
      decision: "allowed",
      ticketId: ticket.id,
      capability: pending.capability.name,
      capabilityVersion: pending.capability.version,
      risk: pending.risk,
      approvalMethod: method,
      origin: pending.origin,
      expiresAt: ticket.expiresAt,
    };
  }

  private describeCommand(p: {
    capability: CapabilityDef;
    command: Command;
    risk: RiskLevel;
    mcp?: McpTicketBindings;
  }): Record<string, unknown> {
    const summary: Record<string, unknown> = {
      action: p.capability.description,
      capability: p.capability.name,
      version: p.capability.version,
      risk: p.risk,
      input: p.command.input,
    };
    // MCP approval context (spec 46.27): show the human the normalized server
    // and tool, not just a raw capability identifier.
    if (p.mcp) {
      summary["server"] = p.mcp.serverId;
      summary["tool"] = p.mcp.toolName;
      if (p.mcp.tenant !== undefined) summary["tenant"] = p.mcp.tenant;
      if (p.mcp.resourceScope !== undefined)
        summary["resourceScope"] = p.mcp.resourceScope;
    }
    return summary;
  }

  private deny(
    code: string,
    reason: string,
    risk?: RiskLevel,
  ): AuthorizationResult {
    this.auditor.emit("EXECUTION_DENIED", reason, { code, risk });
    return { decision: "denied", code, reason, risk };
  }
}

function extractClaimedRisk(command: Command): RiskLevel | undefined {
  const candidate =
    command.metadata?.["claimedRisk"] ?? command.metadata?.["risk"];
  return typeof candidate === "string" &&
    (RISK_LEVELS as readonly string[]).includes(candidate)
    ? (candidate as RiskLevel)
    : undefined;
}

const HEX64 = /^[0-9a-f]{64}$/;
const CREDENTIAL_CLASSES = new Set(["read", "write", "admin", "none"]);

/**
 * Strictly validate MCP authorization bindings carried in command metadata.
 * All binding values are RTQ-decided attribution facts (never supplied by the
 * MCP server itself). Malformed, oversized or incomplete bindings are
 * rejected outright (fail closed).
 */
function parseMcpBindings(
  metadata: Record<string, unknown> | undefined,
): McpTicketBindings | undefined {
  const raw = metadata?.["mcp"];
  if (raw === undefined) return undefined;
  if (raw === null || typeof raw !== "object" || Array.isArray(raw))
    return undefined;
  const r = raw as Record<string, unknown>;

  const str = (v: unknown, maxLen: number): string | undefined =>
    typeof v === "string" && v.length > 0 && v.length <= maxLen ? v : undefined;

  const serverId = str(r["serverId"], 256);
  const toolName = str(r["toolName"], 512);
  const schemaHash =
    typeof r["schemaHash"] === "string" && HEX64.test(r["schemaHash"])
      ? r["schemaHash"]
      : undefined;
  if (!serverId || !toolName || !schemaHash) return undefined;

  const serverIdentity = str(r["serverIdentity"], 4096);
  const tenant = str(r["tenant"], 256);
  const resourceScope = str(r["resourceScope"], 4096);
  const credentialClass =
    typeof r["credentialClass"] === "string" &&
    CREDENTIAL_CLASSES.has(r["credentialClass"])
      ? r["credentialClass"]
      : undefined;

  return {
    serverId,
    toolName,
    schemaHash,
    ...(serverIdentity !== undefined ? { serverIdentity } : {}),
    ...(tenant !== undefined ? { tenant } : {}),
    ...(resourceScope !== undefined ? { resourceScope } : {}),
    ...(credentialClass !== undefined ? { credentialClass } : {}),
  };
}

function withTimeout<T>(
  promise: Promise<T>,
  ms: number,
  label: string,
): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new Error(`execute(${label}) timed out after ${ms}ms`)),
      ms,
    );
    promise.then(
      (v) => {
        clearTimeout(timer);
        resolve(v);
      },
      (e) => {
        clearTimeout(timer);
        reject(e);
      },
    );
  });
}
