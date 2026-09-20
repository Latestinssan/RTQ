"use client";

import { useState } from "react";
import { Copy, Check, Code2, FileCode, Shield, Terminal } from "lucide-react";

interface CodeTab {
  id: string;
  name: string;
  badge: string;
  language: string;
  description: string;
  code: string;
  highlightNotes: string[];
}

const TABS: CodeTab[] = [
  {
    id: "capability",
    name: "capability.ts",
    badge: "@rtq/core",
    language: "typescript",
    description: "Every tool or action is explicitly defined with immutable schemas and an authoritative base risk score.",
    highlightNotes: [
      "Explicit registry: non-registered capabilities cannot execute",
      "Base risk cannot be demoted by caller claims",
      "Typed JSON Schema validation at the boundary",
    ],
    code: `import { createRTQ } from "@rtq/security";

const rtq = createRTQ({
  signingKey: process.env.RTQ_SIGNING_KEY!, // Key never leaves host memory
});

// Explicit registration is mandatory. Unknown operations are rejected.
rtq.registerCapability({
  name: "workspace.readFile",
  version: 1,
  description: "Read utf-8 contents of a workspace file",
  inputSchema: {
    type: "object",
    properties: {
      path: { type: "string", pattern: "^[a-zA-Z0-9_/.-]+$" },
    },
    required: ["path"],
    additionalProperties: false,
  },
  risk: {
    base: "low", // Authoritative base risk computed by RTQ
    factors: ["fs_read", "workspace_contained"],
  },
  execute: async (ctx, input) => {
    // RTQ executes this capability through its configured sandbox path.
    return { ok: true, data: await ctx.fs.readFile(input.path, "utf-8") };
  },
});`,
  },
  {
    id: "policy",
    name: "policy-rules.ts",
    badge: "@rtq/policy",
    language: "typescript",
    description: "Default-deny policy engine. If no explicit rule matches, the operation is denied. There is no silent fallback.",
    highlightNotes: [
      "Missing rule = denial (Invariant INV-04)",
      "Declarative matching against authoritative risk & capability names",
      "Human-in-the-loop requirement for high/critical risks",
    ],
    code: `import { PolicyEngine } from "@rtq/policy";

export const policy = new PolicyEngine({
  defaultAction: "DENY", // Strict default-deny: missing rule is a refusal
  rules: [
    {
      id: "allow-workspace-reads",
      capability: "workspace.readFile",
      maxRisk: "low",
      effect: "ALLOW",
      condition: (ctx) => ctx.input.path.startsWith("src/"),
    },
    {
      id: "escalate-dangerous-ops",
      riskLevel: ["high", "critical"],
      effect: "REQUIRE_CHALLENGE", // Mandates cryptographic mobile approval
      strategy: "qr-challenge-response",
    },
  ],
});`,
  },
  {
    id: "approval",
    name: "qr-challenge.ts",
    badge: "@rtq/approval",
    language: "typescript",
    description: "Challenge-response approval only. Scanning a QR code grants nothing; the mobile device must sign the nonce.",
    highlightNotes: [
      "Scanning grants zero privileges (No PINs, no simple tap-to-allow)",
      "Device private key signs SHA-256(challenge_nonce + operation_hash)",
      "Single-use ticket issued exclusively upon cryptographic signature verification",
    ],
    code: `import { ChallengeApprovalStrategy } from "@rtq/approval";

// QR Challenge-Response: scanning grants nothing
const approver = new ChallengeApprovalStrategy({
  timeoutMs: 60_000,
  requireBiometric: true,
});

const challenge = await approver.createChallenge({
  capability: "system.deployArtifact",
  operationHash: "8a4f9b01c...",
  clientNonce: crypto.randomUUID(),
});

// Device receives challenge -> signs payload with Secure Enclave / TPM key
// Single-use ticket is minted ONLY if signature and nonce match.
const result = await approver.verifyResponse(challenge.id, signedPayload);
if (!result.verified) {
  throw new SecurityRefusalError("Approval signature rejected or expired");
}`,
  },
  {
    id: "sandbox",
    name: "seatbelt.sb",
    badge: "@rtq/sandbox",
    language: "scheme",
    description: "Fail-closed OS sandboxing. If platform tools are missing, execution halts. The escape hatch is explicit.",
    highlightNotes: [
      "macOS: Kernel Seatbelt profiles (sandbox-exec)",
      "Linux: bubblewrap with isolated namespaces and unshare",
      "Windows: AppContainer isolation tokens",
    ],
    code: `;; macOS Seatbelt Profile (Fail-Closed)
(version 1)
(deny default) ; Default deny all kernel syscalls

;; Allow minimal binary execution and workspace reads
(allow process-exec (literal "/bin/cat") (literal "/usr/bin/git"))
(allow file-read* 
  (subpath "/Users/operator/workspace")
  (subpath "/usr/lib")
  (subpath "/System/Library"))

;; Block all network sockets unconditionally
(deny network*)
(deny file-write*) ; Completely read-only`,
  },
];

export function CodeShowcase() {
  const [activeTabId, setActiveTabId] = useState(TABS[0].id);
  const [copied, setCopied] = useState(false);

  const activeTab = TABS.find((t) => t.id === activeTabId) || TABS[0];

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(activeTab.code);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (e) {
      console.error(e);
    }
  };

  return (
    <section className="relative mx-auto max-w-6xl px-6 py-20">
      <div className="mb-10 text-center">
        <div className="mb-3 inline-flex items-center gap-2 rounded-full border border-sky-500/20 bg-sky-500/10 px-3 py-1 font-mono text-xs uppercase tracking-widest text-sky-400">
          <Code2 size={13} />
          <span>Inspectable Security Primitives</span>
        </div>
        <h2 className="text-3xl font-black tracking-tight text-white md:text-4xl">
          Clean Code. Zero Fluff. Verifiable Logic.
        </h2>
        <p className="mx-auto mt-3 max-w-2xl text-sm text-white/50">
          Security-critical packages declare zero npm runtime dependencies. Inspect the exact TypeScript
          and sandboxing constructs that power RTQ.
        </p>
      </div>

      <div className="overflow-hidden rounded-2xl border border-white/10 bg-[#070914] shadow-2xl">
        {/* Tab Navigation */}
        <div className="flex flex-wrap items-center justify-between border-b border-white/10 bg-white/[0.02] px-4">
          <div className="flex flex-wrap gap-1 py-2">
            {TABS.map((tab) => {
              const isSelected = tab.id === activeTab.id;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTabId(tab.id)}
                  className={`flex items-center gap-2 rounded-lg px-3.5 py-2 font-mono text-xs transition ${
                    isSelected
                      ? "bg-white/10 text-white font-bold shadow-sm"
                      : "text-white/40 hover:bg-white/5 hover:text-white/80"
                  }`}
                >
                  <FileCode size={13} className={isSelected ? "text-sky-400" : "text-white/30"} />
                  <span>{tab.name}</span>
                  <span className="rounded bg-white/5 px-1.5 py-0.5 text-[9px] text-sky-300">
                    {tab.badge}
                  </span>
                </button>
              );
            })}
          </div>

          <button
            onClick={handleCopy}
            className="my-2 flex items-center gap-1.5 rounded-lg border border-white/10 bg-white/5 px-3 py-1.5 font-mono text-xs text-white/60 transition hover:bg-white/10 hover:text-white"
            title="Copy code"
          >
            {copied ? (
              <>
                <Check size={12} className="text-emerald-400" />
                <span className="text-emerald-400">Copied</span>
              </>
            ) : (
              <>
                <Copy size={12} />
                <span>Copy</span>
              </>
            )}
          </button>
        </div>

        {/* Tab explanation banner */}
        <div className="border-b border-white/[0.06] bg-white/[0.01] px-6 py-3">
          <p className="text-xs text-white/60">{activeTab.description}</p>
        </div>

        {/* Code Content */}
        <div className="relative p-6">
          <pre className="overflow-x-auto font-mono text-xs leading-relaxed text-sky-100">
            <code>{activeTab.code}</code>
          </pre>
        </div>

        {/* Security Highlight Notes */}
        <div className="border-t border-white/10 bg-[#04060d] px-6 py-4">
          <div className="flex flex-wrap items-center gap-6">
            <span className="font-mono text-[10px] font-bold uppercase tracking-wider text-sky-400">
              Guaranteed Invariants:
            </span>
            {activeTab.highlightNotes.map((note, i) => (
              <div key={i} className="flex items-center gap-2 font-mono text-xs text-white/60">
                <span className="h-1 w-1 rounded-full bg-emerald-400" />
                <span>{note}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}
