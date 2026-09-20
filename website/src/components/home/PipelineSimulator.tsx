"use client";

import { useState } from "react";
import Link from "next/link";
import {
  Play,
  RotateCcw,
  Shield,
  Zap,
  Terminal,
  Lock,
  CheckCircle2,
  XCircle,
  AlertOctagon,
  ChevronRight,
  ExternalLink,
} from "lucide-react";
import {
  COMMIT_SHA,
  getGithubSourceUrl,
  EvidenceBadge,
  type EvidenceLevel,
} from "@/components/evidence/EvidenceBadge";

interface Scenario {
  id: string;
  name: string;
  badge: string;
  badgeColor: string;
  command: string;
  callerClaim?: string;
  targetCapability: string;
  stages: {
    title: string;
    step: string;
    status: "pass" | "fail" | "warn" | "neutral";
    headline: string;
    details: string;
    codeSnippet?: string;
    evidenceLevel: EvidenceLevel;
    invariantId?: string;
    implFile: string;
    implLines: [number, number];
    testFile: string;
    testLines: [number, number];
  }[];
}

const SCENARIOS: Scenario[] = [
  {
    id: "safe-read",
    name: "Scenario A: Authorized Workspace Read",
    badge: "Policy Allowed",
    badgeColor: "text-emerald-400 border-emerald-500/30 bg-emerald-500/10",
    command: 'files.read({ path: "src/config.ts" })',
    targetCapability: "files.read@1",
    stages: [
      {
        title: "01. Capability Registry",
        step: "Registry Lookup",
        status: "pass",
        headline: "Registered Capability & Schema Match",
        details: "files.read v1 is registered with immutable inputSchema. Version and name match exactly.",
        codeSnippet: `{ "name": "files.read", "version": 1, "risk": { "base": "low" } }`,
        evidenceLevel: "LEVEL 1 — UNIT TESTED",
        invariantId: "INV-01 & INV-02",
        implFile: "packages/security/src/index.ts",
        implLines: [295, 307],
        testFile: "tests/invariants/invariants.test.ts",
        testLines: [54, 72],
      },
      {
        title: "02. Authoritative Risk",
        step: "Risk Engine",
        status: "pass",
        headline: "Computed Risk: LOW",
        details: "Read within authorized workspace computed as low risk from declared factors.",
        codeSnippet: `{ "effectiveRisk": "low", "baseLevel": "low" }`,
        evidenceLevel: "LEVEL 1 — UNIT TESTED",
        invariantId: "INV-04",
        implFile: "packages/security/src/index.ts",
        implLines: [337, 347],
        testFile: "tests/invariants/invariants.test.ts",
        testLines: [84, 112],
      },
      {
        title: "03. Default-Deny Policy",
        step: "Policy Evaluator",
        status: "pass",
        headline: "Matching Allow Rule Evaluated",
        details: "Explicit allow rule matched. If no rule had matched, policy engine would return deny.",
        codeSnippet: `{ "action": "ALLOW", "matchedRules": ["allow:files.read"] }`,
        evidenceLevel: "LEVEL 1 — UNIT TESTED",
        invariantId: "INV-03",
        implFile: "packages/policy/src/index.ts",
        implLines: [365, 382],
        testFile: "tests/invariants/invariants.test.ts",
        testLines: [74, 82],
      },
      {
        title: "04. Single-Use Ticket",
        step: "Crypto Minting",
        status: "pass",
        headline: "Ticket Minted with HMAC-SHA256",
        details: "Cryptographic ticket issued with 60s TTL and canonical signature covering all bindings.",
        codeSnippet: `{ "ticketId": "tkt_8f9a2c", "status": "issued", "signature": "e4a91b...c2" }`,
        evidenceLevel: "LEVEL 1 — UNIT TESTED",
        invariantId: "INV-10",
        implFile: "packages/core/src/ticket-store.ts",
        implLines: [141, 171],
        testFile: "tests/unit/ticket-store.test.ts",
        testLines: [29, 41],
      },
      {
        title: "05. Delegated OS Sandbox",
        step: "Platform Sandbox",
        status: "pass",
        headline: "Executed in Platform Sandbox",
        details: "Spawned inside macOS Seatbelt or Linux bubblewrap with read-only view of workspace.",
        codeSnippet: `[seatbelt:deny-all-except] (allow file-read* (subpath "/workspace"))`,
        evidenceLevel: "LEVEL 3 — REAL OS ENFORCEMENT",
        implFile: "packages/sandbox/src/index.ts",
        implLines: [220, 280],
        testFile: "tests/sandbox/darwin.test.ts",
        testLines: [63, 117],
      },
      {
        title: "06. Redacted Audit Log",
        step: "Audit Emitter",
        status: "pass",
        headline: "Audit Event Emitted (Redacted)",
        details: "Structured event recorded with ticketId, timestamp, and sensitive credentials redacted.",
        codeSnippet: `{ "event": "CAPABILITY_EXEC", "status": "SUCCESS", "ticket": "tkt_8f9a2c" }`,
        evidenceLevel: "LEVEL 1 — UNIT TESTED",
        invariantId: "INV-08",
        implFile: "packages/sandbox/src/index.ts",
        implLines: [85, 125],
        testFile: "tests/invariants/invariants.test.ts",
        testLines: [219, 243],
      },
    ],
  },
  {
    id: "unauthorized-cmd",
    name: "Scenario B: Unregistered / Denied Exec",
    badge: "Policy Denied",
    badgeColor: "text-rose-400 border-rose-500/30 bg-rose-500/10",
    command: 'shell.exec({ cmd: "rm -rf / --no-preserve-root" })',
    targetCapability: "shell.exec@1",
    stages: [
      {
        title: "01. Capability Registry",
        step: "Registry Lookup",
        status: "pass",
        headline: "Registered Capability Found",
        details: "shell.exec v1 is defined with declared base risk: critical.",
        codeSnippet: `{ "name": "shell.exec", "risk": { "base": "critical" } }`,
        evidenceLevel: "LEVEL 1 — UNIT TESTED",
        invariantId: "INV-01",
        implFile: "packages/security/src/index.ts",
        implLines: [295, 301],
        testFile: "tests/invariants/invariants.test.ts",
        testLines: [54, 62],
      },
      {
        title: "02. Authoritative Risk",
        step: "Risk Engine",
        status: "warn",
        headline: "Evaluated Risk: CRITICAL",
        details: "Authoritative risk evaluator flags critical risk for unrestricted shell execution.",
        codeSnippet: `{ "effectiveRisk": "critical", "baseLevel": "critical" }`,
        evidenceLevel: "LEVEL 1 — UNIT TESTED",
        invariantId: "INV-04",
        implFile: "packages/security/src/index.ts",
        implLines: [337, 347],
        testFile: "tests/invariants/invariants.test.ts",
        testLines: [84, 112],
      },
      {
        title: "03. Default-Deny Policy",
        step: "Policy Evaluator",
        status: "fail",
        headline: "DENIED BY DEFAULT-DENY POLICY",
        details: "No matching allow rule permits critical shell destruction. Evaluator returns decision: 'deny'.",
        codeSnippet: `{ "decision": "deny", "code": "policy.default_deny" }`,
        evidenceLevel: "LEVEL 1 — UNIT TESTED",
        invariantId: "INV-03",
        implFile: "packages/policy/src/index.ts",
        implLines: [365, 382],
        testFile: "tests/invariants/invariants.test.ts",
        testLines: [74, 82],
      },
      {
        title: "04. Single-Use Ticket",
        step: "Crypto Minting",
        status: "neutral",
        headline: "Execution Halted Before Ticket Minting",
        details: "Zero tickets are minted for denied requests. The authorization boundary halts the pipeline.",
        codeSnippet: `TICKET_STORE: NULL (No ticket issued on denial)`,
        evidenceLevel: "LEVEL 1 — UNIT TESTED",
        implFile: "packages/security/src/index.ts",
        implLines: [295, 301],
        testFile: "tests/invariants/invariants.test.ts",
        testLines: [54, 62],
      },
    ],
  },
  {
    id: "ticket-replay",
    name: "Scenario C: Replay Attack (Second Redemption)",
    badge: "Replay Rejected (ok: false)",
    badgeColor: "text-amber-400 border-amber-500/30 bg-amber-500/10",
    command: 'rtq.execute("tkt_already_consumed_91")',
    targetCapability: "files.read@1 (Stale Ticket)",
    stages: [
      {
        title: "01. First Execution",
        step: "Initial Redemption",
        status: "pass",
        headline: "Ticket Redeemed on First Attempt",
        details: "First redemption succeeds (first.ok === true) and marks ticket status: 'redeemed'.",
        codeSnippet: `{ "ticketId": "tkt_already_consumed_91", "ok": true, "status": "redeemed" }`,
        evidenceLevel: "LEVEL 2 — INTEGRATION TESTED",
        invariantId: "INV-09",
        implFile: "packages/core/src/ticket-store.ts",
        implLines: [180, 206],
        testFile: "tests/invariants/invariants.test.ts",
        testLines: [245, 263],
      },
      {
        title: "02. Second Execution Attempt",
        step: "Replay Check",
        status: "fail",
        headline: "REPLAY REJECTED: second.ok === false",
        details: "Calling rtq.execute() with an already consumed ticket returns ok: false with code 'replay'.",
        codeSnippet: `{ "ok": false, "code": "replay", "reason": "Ticket was already redeemed" }`,
        evidenceLevel: "LEVEL 2 — INTEGRATION TESTED",
        invariantId: "INV-09",
        implFile: "packages/core/src/ticket-store.ts",
        implLines: [194, 206],
        testFile: "tests/invariants/invariants.test.ts",
        testLines: [245, 263],
      },
      {
        title: "03. OS Sandbox Boundary",
        step: "Sandbox Gate",
        status: "neutral",
        headline: "Sandbox Never Initiated",
        details: "Child process is never spawned when ticket validation fails.",
        codeSnippet: `EXECUTION_ABORTED: 0 processes spawned`,
        evidenceLevel: "LEVEL 1 — UNIT TESTED",
        implFile: "packages/sandbox/src/index.ts",
        implLines: [220, 280],
        testFile: "tests/sandbox/darwin.test.ts",
        testLines: [63, 117],
      },
    ],
  },
  {
    id: "risk-downgrade",
    name: "Scenario D: Caller Risk Downgrade Attempt",
    badge: "Caller Claim Ignored",
    badgeColor: "text-sky-400 border-sky-500/30 bg-sky-500/10",
    command: 'db.drop({}) /* caller passes metadata: { claimedRisk: "low" } */',
    callerClaim: 'Caller claims claimedRisk: "low"',
    targetCapability: "db.drop@1 (declared base: high)",
    stages: [
      {
        title: "01. Capability Declaration",
        step: "Registry Check",
        status: "pass",
        headline: "Capability Registered with Base Risk: HIGH",
        details: "db.drop is registered with risk: { base: 'high' } in capability definition.",
        codeSnippet: `{ "name": "db.drop", "risk": { "base": "high" } }`,
        evidenceLevel: "LEVEL 1 — UNIT TESTED",
        invariantId: "INV-04",
        implFile: "packages/security/src/index.ts",
        implLines: [337, 347],
        testFile: "tests/invariants/invariants.test.ts",
        testLines: [84, 112],
      },
      {
        title: "02. Authoritative Risk Check",
        step: "Risk Engine",
        status: "warn",
        headline: "Caller Claim to Lower Risk Ignored",
        details: "RTQ ignores caller's 'low' claim; evaluates risk authoritatively as 'high'.",
        codeSnippet: `// Input claimedRisk: "low" ignored. Result: { "risk": "high" }`,
        evidenceLevel: "LEVEL 1 — UNIT TESTED",
        invariantId: "INV-04",
        implFile: "packages/security/src/index.ts",
        implLines: [337, 347],
        testFile: "tests/invariants/invariants.test.ts",
        testLines: [84, 112],
      },
      {
        title: "03. Policy Decision",
        step: "Approval Mandated",
        status: "warn",
        headline: "decision: 'approval_required'",
        details: "Because effective risk remains 'high', RTQ mandates human or cryptographic device confirmation.",
        codeSnippet: `{ "decision": "approval_required", "risk": "high" }`,
        evidenceLevel: "LEVEL 1 — UNIT TESTED",
        invariantId: "INV-06",
        implFile: "packages/security/src/index.ts",
        implLines: [437, 449],
        testFile: "tests/invariants/invariants.test.ts",
        testLines: [133, 189],
      },
    ],
  },
];

export function PipelineSimulator() {
  const [selectedScenarioId, setSelectedScenarioId] = useState(SCENARIOS[0].id);
  const [activeStageIndex, setActiveStageIndex] = useState(0);

  const scenario = SCENARIOS.find((s) => s.id === selectedScenarioId) || SCENARIOS[0];

  const handleScenarioChange = (id: string) => {
    setSelectedScenarioId(id);
    setActiveStageIndex(0);
  };

  const current = scenario.stages[activeStageIndex];
  const implUrl = getGithubSourceUrl(
    current.implFile,
    current.implLines[0],
    current.implLines[1],
  );
  const testUrl = getGithubSourceUrl(
    current.testFile,
    current.testLines[0],
    current.testLines[1],
  );

  return (
    <section id="pipeline" className="relative mx-auto max-w-6xl px-6 py-24">
      {/* Header */}
      <div className="mb-12 text-center">
        <div className="mb-3 inline-flex items-center gap-2 rounded-full border border-sky-500/20 bg-sky-500/10 px-3 py-1 font-mono text-xs uppercase tracking-widest text-sky-400">
          <Zap size={13} />
          <span>Interactive Execution Simulator</span>
        </div>
        <h2 className="text-3xl font-black tracking-tight text-white md:text-5xl">
          The RTQ Security Pipeline
        </h2>
        <p className="mx-auto mt-4 max-w-2xl text-sm leading-relaxed text-white/50 md:text-base">
          Every invocation follows an explicit fail-closed path. Select a tested scenario below to
          trace how registry lookups, authoritative risk checks, and single-use tickets behave in
          repository tests.
        </p>
      </div>

      {/* Scenario Selector Tabs */}
      <div className="mb-8 grid grid-cols-1 gap-2.5 sm:grid-cols-2 lg:grid-cols-4">
        {SCENARIOS.map((s) => {
          const isSelected = s.id === scenario.id;
          return (
            <button
              key={s.id}
              onClick={() => handleScenarioChange(s.id)}
              className={`flex flex-col items-start rounded-xl border p-4 text-left transition ${
                isSelected
                  ? "border-sky-500/50 bg-sky-500/10 shadow-[0_0_25px_rgba(56,189,248,0.15)]"
                  : "border-white/[0.08] bg-white/[0.02] hover:border-white/20 hover:bg-white/[0.04]"
              }`}
            >
              <div className="flex w-full items-center justify-between">
                <span
                  className={`rounded-full border px-2 py-0.5 font-mono text-[10px] font-bold ${s.badgeColor}`}
                >
                  {s.badge}
                </span>
                {isSelected && <ChevronRight size={14} className="text-sky-400" />}
              </div>
              <p className="mt-2.5 font-mono text-xs font-bold text-white">{s.name}</p>
              <p className="mt-1 line-clamp-1 font-mono text-[11px] text-white/40">{s.command}</p>
            </button>
          );
        })}
      </div>

      {/* Simulator Terminal Card */}
      <div className="overflow-hidden rounded-2xl border border-white/[0.1] bg-[#070914] shadow-2xl">
        {/* Terminal Title Bar */}
        <div className="flex flex-wrap items-center justify-between gap-4 border-b border-white/[0.08] bg-white/[0.02] px-6 py-4">
          <div className="flex items-center gap-3">
            <div className="flex gap-1.5">
              <div className="h-3 w-3 rounded-full bg-rose-500/80" />
              <div className="h-3 w-3 rounded-full bg-amber-500/80" />
              <div className="h-3 w-3 rounded-full bg-emerald-500/80" />
            </div>
            <span className="font-mono text-xs text-white/40">rtq-runtime-inspector</span>
          </div>

          <div className="flex items-center gap-2">
            <span className="font-mono text-xs text-white/40">Command:</span>
            <code className="rounded border border-white/10 bg-white/5 px-2.5 py-1 font-mono text-xs font-semibold text-sky-300">
              {scenario.command}
            </code>
          </div>

          <button
            onClick={() => setActiveStageIndex(0)}
            className="flex items-center gap-1.5 rounded-lg border border-white/10 bg-white/5 px-3 py-1 font-mono text-xs text-white/60 transition hover:bg-white/10 hover:text-white"
          >
            <RotateCcw size={12} />
            <span>Reset</span>
          </button>
        </div>

        {/* Step Indicator Progress */}
        <div className="grid grid-cols-2 gap-2 border-b border-white/[0.08] bg-white/[0.01] p-4 md:grid-cols-4 lg:grid-cols-6">
          {scenario.stages.map((stage, idx) => {
            const isActive = idx === activeStageIndex;
            return (
              <button
                key={stage.title}
                onClick={() => setActiveStageIndex(idx)}
                className={`flex flex-col rounded-lg p-2.5 text-left transition ${
                  isActive
                    ? "border border-sky-500/40 bg-sky-500/15"
                    : "border border-transparent hover:bg-white/5"
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="font-mono text-[10px] uppercase tracking-wider text-white/40">
                    Step 0{idx + 1}
                  </span>
                  {stage.status === "pass" && <CheckCircle2 size={13} className="text-emerald-400" />}
                  {stage.status === "fail" && <XCircle size={13} className="text-rose-400" />}
                  {stage.status === "warn" && <AlertOctagon size={13} className="text-amber-400" />}
                  {stage.status === "neutral" && <Lock size={13} className="text-white/20" />}
                </div>
                <span className="mt-1 font-mono text-xs font-bold text-white/90">
                  {stage.step}
                </span>
              </button>
            );
          })}
        </div>

        {/* Active Stage Details */}
        <div className="p-6 md:p-8">
          <div className="grid grid-cols-1 gap-8 lg:grid-cols-12">
            {/* Left: Explanation & Evidence Links */}
            <div className="space-y-6 lg:col-span-7">
              <div>
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-mono text-xs uppercase tracking-widest text-sky-400">
                    {current.title}
                  </span>
                  {current.invariantId && (
                    <span className="rounded-full border border-sky-500/30 bg-sky-500/10 px-2.5 py-0.5 font-mono text-[10px] font-bold text-sky-300">
                      {current.invariantId}
                    </span>
                  )}
                  <EvidenceBadge level={current.evidenceLevel} />
                </div>
                <h3 className="mt-2 text-xl font-black text-white md:text-2xl">
                  {current.headline}
                </h3>
                <p className="mt-3 text-sm leading-relaxed text-white/70">
                  {current.details}
                </p>
              </div>

              {/* Evidence Chain Links */}
              <div className="rounded-xl border border-white/5 bg-black/30 p-4 space-y-2 font-mono text-xs">
                <span className="font-bold uppercase text-[10px] text-white/40 tracking-wider block">
                  Evidence Chain (Commit {COMMIT_SHA})
                </span>
                <div className="flex flex-wrap items-center gap-4">
                  <a
                    href={implUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 text-sky-400 hover:underline"
                  >
                    <span>{current.implFile} (L{current.implLines[0]}-{current.implLines[1]})</span>
                    <ExternalLink size={11} />
                  </a>
                  <span className="text-white/20">&bull;</span>
                  <a
                    href={testUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 text-sky-300 hover:underline"
                  >
                    <span>{current.testFile} (L{current.testLines[0]}-{current.testLines[1]})</span>
                    <ExternalLink size={11} />
                  </a>
                </div>
              </div>

              {/* Stage navigation controls */}
              <div className="flex items-center gap-3 pt-2">
                <button
                  disabled={activeStageIndex === 0}
                  onClick={() => setActiveStageIndex((prev) => Math.max(0, prev - 1))}
                  className="rounded-lg border border-white/10 bg-white/5 px-4 py-2 font-mono text-xs text-white/60 transition hover:bg-white/10 hover:text-white disabled:opacity-30"
                >
                  &larr; Previous Stage
                </button>
                <button
                  disabled={activeStageIndex >= scenario.stages.length - 1}
                  onClick={() =>
                    setActiveStageIndex((prev) =>
                      Math.min(scenario.stages.length - 1, prev + 1)
                    )
                  }
                  className="flex items-center gap-1.5 rounded-lg bg-sky-500 px-4 py-2 font-mono text-xs font-bold text-white transition hover:bg-sky-400 disabled:opacity-30"
                >
                  <span>Next Stage</span>
                  <ChevronRight size={14} />
                </button>
                <span className="font-mono text-xs text-white/40">
                  Stage {activeStageIndex + 1} of {scenario.stages.length}
                </span>
              </div>
            </div>

            {/* Right: Runtime State Inspection */}
            <div className="lg:col-span-5">
              <div className="rounded-xl border border-white/10 bg-[#04060d] p-4 space-y-3">
                <div className="flex items-center justify-between border-b border-white/5 pb-2">
                  <div className="flex items-center gap-2">
                    <Terminal size={13} className="text-sky-400" />
                    <span className="font-mono text-[11px] uppercase tracking-wider text-white/50">
                      Runtime State Inspector
                    </span>
                  </div>
                  <span className="font-mono text-[10px] text-emerald-400">CI TESTED</span>
                </div>

                <pre className="overflow-x-auto p-1 font-mono text-xs leading-relaxed text-sky-200">
                  <code>{current.codeSnippet || "// No state mutation at this stage"}</code>
                </pre>

                <div className="border-t border-white/5 pt-3">
                  <p className="font-mono text-[10px] text-white/40">
                    Tested behavior corresponds to repository automated tests. See{" "}
                    <Link href="/docs/evidence" className="text-sky-400 underline">
                      /docs/evidence
                    </Link>{" "}
                    for full scope and limitations.
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
