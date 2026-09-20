"use client";

import { useState } from "react";
import Link from "next/link";
import { CheckCircle2, ShieldCheck, ArrowRight, Filter, ExternalLink, TestTube } from "lucide-react";
import {
  COMMIT_SHA,
  getGithubSourceUrl,
  EvidenceBadge,
  type EvidenceLevel,
} from "@/components/evidence/EvidenceBadge";

interface InvariantItem {
  id: string;
  category: "surface" | "policy-risk" | "tickets" | "sandbox-env";
  title: string;
  testedBehavior: string;
  limitation: string;
  level: EvidenceLevel;
  implementationFile: string;
  implLines: [number, number];
  testFile: string;
  testLines: [number, number];
  workflow: string;
  runner: string;
}

const INVARIANTS: InvariantItem[] = [
  {
    id: "INV-01",
    category: "surface",
    title: "Explicit Surface: Unregistered Denied",
    testedBehavior: "Calling rtq.authorize() for 'shell.exec' without registration returns decision: 'denied'.",
    limitation: "Does not prove internal security of registered capability handlers.",
    level: "LEVEL 1 — UNIT TESTED",
    implementationFile: "packages/security/src/index.ts",
    implLines: [295, 301],
    testFile: "tests/invariants/invariants.test.ts",
    testLines: [54, 62],
    workflow: "security.yml",
    runner: "ubuntu-latest",
  },
  {
    id: "INV-02",
    category: "surface",
    title: "Explicit Surface: Version Mismatch Denied",
    testedBehavior: "Requested version 2 for version 1 capability returns decision: 'denied'.",
    limitation: "Does not establish automatic backward-compatibility migration safety.",
    level: "LEVEL 1 — UNIT TESTED",
    implementationFile: "packages/security/src/index.ts",
    implLines: [302, 307],
    testFile: "tests/invariants/invariants.test.ts",
    testLines: [64, 72],
    workflow: "security.yml",
    runner: "ubuntu-latest",
  },
  {
    id: "INV-03",
    category: "policy-risk",
    title: "Default-Deny Policy Semantics",
    testedBehavior: "Registered capability with zero matching rules evaluates to decision: 'deny'.",
    limitation: "Does not prevent operators from authoring overly permissive allow rules.",
    level: "LEVEL 1 — UNIT TESTED",
    implementationFile: "packages/policy/src/index.ts",
    implLines: [365, 382],
    testFile: "tests/invariants/invariants.test.ts",
    testLines: [74, 82],
    workflow: "security.yml",
    runner: "ubuntu-latest",
  },
  {
    id: "INV-04",
    category: "policy-risk",
    title: "Authoritative Risk Downgrade Immunity",
    testedBehavior: "Caller claimedRisk: 'low' cannot demote high base risk; still requires approval.",
    limitation: "Declared risk values are set by developers; RTQ does not mathematically prove exploitability.",
    level: "LEVEL 1 — UNIT TESTED",
    implementationFile: "packages/security/src/index.ts",
    implLines: [337, 347],
    testFile: "tests/invariants/invariants.test.ts",
    testLines: [84, 112],
    workflow: "security.yml",
    runner: "ubuntu-latest",
  },
  {
    id: "INV-05",
    category: "policy-risk",
    title: "Unknown Origin Escalation",
    testedBehavior: "origin: 'unknown' is not treated as local and escalates to require approval.",
    limitation: "Relies on caller/host integration honestly supplying caller origin metadata.",
    level: "LEVEL 1 — UNIT TESTED",
    implementationFile: "packages/security/src/index.ts",
    implLines: [320, 325],
    testFile: "tests/invariants/invariants.test.ts",
    testLines: [114, 131],
    workflow: "security.yml",
    runner: "ubuntu-latest",
  },
  {
    id: "INV-06",
    category: "policy-risk",
    title: "High/Critical Approval Non-Automatic",
    testedBehavior: "High and critical risk operations reject automatic approval by default.",
    limitation: "Custom policy rules could explicitly grant overrides if misconfigured.",
    level: "LEVEL 1 — UNIT TESTED",
    implementationFile: "packages/security/src/index.ts",
    implLines: [437, 449],
    testFile: "tests/invariants/invariants.test.ts",
    testLines: [133, 189],
    workflow: "security.yml",
    runner: "ubuntu-latest",
  },
  {
    id: "INV-07",
    category: "sandbox-env",
    title: "Sandbox Network Deny-by-Default",
    testedBehavior: "bwrap argv contains --unshare-net; unsupported network allowlist throws.",
    limitation: "This invariant tests argument assembly; live kernel network drop tested in darwin.test.ts.",
    level: "LEVEL 1 — UNIT TESTED",
    implementationFile: "packages/sandbox/src/index.ts",
    implLines: [140, 195],
    testFile: "tests/invariants/invariants.test.ts",
    testLines: [191, 217],
    workflow: "security.yml",
    runner: "ubuntu-latest",
  },
  {
    id: "INV-08",
    category: "sandbox-env",
    title: "Ambient Secrets Stripped from Env",
    testedBehavior: "buildSandboxEnvironment() strips keys matching 'secret', 'token', and 'API_TOKEN'.",
    limitation: "Does not prevent processes from reading secrets stored on accessible disk paths.",
    level: "LEVEL 1 — UNIT TESTED",
    implementationFile: "packages/sandbox/src/index.ts",
    implLines: [85, 125],
    testFile: "tests/invariants/invariants.test.ts",
    testLines: [219, 243],
    workflow: "security.yml",
    runner: "ubuntu-latest",
  },
  {
    id: "INV-09",
    category: "tickets",
    title: "Single-Use Ticket Replay Rejection",
    testedBehavior: "Second redemption of an authorization ticket via rtq.execute() returns ok: false.",
    limitation: "Relies on in-memory ticket store state within single process; not distributed across nodes.",
    level: "LEVEL 2 — INTEGRATION TESTED",
    implementationFile: "packages/core/src/ticket-store.ts",
    implLines: [194, 206],
    testFile: "tests/invariants/invariants.test.ts",
    testLines: [245, 263],
    workflow: "security.yml",
    runner: "ubuntu-latest",
  },
  {
    id: "INV-10",
    category: "tickets",
    title: "Ticket Cryptogram Tamper Check",
    testedBehavior: "HMAC-SHA256 signature covers ticket bindings and status, detecting tampering.",
    limitation: "Assumes the HMAC signing key is kept confidential in host process memory.",
    level: "LEVEL 1 — UNIT TESTED",
    implementationFile: "packages/core/src/ticket-store.ts",
    implLines: [159, 164],
    testFile: "tests/unit/ticket-store.test.ts",
    testLines: [70, 86],
    workflow: "security.yml",
    runner: "ubuntu-latest",
  },
  {
    id: "INV-11",
    category: "tickets",
    title: "Capability Version Invalidation",
    testedBehavior: "Replacing a capability with v2 invalidates outstanding tickets issued for v1.",
    limitation: "Tickets for other unchanged capabilities remain redeemable until TTL expiration.",
    level: "LEVEL 2 — INTEGRATION TESTED",
    implementationFile: "packages/core/src/ticket-store.ts",
    implLines: [232, 240],
    testFile: "tests/invariants/invariants.test.ts",
    testLines: [291, 323],
    workflow: "security.yml",
    runner: "ubuntu-latest",
  },
  {
    id: "INV-12",
    category: "tickets",
    title: "Approval Substitution Rejected",
    testedBehavior: "Approval signed for challenge A is rejected when submitted to challenge B.",
    limitation: "Does not protect if device private keys are extracted by a physical attacker.",
    level: "LEVEL 2 — INTEGRATION TESTED",
    implementationFile: "packages/security/src/index.ts",
    implLines: [470, 520],
    testFile: "tests/invariants/invariants.test.ts",
    testLines: [325, 380],
    workflow: "security.yml",
    runner: "ubuntu-latest",
  },
];

const CATEGORIES = [
  { id: "all", label: "All 12 Properties" },
  { id: "surface", label: "Surface & Registry (2)" },
  { id: "policy-risk", label: "Policy & Risk (4)" },
  { id: "tickets", label: "Tickets & Replay (4)" },
  { id: "sandbox-env", label: "Sandbox Env (2)" },
];

export function InvariantsMatrix() {
  const [selectedCategory, setSelectedCategory] = useState<string>("all");

  const filtered =
    selectedCategory === "all"
      ? INVARIANTS
      : INVARIANTS.filter((inv) => inv.category === selectedCategory);

  return (
    <section id="invariants" className="relative mx-auto max-w-6xl px-6 py-20">
      <div className="mb-10 flex flex-col items-start justify-between gap-4 md:flex-row md:items-end">
        <div>
          <div className="mb-2 inline-flex items-center gap-2 rounded-full border border-sky-500/20 bg-sky-500/10 px-3 py-1 font-mono text-xs uppercase tracking-widest text-sky-400">
            <TestTube size={13} />
            <span>Automated CI Properties (tests/invariants)</span>
          </div>
          <h2 className="text-3xl font-black tracking-tight text-white md:text-4xl">
            12 Security Properties Tested in CI
          </h2>
          <p className="mt-2 max-w-xl text-sm text-white/50">
            Passing CI does not constitute a mathematical proof. Below are the 12 automated checks
            asserted on every commit to <code className="text-white font-mono">main</code> at commit{" "}
            <code className="text-sky-300 font-mono">{COMMIT_SHA}</code>.
          </p>
        </div>

        <Link
          href="/docs/evidence"
          className="inline-flex items-center gap-1.5 font-mono text-xs font-bold text-sky-400 hover:text-sky-300"
        >
          <span>View Full Evidence Chains &rarr;</span>
          <ArrowRight size={14} />
        </Link>
      </div>

      {/* Filter Tabs */}
      <div className="mb-8 flex flex-wrap items-center gap-2 border-b border-white/10 pb-4">
        <Filter size={13} className="mr-2 text-white/30" />
        {CATEGORIES.map((cat) => {
          const isActive = selectedCategory === cat.id;
          return (
            <button
              key={cat.id}
              onClick={() => setSelectedCategory(cat.id)}
              className={`rounded-lg px-3 py-1.5 font-mono text-xs transition ${
                isActive
                  ? "bg-white/10 text-white font-bold"
                  : "text-white/40 hover:bg-white/5 hover:text-white/70"
              }`}
            >
              {cat.label}
            </button>
          );
        })}
      </div>

      {/* Grid */}
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3">
        {filtered.map((inv) => {
          const implUrl = getGithubSourceUrl(
            inv.implementationFile,
            inv.implLines[0],
            inv.implLines[1],
          );
          const testUrl = getGithubSourceUrl(inv.testFile, inv.testLines[0], inv.testLines[1]);

          return (
            <div
              key={inv.id}
              className="flex flex-col justify-between rounded-xl border border-white/[0.08] bg-white/[0.02] p-5 transition hover:border-sky-500/30 hover:bg-sky-500/[0.02] space-y-4"
            >
              <div>
                <div className="flex items-center justify-between">
                  <span className="font-mono text-xs font-black text-sky-400">{inv.id}</span>
                  <EvidenceBadge level={inv.level} />
                </div>
                <h3 className="mt-2.5 text-sm font-bold text-white">{inv.title}</h3>
                <p className="mt-1.5 text-xs text-white/60 leading-relaxed">{inv.testedBehavior}</p>
              </div>

              <div className="rounded border border-amber-500/15 bg-amber-500/[0.03] p-2 text-[11px] text-amber-300/80">
                <span className="font-mono font-bold uppercase text-[9px] text-amber-400 block">
                  Not Established:
                </span>
                {inv.limitation}
              </div>

              <div className="flex items-center justify-between border-t border-white/5 pt-3 font-mono text-[10px]">
                <a
                  href={implUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1 text-sky-400 hover:underline"
                >
                  <span>Impl (L{inv.implLines[0]}-{inv.implLines[1]})</span>
                  <ExternalLink size={10} />
                </a>
                <a
                  href={testUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1 text-white/50 hover:text-white hover:underline"
                >
                  <span>Test (L{inv.testLines[0]}-{inv.testLines[1]})</span>
                  <ExternalLink size={10} />
                </a>
              </div>
            </div>
          );
        })}
      </div>
    </section>
  );
}
