import Link from "next/link";
import { CheckCircle2, Shield, AlertTriangle, ExternalLink, TestTube, ArrowRight } from "lucide-react";
import {
  COMMIT_SHA,
  REPO_BASE,
  EvidenceBadge,
  getGithubSourceUrl,
  getWorkflowUrl,
} from "@/components/evidence/EvidenceBadge";

export const metadata = {
  title: "Verification Matrix",
  description: "Twelve automated security properties tested in repository CI on every commit.",
};

export default function VerificationMatrixPage() {
  const properties = [
    {
      id: "INV-01",
      property: "Explicit surface: unregistered capability is denied",
      level: "LEVEL 1 — UNIT TESTED" as const,
      impl: "packages/security/src/index.ts",
      implLines: "L295-L301",
      test: "tests/invariants/invariants.test.ts",
      testLines: "L54-L62",
      workflow: "security.yml",
      runner: "ubuntu-latest",
    },
    {
      id: "INV-02",
      property: "Explicit surface: wrong capability version is denied",
      level: "LEVEL 1 — UNIT TESTED" as const,
      impl: "packages/security/src/index.ts",
      implLines: "L302-L307",
      test: "tests/invariants/invariants.test.ts",
      testLines: "L64-L72",
      workflow: "security.yml",
      runner: "ubuntu-latest",
    },
    {
      id: "INV-03",
      property: "Default-deny policy: no matching rule results in denial",
      level: "LEVEL 1 — UNIT TESTED" as const,
      impl: "packages/policy/src/index.ts",
      implLines: "L365-L382",
      test: "tests/invariants/invariants.test.ts",
      testLines: "L74-L82",
      workflow: "security.yml",
      runner: "ubuntu-latest",
    },
    {
      id: "INV-04",
      property: "Authoritative risk: caller claimedRisk cannot downgrade declared risk",
      level: "LEVEL 1 — UNIT TESTED" as const,
      impl: "packages/security/src/index.ts",
      implLines: "L337-L347",
      test: "tests/invariants/invariants.test.ts",
      testLines: "L84-L112",
      workflow: "security.yml",
      runner: "ubuntu-latest",
    },
    {
      id: "INV-05",
      property: "Origin is a hint: unknown origin is never treated as local and escalates",
      level: "LEVEL 1 — UNIT TESTED" as const,
      impl: "packages/security/src/index.ts",
      implLines: "L320-L325",
      test: "tests/invariants/invariants.test.ts",
      testLines: "L114-L131",
      workflow: "security.yml",
      runner: "ubuntu-latest",
    },
    {
      id: "INV-06",
      property: "Approval strategy defaults: high/critical risk is never automatic",
      level: "LEVEL 1 — UNIT TESTED" as const,
      impl: "packages/security/src/index.ts",
      implLines: "L437-L449",
      test: "tests/invariants/invariants.test.ts",
      testLines: "L133-L189",
      workflow: "security.yml",
      runner: "ubuntu-latest",
    },
    {
      id: "INV-07",
      property: "Sandbox network deny-by-default: emits --unshare-net; unsupported allowlist throws",
      level: "LEVEL 1 — UNIT TESTED" as const,
      impl: "packages/sandbox/src/index.ts",
      implLines: "L140-L195",
      test: "tests/invariants/invariants.test.ts",
      testLines: "L191-L217",
      workflow: "security.yml",
      runner: "ubuntu-latest",
    },
    {
      id: "INV-08",
      property: "Ambient secrets stripped from child process environment",
      level: "LEVEL 1 — UNIT TESTED" as const,
      impl: "packages/sandbox/src/index.ts",
      implLines: "L85-L125",
      test: "tests/invariants/invariants.test.ts",
      testLines: "L219-L243",
      workflow: "security.yml",
      runner: "ubuntu-latest",
    },
    {
      id: "INV-09",
      property: "Single-use tickets: second redemption is rejected (replay check)",
      level: "LEVEL 2 — INTEGRATION TESTED" as const,
      impl: "packages/core/src/ticket-store.ts",
      implLines: "L194-L206",
      test: "tests/invariants/invariants.test.ts",
      testLines: "L245-L263",
      workflow: "security.yml",
      runner: "ubuntu-latest",
    },
    {
      id: "INV-10",
      property: "Tickets are replay- and tamper-resistant via HMAC-SHA256 signatures",
      level: "LEVEL 1 — UNIT TESTED" as const,
      impl: "packages/core/src/ticket-store.ts",
      implLines: "L159-L164",
      test: "tests/unit/ticket-store.test.ts",
      testLines: "L70-L86",
      workflow: "security.yml",
      runner: "ubuntu-latest",
    },
    {
      id: "INV-11",
      property: "Replacing a capability invalidates previously issued outstanding tickets",
      level: "LEVEL 2 — INTEGRATION TESTED" as const,
      impl: "packages/core/src/ticket-store.ts",
      implLines: "L232-L240",
      test: "tests/invariants/invariants.test.ts",
      testLines: "L291-L323",
      workflow: "security.yml",
      runner: "ubuntu-latest",
    },
    {
      id: "INV-12",
      property: "Approval substitution rejected: approval for challenge A cannot authorize B",
      level: "LEVEL 2 — INTEGRATION TESTED" as const,
      impl: "packages/security/src/index.ts",
      implLines: "L470-L520",
      test: "tests/invariants/invariants.test.ts",
      testLines: "L325-L380",
      workflow: "security.yml",
      runner: "ubuntu-latest",
    },
  ];

  return (
    <div className="space-y-10">
      <div>
        <p className="mb-3 text-[10px] font-mono font-bold uppercase tracking-[0.5em] text-sky-400">
          Security &bull; CI Verification
        </p>
        <h1 className="text-3xl font-black tracking-tight text-white md:text-5xl">
          Verification Matrix
        </h1>
        <p className="mt-4 text-base text-white/60 leading-relaxed">
          Below are the 12 automated checks configured for the current verification suite. The evidence shown here corresponds to commit e179d2b.
        </p>
        <p className="mt-2 text-sm font-bold text-emerald-400">
          CI status for e179d2b: Passed
        </p>
      </div>

      <div className="rounded-xl border border-sky-500/20 bg-sky-500/5 p-4 text-xs text-sky-200/90 leading-relaxed">
        <strong>Verification specification revision: e179d2b</strong> – invariant definitions were updated at this commit; previous IDs may have changed. See the <Link href="/docs/invariant-changelog.md" className="underline text-sky-300 font-bold">Changelog</Link>.
      </div>

      {/* Methodology Disclaimer */}
      <div className="rounded-xl border border-amber-500/20 bg-amber-500/5 p-4 text-xs text-amber-200/90 leading-relaxed">
        <strong>Important Clarification:</strong> Passing automated CI tests does not constitute a
        formal mathematical proof or an independent security audit. Each check demonstrates
        empirical conformance for the tested code paths and environment. For complete evidence chains,
        see the{" "}
        <Link href="/docs/evidence" className="underline text-amber-300 font-bold">
          Evidence &amp; Verification
        </Link>{" "}
        documentation.
      </div>

      {/* Properties Table */}
      <div>
        <h2 className="text-xl font-bold text-white mb-4">
          Automated Properties Tested in CI
        </h2>
        <div className="overflow-x-auto rounded-xl border border-white/10 bg-[#070914]">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-white/10 bg-white/[0.02]">
                <th className="p-3.5 font-mono text-[10px] font-bold uppercase tracking-wider text-white/40">ID</th>
                <th className="p-3.5 font-mono text-[10px] font-bold uppercase tracking-wider text-white/40">Tested Property</th>
                <th className="p-3.5 font-mono text-[10px] font-bold uppercase tracking-wider text-white/40">Level</th>
                <th className="p-3.5 font-mono text-[10px] font-bold uppercase tracking-wider text-white/40">Source Code</th>
                <th className="p-3.5 font-mono text-[10px] font-bold uppercase tracking-wider text-white/40">Test Code</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5 font-mono">
              {properties.map((p) => (
                <tr key={p.id} className="hover:bg-white/[0.02] transition">
                  <td className="p-3.5 text-sky-400 font-bold">{p.id}</td>
                  <td className="p-3.5 font-sans text-white/80 max-w-xs">{p.property}</td>
                  <td className="p-3.5">
                    <EvidenceBadge level={p.level} />
                  </td>
                  <td className="p-3.5 text-[11px]">
                    <a
                      href={`${REPO_BASE}/blob/${COMMIT_SHA}/${p.impl}#${p.implLines}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-sky-400 hover:underline inline-flex items-center gap-1"
                    >
                      <span>{p.implLines}</span>
                      <ExternalLink size={10} />
                    </a>
                  </td>
                  <td className="p-3.5 text-[11px]">
                    <a
                      href={`${REPO_BASE}/blob/${COMMIT_SHA}/${p.test}#${p.testLines}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-sky-300 hover:underline inline-flex items-center gap-1"
                    >
                      <span>{p.testLines}</span>
                      <ExternalLink size={10} />
                    </a>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Real OS Gating & Workflows */}
      <div className="space-y-4">
        <h2 className="text-xl font-bold text-white">CI Workflows &amp; Runners</h2>
        <p className="text-xs text-white/50 leading-relaxed">
          Tests are executed in Vitest under Node 24 on GitHub Actions runners.
          Platform sandboxes run on their specific OS runner in{" "}
          <code className="text-sky-300">.github/workflows/sandbox.yml</code>:
        </p>

        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 text-xs">
          <div className="rounded-xl border border-white/10 bg-white/[0.02] p-4 space-y-2">
            <span className="font-mono font-bold text-sky-400">security.yml</span>
            <p className="text-white/60">
              Runs the 12 invariants on <code className="text-white">ubuntu-latest</code>. Also runs
              pipeline and audit integration tests across an OS matrix (Ubuntu, macOS, Windows).
            </p>
          </div>
          <div className="rounded-xl border border-white/10 bg-white/[0.02] p-4 space-y-2">
            <span className="font-mono font-bold text-sky-400">sandbox.yml</span>
            <p className="text-white/60">
              Executes real macOS Seatbelt tests on <code className="text-white">macos-15</code>,
              bubblewrap checks on <code className="text-white">ubuntu-latest</code>, and AppContainer
              checks on <code className="text-white">windows-latest</code>.
            </p>
          </div>
        </div>
      </div>

      <div className="mt-8 flex flex-wrap gap-4 border-t border-white/10 pt-6">
        <Link
          href="/docs/evidence"
          className="rounded-xl border border-sky-500/20 bg-sky-500/10 px-4 py-2.5 font-mono text-xs font-bold text-sky-400 hover:bg-sky-500/20 transition inline-flex items-center gap-1.5"
        >
          <span>View Full Evidence Chains &rarr;</span>
        </Link>
        <Link
          href="/docs/threat-model"
          className="rounded-xl border border-white/10 bg-white/5 px-4 py-2.5 font-mono text-xs font-bold text-white/70 hover:bg-white/10 hover:text-white transition"
        >
          Threat Model &amp; Limitations &rarr;
        </Link>
      </div>
    </div>
  );
}
