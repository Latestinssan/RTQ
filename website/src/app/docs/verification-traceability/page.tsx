import Link from "next/link";
import { Shield, Layers, ExternalLink, ArrowRight } from "lucide-react";
import { COMMIT_SHA, REPO_BASE, getGithubSourceUrl } from "@/components/evidence/EvidenceBadge";

export const metadata = {
  title: "Verification & Traceability",
  description: "Direct source line citations for every security property tested in RTQ.",
};

export default function VerificationTraceabilityPage() {
  const traceabilityItems = [
    {
      id: "INV-01",
      claim: "Unregistered capability is denied at boundary",
      implFile: "packages/security/src/index.ts",
      implLines: [295, 301] as [number, number],
      testFile: "tests/invariants/invariants.test.ts",
      testLines: [54, 62] as [number, number],
      behavior: "rtq.authorize() checks this.capabilities.get(); missing capability returns code: 'capability.not_registered'.",
    },
    {
      id: "INV-02",
      claim: "Requested version mismatch is denied",
      implFile: "packages/security/src/index.ts",
      implLines: [302, 307] as [number, number],
      testFile: "tests/invariants/invariants.test.ts",
      testLines: [64, 72] as [number, number],
      behavior: "Exact integer equality check between requested version and registered definition version.",
    },
    {
      id: "INV-03",
      claim: "Default-deny policy evaluation",
      implFile: "packages/policy/src/index.ts",
      implLines: [365, 382] as [number, number],
      testFile: "tests/invariants/invariants.test.ts",
      testLines: [74, 82] as [number, number],
      behavior: "PolicyEngine.evaluate() falls through to decision: 'deny' when no rules match.",
    },
    {
      id: "INV-04",
      claim: "Authoritative risk: caller claims cannot lower risk",
      implFile: "packages/security/src/index.ts",
      implLines: [337, 347] as [number, number],
      testFile: "tests/invariants/invariants.test.ts",
      testLines: [84, 112] as [number, number],
      behavior: "Risk engine evaluates declared capability metadata; caller claimedRisk downgrade is ignored.",
    },
    {
      id: "INV-05",
      claim: "Unknown origin escalates authorization",
      implFile: "packages/security/src/index.ts",
      implLines: [320, 325] as [number, number],
      testFile: "tests/invariants/invariants.test.ts",
      testLines: [114, 131] as [number, number],
      behavior: "Untrusted origin 'unknown' is prevented from receiving local automatic approval.",
    },
    {
      id: "INV-06",
      claim: "High/critical approval strategy is never automatic",
      implFile: "packages/security/src/index.ts",
      implLines: [437, 449] as [number, number],
      testFile: "tests/invariants/invariants.test.ts",
      testLines: [133, 189] as [number, number],
      behavior: "Default strategy resolution mandates human or device confirmation for high/critical risks.",
    },
    {
      id: "INV-07",
      claim: "Sandbox network deny-by-default with --unshare-net",
      implFile: "packages/sandbox/src/index.ts",
      implLines: [140, 195] as [number, number],
      testFile: "tests/invariants/invariants.test.ts",
      testLines: [191, 217] as [number, number],
      behavior: "bubblewrap argv builder injects --unshare-net and throws if an unsupported network allowlist is requested.",
    },
    {
      id: "INV-08",
      claim: "Sensitive environment keys stripped from child process",
      implFile: "packages/sandbox/src/index.ts",
      implLines: [85, 125] as [number, number],
      testFile: "tests/invariants/invariants.test.ts",
      testLines: [219, 243] as [number, number],
      behavior: "buildSandboxEnvironment() strips keys matching 'secret', 'token', and 'API_TOKEN'.",
    },
    {
      id: "INV-09",
      claim: "Single-use tickets: second redemption is rejected",
      implFile: "packages/core/src/ticket-store.ts",
      implLines: [194, 206] as [number, number],
      testFile: "tests/invariants/invariants.test.ts",
      testLines: [245, 263] as [number, number],
      behavior: "Atomic status transition from 'issued' to 'redeemed'; subsequent redemption returns code: 'replay'.",
    },
    {
      id: "INV-10",
      claim: "Ticket signature tamper resistance",
      implFile: "packages/core/src/ticket-store.ts",
      implLines: [159, 164] as [number, number],
      testFile: "tests/unit/ticket-store.test.ts",
      testLines: [70, 86] as [number, number],
      behavior: "HMAC-SHA256 signature covers canonical JSON ticket representation; modified fields fail verification.",
    },
    {
      id: "INV-11",
      claim: "Capability version update invalidates outstanding tickets",
      implFile: "packages/core/src/ticket-store.ts",
      implLines: [232, 240] as [number, number],
      testFile: "tests/invariants/invariants.test.ts",
      testLines: [291, 323] as [number, number],
      behavior: "Ticket redemption verifies expected capability version against stored ticket version.",
    },
    {
      id: "INV-12",
      claim: "Approval substitution rejected across challenges",
      implFile: "packages/security/src/index.ts",
      implLines: [470, 520] as [number, number],
      testFile: "tests/invariants/invariants.test.ts",
      testLines: [325, 380] as [number, number],
      behavior: "Cryptographic challenge signature bound to challengeId A cannot authorize challengeId B.",
    },
  ];

  return (
    <div className="space-y-10">
      <div>
        <p className="mb-3 text-[10px] font-mono font-bold uppercase tracking-[0.5em] text-sky-400">
          Security &bull; Evidence Traceability
        </p>
        <h1 className="text-3xl font-black tracking-tight text-white md:text-5xl">
          Verification Traceability
        </h1>
        <p className="mt-4 text-base text-white/60 leading-relaxed">
          Every security claim links directly to its source file, line numbers, and automated test
          in the repository at commit <code className="text-white font-mono">{COMMIT_SHA}</code>.
        </p>
      </div>

      {/* Traceability Items */}
      <div className="space-y-4">
        {traceabilityItems.map((item) => {
          const implUrl = getGithubSourceUrl(item.implFile, item.implLines[0], item.implLines[1]);
          const testUrl = getGithubSourceUrl(item.testFile, item.testLines[0], item.testLines[1]);

          return (
            <div
              key={item.id}
              className="rounded-xl border border-white/10 bg-[#070914] p-5 space-y-3"
            >
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/5 pb-2">
                <div className="flex items-center gap-2">
                  <span className="rounded bg-sky-500/10 px-2 py-0.5 font-mono text-xs font-bold text-sky-400 border border-sky-500/20">
                    {item.id}
                  </span>
                  <h3 className="text-sm font-bold text-white">{item.claim}</h3>
                </div>
                <span className="font-mono text-[10px] text-emerald-400">CI TESTED</span>
              </div>

              <p className="text-xs text-white/60 leading-relaxed">{item.behavior}</p>

              <div className="flex flex-wrap items-center gap-6 border-t border-white/5 pt-3 font-mono text-xs">
                <div>
                  <span className="text-white/40 block text-[10px] uppercase">Implementation</span>
                  <a
                    href={implUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-sky-400 hover:underline inline-flex items-center gap-1"
                  >
                    <span>{item.implFile} (L{item.implLines[0]}-{item.implLines[1]})</span>
                    <ExternalLink size={10} />
                  </a>
                </div>

                <div>
                  <span className="text-white/40 block text-[10px] uppercase">Automated Test</span>
                  <a
                    href={testUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-sky-300 hover:underline inline-flex items-center gap-1"
                  >
                    <span>{item.testFile} (L{item.testLines[0]}-{item.testLines[1]})</span>
                    <ExternalLink size={10} />
                  </a>
                </div>
              </div>
            </div>
          );
        })}
      </div>

      <div className="flex flex-wrap gap-4 border-t border-white/10 pt-6">
        <Link
          href="/docs/evidence"
          className="rounded-xl border border-sky-500/20 bg-sky-500/10 px-4 py-2.5 font-mono text-xs font-bold text-sky-400 hover:bg-sky-500/20 transition"
        >
          View Evidence Matrix &rarr;
        </Link>
        <Link
          href="/docs/verification-matrix"
          className="rounded-xl border border-white/10 bg-white/5 px-4 py-2.5 font-mono text-xs font-bold text-white/70 hover:bg-white/10 hover:text-white transition"
        >
          Verification Matrix &rarr;
        </Link>
      </div>
    </div>
  );
}
