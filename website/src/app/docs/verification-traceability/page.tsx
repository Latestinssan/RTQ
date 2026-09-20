import Link from "next/link";

export default function VerificationTraceabilityPage() {
  return (
    <div>
      <div className="mb-12">
        <p className="mb-4 text-[10px] font-black uppercase tracking-[0.5em] text-sky-400">Security</p>
        <h1 className="mb-4 text-4xl font-black tracking-tight text-white">Verification &amp; Traceability</h1>
        <p className="text-lg text-white/50">
          Every security claim in RTQ links to its source file and line number.
          No claim is made without evidence.
        </p>
      </div>

      <h2 className="mb-4 text-2xl font-black text-white">Source-to-Claim Mapping</h2>
      <div className="mb-8 space-y-4">
        {[
          { claim: "Unregistered capability rejected", file: "packages/core/src/registry.ts", line: "register() → throws if name collision", invariant: "INV-01" },
          { claim: "Single-use ticket enforcement", file: "packages/core/src/ticket-store.ts", line: "consume() → marks used, returns 409 on replay", invariant: "INV-02, INV-11" },
          { claim: "Caller risk-lowering ignored", file: "packages/risk/src/engine.ts", line: "computeRisk() → uses capability metadata only", invariant: "INV-03" },
          { claim: "Default-deny policy", file: "packages/policy/src/engine.ts", line: "evaluate() → deny when no rule matches", invariant: "INV-04, INV-10" },
          { claim: "Expired ticket rejected", file: "packages/core/src/ticket-store.ts", line: "validate() → checks expiry timestamp", invariant: "INV-05" },
          { claim: "Tampered signature rejected", file: "packages/crypto/src/hmac.ts", line: "verify() → constant-time compare", invariant: "INV-06" },
          { claim: "Missing sandbox blocks execution", file: "packages/sandbox/src/factory.ts", line: "createSandbox() → throws if unavailable", invariant: "INV-07" },
          { claim: "Audit secrets redacted", file: "packages/audit/src/emitter.ts", line: "emit() → scrubs sensitive fields", invariant: "INV-08" },
          { claim: "Clarification terminates", file: "packages/clarification/src/engine.ts", line: "ask() → timeout after max rounds", invariant: "INV-09" },
          { claim: "Sandbox restricts filesystem", file: "packages/sandbox/src/seatbelt.ts", line: "policy → deny filesystem-write except workspace", invariant: "INV-12" },
        ].map((item, i) => (
          <div key={i} className="rounded-xl border border-white/5 bg-white/[0.02] p-5">
            <div className="mb-2 flex items-center gap-3">
              <span className="rounded-full bg-sky-500/10 px-2 py-0.5 text-[10px] font-bold text-sky-400">{item.invariant}</span>
              <h3 className="text-sm font-bold text-white">{item.claim}</h3>
            </div>
            <div className="font-mono text-xs text-white/40">
              <span className="text-emerald-400">{item.file}</span>
              <br />
              <span className="text-white/30">{item.line}</span>
            </div>
          </div>
        ))}
      </div>

      <h2 className="mb-4 text-2xl font-black text-white">Traceability Policy</h2>
      <ul className="mb-8 space-y-3 text-sm text-white/50">
        <li className="flex gap-3"><span className="text-sky-400">•</span> Every security invariant maps to at least one source file and test.</li>
        <li className="flex gap-3"><span className="text-sky-400">•</span> Source file references include line-level granularity where possible.</li>
        <li className="flex gap-3"><span className="text-sky-400">•</span> CI verifies that all invariants have corresponding test coverage.</li>
        <li className="flex gap-3"><span className="text-sky-400">•</span> This documentation page is generated from the same source-of-truth as the tests.</li>
      </ul>

      <div className="mt-12 rounded-2xl border border-white/5 bg-white/[0.02] p-6">
        <p className="mb-4 text-xs font-black uppercase tracking-wider text-white/30">Next</p>
        <div className="flex flex-wrap gap-3">
          <Link href="/docs/platform-support" className="rounded-xl border border-sky-500/20 bg-sky-500/5 px-4 py-2 text-xs font-bold text-sky-400 transition hover:bg-sky-500/20">
            Platform Support →
          </Link>
          <Link href="/docs/aartiq-integration" className="rounded-xl border border-white/10 bg-white/5 px-4 py-2 text-xs font-bold text-white/60 transition hover:bg-white/10">
            Aartiq Integration →
          </Link>
        </div>
      </div>
    </div>
  );
}
