import Link from "next/link";

export default function VerificationMatrixPage() {
  return (
    <div>
      <div className="mb-12">
        <p className="mb-4 text-[10px] font-black uppercase tracking-[0.5em] text-sky-400">Security</p>
        <h1 className="mb-4 text-4xl font-black tracking-tight text-white">Verification Matrix</h1>
        <p className="text-lg text-white/50">
          Twelve automated invariants verify RTQ&apos;s security properties in CI.
          Every invariant is a test that must pass before any release ships.
        </p>
      </div>

      <h2 className="mb-4 text-2xl font-black text-white">Invariant Matrix</h2>
      <div className="mb-8 overflow-x-auto">
        <table className="w-full text-left text-sm">
          <thead>
            <tr className="border-b border-white/10">
              <th className="pb-3 text-[10px] font-black uppercase tracking-wider text-white/40">#</th>
              <th className="pb-3 text-[10px] font-black uppercase tracking-wider text-white/40">Invariant</th>
              <th className="pb-3 text-[10px] font-black uppercase tracking-wider text-white/40">Package</th>
              <th className="pb-3 text-[10px] font-black uppercase tracking-wider text-white/40">Status</th>
            </tr>
          </thead>
          <tbody className="text-white/60">
            {[
              ["INV-01", "Unregistered capability → rejection", "@rtq/core", "✓ Enforced"],
              ["INV-02", "Replay of consumed ticket → 409 Conflict", "@rtq/core", "✓ Enforced"],
              ["INV-03", "Caller risk-lowering attempt → ignored", "@rtq/risk", "✓ Enforced"],
              ["INV-04", "Missing policy rule → denial (default-deny)", "@rtq/policy", "✓ Enforced"],
              ["INV-05", "Expired ticket → rejection", "@rtq/core", "✓ Enforced"],
              ["INV-06", "Tampered ticket signature → rejection", "@rtq/crypto", "✓ Enforced"],
              ["INV-07", "Missing sandbox → execution blocked", "@rtq/sandbox", "✓ Enforced"],
              ["INV-08", "Audit event contains no raw secrets", "@rtq/audit", "✓ Enforced"],
              ["INV-09", "Clarification loop terminates or times out", "@rtq/clarification", "✓ Enforced"],
              ["INV-10", "Policy engine rejects unknown capability", "@rtq/policy", "✓ Enforced"],
              ["INV-11", "Ticket is single-use (second use rejected)", "@rtq/core", "✓ Enforced"],
              ["INV-12", "Platform sandbox actually restricts filesystem", "@rtq/sandbox", "✓ Enforced"],
            ].map(([id, desc, pkg, status]) => (
              <tr key={id} className="border-b border-white/5">
                <td className="py-3 font-mono text-xs text-sky-400">{id}</td>
                <td className="py-3">{desc}</td>
                <td className="py-3 font-mono text-xs text-white/40">{pkg}</td>
                <td className="py-3"><span className="rounded-full bg-emerald-500/10 px-2 py-0.5 text-[10px] font-bold text-emerald-400">{status}</span></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <h2 className="mb-4 text-2xl font-black text-white">Test Suites</h2>
      <div className="mb-8 grid gap-3 md:grid-cols-2">
        {[
          { suite: "core", tests: "Registry, ticket store, replay, expiry", label: "158+ tests" },
          { suite: "risk", tests: "Risk computation, claim rejection, factors", label: "45+ tests" },
          { suite: "policy", tests: "Default-deny, rule matching, capability gating", label: "38+ tests" },
          { suite: "sandbox", tests: "Seatbelt, bubblewrap, AppContainer enforcement", label: "65+ tests" },
          { suite: "audit", tests: "Event emission, secret redaction, integrity", label: "28+ tests" },
          { suite: "approval", tests: "Ticket signing, QR flow, mobile pairing", label: "52+ tests" },
        ].map((s) => (
          <div key={s.suite} className="rounded-xl border border-white/5 bg-white/[0.02] p-4">
            <div className="mb-2 flex items-center justify-between">
              <code className="text-xs font-bold text-sky-400">@rtq/{s.suite}</code>
              <span className="text-[10px] text-white/30">{s.label}</span>
            </div>
            <p className="text-xs text-white/40">{s.tests}</p>
          </div>
        ))}
      </div>

      <h2 className="mb-4 text-2xl font-black text-white">Platform Gating</h2>
      <p className="mb-4 text-sm text-white/50">
        Platform-specific tests run only on their target OS. CI skips tests when
        the required platform is unavailable — counted as skipped, never as
        passing.
      </p>
      <div className="mb-8 rounded-2xl border border-white/5 bg-white/[0.02] p-6 font-mono text-xs leading-relaxed text-white/50">
        <span className="text-white/30"># CI matrix</span><br />
        jest.yml → 4 jobs:<br />
        &nbsp;&nbsp;• core (all platforms)<br />
        &nbsp;&nbsp;• sandbox-macos (Seatbelt)<br />
        &nbsp;&nbsp;• sandbox-linux (bubblewrap)<br />
        &nbsp;&nbsp;• sandbox-windows (AppContainer)
      </div>

      <div className="mt-12 rounded-2xl border border-white/5 bg-white/[0.02] p-6">
        <p className="mb-4 text-xs font-black uppercase tracking-wider text-white/30">Next</p>
        <div className="flex flex-wrap gap-3">
          <Link href="/docs/verification-traceability" className="rounded-xl border border-sky-500/20 bg-sky-500/5 px-4 py-2 text-xs font-bold text-sky-400 transition hover:bg-sky-500/20">
            Traceability →
          </Link>
          <Link href="/docs/platform-support" className="rounded-xl border border-white/10 bg-white/5 px-4 py-2 text-xs font-bold text-white/60 transition hover:bg-white/10">
            Platform Support →
          </Link>
        </div>
      </div>
    </div>
  );
}
