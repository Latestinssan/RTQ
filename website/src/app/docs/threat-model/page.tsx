import Link from "next/link";

export default function ThreatModelPage() {
  return (
    <div>
      <div className="mb-12">
        <p className="mb-4 text-[10px] font-black uppercase tracking-[0.5em] text-sky-400">Security</p>
        <h1 className="mb-4 text-4xl font-black tracking-tight text-white">Threat Model</h1>
        <p className="text-lg text-white/50">
          RTQ&apos;s threat model defines trust boundaries, known threats, and the
          mitigations applied at each layer. Every claim links to source code or
          test evidence.
        </p>
      </div>

      <h2 className="mb-4 text-2xl font-black text-white">Trust Boundaries</h2>
      <div className="mb-8 space-y-3">
        {[
          "RTQ runtime process — trusted",
          "Capability registry — trusted (read-only after init)",
          "Policy engine — trusted (fail-closed)",
          "Ticket signing key — trusted (never leaves process)",
          "OS sandbox boundary — trusted (kernel-enforced)",
          "Caller / host process — untrusted",
          "External inputs — untrusted",
        ].map((item, i) => (
          <div key={i} className="flex items-center gap-3 rounded-xl border border-white/5 bg-white/[0.02] p-3 text-sm">
            <span className={i < 5 ? "text-emerald-400" : "text-amber-400"}>{i < 5 ? "✓" : "⚠"}</span>
            <span className="text-white/60">{item}</span>
          </div>
        ))}
      </div>

      <h2 className="mb-4 text-2xl font-black text-white">Threats &amp; Mitigations</h2>
      <div className="mb-8 space-y-4">
        {[
          { threat: "Capability spoofing", desc: "Registering a capability that mimics a system operation.", mitigation: "Registry is append-only after init. Name collisions rejected at registration time.", source: "packages/core/src/registry.ts" },
          { threat: "Ticket replay", desc: "Reusing a valid ticket for a different execution.", mitigation: "Single-use enforcement. Ticket store marks consumed tickets; replay returns 409 Conflict.", source: "packages/core/src/ticket-store.ts" },
          { threat: "Risk manipulation", desc: "Caller claims a lower risk to bypass approval.", mitigation: "Authoritative risk engine ignores caller claims. Risk computed from capability metadata only.", source: "packages/risk/src/engine.ts" },
          { threat: "Policy bypass", desc: "Executing a capability without a matching allow rule.", mitigation: "Default-deny. Missing rule = denial. No fallback path.", source: "packages/policy/src/engine.ts" },
          { threat: "Sandbox escape", desc: "Executing outside OS sandbox constraints.", mitigation: "No sandbox = no execution. Platform-specific enforcement (Seatbelt/bwrap/AppContainer).", source: "packages/sandbox/src/" },
          { threat: "Audit tampering", desc: "Modifying audit logs to hide execution.", mitigation: "Structured events with HMAC integrity. Secrets redacted before write.", source: "packages/audit/src/emitter.ts" },
        ].map((item, i) => (
          <div key={i} className="rounded-xl border border-white/5 bg-white/[0.02] p-5">
            <h3 className="mb-2 text-sm font-bold text-rose-400">{item.threat}</h3>
            <p className="mb-2 text-sm text-white/40">{item.desc}</p>
            <p className="mb-2 text-sm text-emerald-400">{item.mitigation}</p>
            <code className="text-[10px] text-white/30">Source: {item.source}</code>
          </div>
        ))}
      </div>

      <h2 className="mb-4 text-2xl font-black text-white">Honest Limitations</h2>
      <ul className="mb-8 space-y-3 text-sm text-white/50">
        <li className="flex gap-3"><span className="text-amber-400">•</span> RTQ cannot prevent a compromised OS kernel from bypassing sandbox enforcement.</li>
        <li className="flex gap-3"><span className="text-amber-400">•</span> RTQ cannot guarantee that a human approver fully understands the operation they approve.</li>
        <li className="flex gap-3"><span className="text-amber-400">•</span> RTQ does not protect against side-channel attacks (timing, cache, etc.).</li>
        <li className="flex gap-3"><span className="text-amber-400">•</span> RTQ cannot enforce capability restrictions on code that runs outside the RTQ runtime.</li>
      </ul>

      <div className="mt-12 rounded-2xl border border-white/5 bg-white/[0.02] p-6">
        <p className="mb-4 text-xs font-black uppercase tracking-wider text-white/30">Next</p>
        <div className="flex flex-wrap gap-3">
          <Link href="/docs/verification-matrix" className="rounded-xl border border-sky-500/20 bg-sky-500/5 px-4 py-2 text-xs font-bold text-sky-400 transition hover:bg-sky-500/20">
            Verification Matrix →
          </Link>
          <Link href="/docs/verification-traceability" className="rounded-xl border border-white/10 bg-white/5 px-4 py-2 text-xs font-bold text-white/60 transition hover:bg-white/10">
            Traceability →
          </Link>
        </div>
      </div>
    </div>
  );
}
