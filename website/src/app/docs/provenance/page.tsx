import Link from "next/link";
import { APP_INFO } from "@/lib/version";

export default function ProvenancePage() {
  return (
    <div>
      <div className="mb-12">
        <p className="mb-4 text-[10px] font-black uppercase tracking-[0.5em] text-sky-400">Reference</p>
        <h1 className="mb-4 text-4xl font-black tracking-tight text-white">Provenance</h1>
        <p className="text-lg text-white/50">
          RTQ&apos;s design history, original implementation, and audit trail.
        </p>
      </div>

      <h2 className="mb-4 text-2xl font-black text-white">Origin</h2>
      <p className="mb-4 text-sm text-white/50 leading-relaxed">
        RTQ was originally implemented as part of the Aartiq browser&apos;s security
        infrastructure. The capability-security pipeline was designed to protect
        AI-assisted browser operations with explicit authorization boundaries.
      </p>
      <p className="mb-8 text-sm text-white/50 leading-relaxed">
        It was extracted into a standalone, dependency-free runtime to make
        capability-security accessible to any application — not just browsers.
      </p>

      <h2 className="mb-4 text-2xl font-black text-white">Design Inputs</h2>
      <div className="mb-8 space-y-3">
        {[
          "Capability-based security (Object-capability model)",
          "Fail-closed design (missing rule = denial)",
          "HMAC-SHA256 ticket signing (RFC 2104)",
          "Platform-native sandboxing (Seatbelt, bubblewrap, AppContainer)",
          "Default-deny policy engine (declarative rules)",
          "Structured audit with secret redaction",
          "Zero npm dependencies in security-critical packages",
        ].map((item, i) => (
          <div key={i} className="flex items-center gap-3 rounded-xl border border-white/5 bg-white/[0.02] p-3 text-sm text-white/60">
            <span className="text-sky-400">•</span> {item}
          </div>
        ))}
      </div>

      <h2 className="mb-4 text-2xl font-black text-white">Repository</h2>
      <div className="mb-8 rounded-2xl border border-white/5 bg-white/[0.02] p-6">
        <div className="space-y-3 text-sm">
          <div className="flex justify-between"><span className="text-white/40">Repository</span><a href={APP_INFO.repo} target="_blank" className="text-sky-400 hover:underline">{APP_INFO.repo}</a></div>
          <div className="flex justify-between"><span className="text-white/40">License</span><span className="text-white/60">Apache-2.0</span></div>
          <div className="flex justify-between"><span className="text-white/40">Version</span><span className="text-white/60">v{APP_INFO.version}</span></div>
          <div className="flex justify-between"><span className="text-white/40">Author</span><span className="text-white/60">{APP_INFO.author}</span></div>
        </div>
      </div>

      <h2 className="mb-4 text-2xl font-black text-white">Audit Trail</h2>
      <p className="mb-4 text-sm text-white/50 leading-relaxed">
        Every security claim in this documentation links to its source file and
        test. The verification matrix page provides full traceability from claim
        to code.
      </p>

      <div className="mt-12 rounded-2xl border border-white/5 bg-white/[0.02] p-6">
        <p className="mb-4 text-xs font-black uppercase tracking-wider text-white/30">Back</p>
        <Link href="/docs/overview" className="rounded-xl border border-sky-500/20 bg-sky-500/5 px-4 py-2 text-xs font-bold text-sky-400 transition hover:bg-sky-500/20">
          Overview →
        </Link>
      </div>
    </div>
  );
}
