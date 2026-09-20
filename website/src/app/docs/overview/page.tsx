import Link from "next/link";
import { APP_INFO } from "@/lib/version";

export default function OverviewPage() {
  return (
    <div>
      <div className="mb-12">
        <p className="mb-4 text-[10px] font-black uppercase tracking-[0.5em] text-sky-400">Getting Started</p>
        <h1 className="mb-4 text-4xl font-black tracking-tight text-white">RTQ Overview</h1>
        <p className="text-lg text-white/50">
          RTQ is a dependency-free, risk-adaptive capability-security runtime.
          Every operation is an explicitly registered capability; every
          authorization is a short-lived, single-use, cryptographically-signed
          ticket.
        </p>
      </div>

      <h2 className="mb-4 text-2xl font-black text-white">Core Pipeline</h2>
      <div className="mb-8 rounded-2xl border border-white/5 bg-white/[0.02] p-6 font-mono text-xs leading-relaxed text-white/50">
        <span className="text-sky-400">Command</span> → Capability (registered) → Risk (authoritative) → Policy (default-deny)
        <br />&nbsp;&nbsp;&nbsp;→ Clarification → Approval (human/device) → Ticket (signed, single-use)
        <br />&nbsp;&nbsp;&nbsp;→ Execution (OS-sandboxed) → Audit (redacted)
      </div>

      <h2 className="mb-4 text-2xl font-black text-white">Packages</h2>
      <div className="mb-8 grid gap-3 md:grid-cols-2">
        {[
          ["@rtq/core", "Security-model types, registry, ticket store"],
          ["@rtq/risk", "Authoritative risk engine"],
          ["@rtq/policy", "Default-deny declarative rules"],
          ["@rtq/clarification", "Structured questions for missing params"],
          ["@rtq/approval", "Strategies + QR/mobile challenge-response"],
          ["@rtq/sandbox", "macOS Seatbelt, Linux bubblewrap, Windows AppContainer"],
          ["@rtq/audit", "Structured, redacted events"],
          ["@rtq/security", "Pipeline façade (createRTQ)"],
          ["@rtq/crypto", "Canonical JSON, HMAC-SHA256, constant-time compare"],
          ["@rtq/cli", "Actionable operator tooling"],
        ].map(([pkg, desc]) => (
          <div key={pkg} className="rounded-xl border border-white/5 bg-white/[0.02] p-4">
            <code className="text-xs font-bold text-sky-400">{pkg}</code>
            <p className="mt-1 text-xs text-white/40">{desc}</p>
          </div>
        ))}
      </div>

      <h2 className="mb-4 text-2xl font-black text-white">Quick Start</h2>
      <div className="mb-8 rounded-2xl border border-white/5 bg-white/[0.02] p-6 font-mono text-xs leading-relaxed text-white/50">
        <span className="text-white/30"># Install</span><br />
        npm install @rtq/security @rtq/core @rtq/risk @rtq/policy<br /><br />
        <span className="text-white/30"># Register a capability</span><br />
        <span className="text-sky-400">import</span> {"{ createRTQ }"} <span className="text-sky-400">from</span> <span className="text-emerald-400">&quot;@rtq/security&quot;</span>;<br /><br />
        const rtq = createRTQ({"{"} signingKey: process.env.RTQ_SIGNING_KEY! {"}"});<br /><br />
        rtq.registerCapability({"{"}<br />
        &nbsp;&nbsp;name: &quot;files.read&quot;,<br />
        &nbsp;&nbsp;version: 1,<br />
        &nbsp;&nbsp;description: &quot;Read a file inside the workspace&quot;,<br />
        &nbsp;&nbsp;inputSchema: {"{"} type: &quot;object&quot;, properties: {"{"} path: {"{"} type: &quot;string&quot; {"}"} {"}"}, required: [&quot;path&quot;] {"}"},<br />
        &nbsp;&nbsp;risk: {"{"} base: &quot;low&quot; {"}"},<br />
        &nbsp;&nbsp;execute: <span className="text-sky-400">async</span> (ctx, input) =&gt; {"{"} ok: <span className="text-sky-400">true</span>, data: {"{"} input {"}"} {"}"},<br />
        {"}"});
      </div>

      <h2 className="mb-4 text-2xl font-black text-white">Design Principles</h2>
      <ul className="mb-8 space-y-3 text-sm text-white/50">
        <li className="flex gap-3"><span className="text-sky-400">•</span> <strong className="text-white">Dependency-free:</strong> Zero npm dependencies in security-critical packages.</li>
        <li className="flex gap-3"><span className="text-sky-400">•</span> <strong className="text-white">Fail-closed:</strong> Missing rule = denial. No silent fallback to allow.</li>
        <li className="flex gap-3"><span className="text-sky-400">•</span> <strong className="text-white">Authoritative risk:</strong> Caller claims can never lower risk. RTQ computes it.</li>
        <li className="flex gap-3"><span className="text-sky-400">•</span> <strong className="text-white">Single-use tickets:</strong> HMAC-SHA256, bound to exact operation. Replay rejected.</li>
        <li className="flex gap-3"><span className="text-sky-400">•</span> <strong className="text-white">OS sandboxing:</strong> Every execution runs in a platform-native sandbox.</li>
      </ul>

      <div className="mt-12 rounded-2xl border border-white/5 bg-white/[0.02] p-6">
        <p className="mb-4 text-xs font-black uppercase tracking-wider text-white/30">Next Steps</p>
        <div className="flex flex-wrap gap-3">
          <Link href="/docs/security-overview" className="rounded-xl border border-sky-500/20 bg-sky-500/5 px-4 py-2 text-xs font-bold text-sky-400 transition hover:bg-sky-500/20">
            Security Overview →
          </Link>
          <Link href="/docs/threat-model" className="rounded-xl border border-white/10 bg-white/5 px-4 py-2 text-xs font-bold text-white/60 transition hover:bg-white/10">
            Threat Model →
          </Link>
          <Link href="/docs/verification-matrix" className="rounded-xl border border-white/10 bg-white/5 px-4 py-2 text-xs font-bold text-white/60 transition hover:bg-white/10">
            Verification Matrix →
          </Link>
        </div>
      </div>
    </div>
  );
}
