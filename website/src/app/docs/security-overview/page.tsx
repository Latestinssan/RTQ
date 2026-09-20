import Link from "next/link";

export default function SecurityOverviewPage() {
  return (
    <div>
      <div className="mb-12">
        <p className="mb-4 text-[10px] font-black uppercase tracking-[0.5em] text-sky-400">Security</p>
        <h1 className="mb-4 text-4xl font-black tracking-tight text-white">Security Overview</h1>
        <p className="text-lg text-white/50">
          RTQ&apos;s security model is built on three layers: explicit capability
          registration, authoritative risk computation, and fail-closed policy
          enforcement.
        </p>
      </div>

      <h2 className="mb-4 text-2xl font-black text-white">Pipeline Layers</h2>
      <div className="mb-8 space-y-4">
        {[
          { name: "1. Capability Registry", desc: "Every operation must be explicitly registered before it can execute. Unregistered operations are rejected.", color: "sky" },
          { name: "2. Risk Engine", desc: "RTQ computes risk authoritatively. Caller claims can never lower the risk score — only RTQ&apos;s own assessment applies.", color: "emerald" },
          { name: "3. Policy Rules", desc: "Default-deny. A missing rule is a denial, never an allow. No silent fallback.", color: "amber" },
          { name: "4. Clarification", desc: "When a capability requires parameters not provided, RTQ asks structured questions instead of guessing.", color: "purple" },
          { name: "5. Approval", desc: "Human or device approval via short-lived, single-use, HMAC-SHA256-signed tickets.", color: "cyan" },
          { name: "6. Execution", desc: "Every execution runs inside an OS-native sandbox (Seatbelt, bubblewrap, or AppContainer).", color: "rose" },
          { name: "7. Audit", desc: "Structured, redacted audit events. Secrets are scrubbed before logging.", color: "blue" },
        ].map((layer) => (
          <div key={layer.name} className="rounded-xl border border-white/5 bg-white/[0.02] p-5">
            <h3 className={`mb-2 text-sm font-bold text-${layer.color}-400`}>{layer.name}</h3>
            <p className="text-sm text-white/40 leading-relaxed">{layer.desc}</p>
          </div>
        ))}
      </div>

      <h2 className="mb-4 text-2xl font-black text-white">Core Principles</h2>
      <ul className="mb-8 space-y-3 text-sm text-white/50">
        <li className="flex gap-3"><span className="text-sky-400">•</span> <strong className="text-white">Explicit Surface:</strong> Only registered capabilities can run. Everything else is denied.</li>
        <li className="flex gap-3"><span className="text-sky-400">•</span> <strong className="text-white">Default Deny:</strong> A missing rule is a denial, never an allow.</li>
        <li className="flex gap-3"><span className="text-sky-400">•</span> <strong className="text-white">Authoritative Risk:</strong> Caller claims can never lower risk. RTQ computes risk itself.</li>
        <li className="flex gap-3"><span className="text-sky-400">•</span> <strong className="text-white">Single-Use Tickets:</strong> HMAC-SHA256, bound to exact operation; replay and tamper are rejected.</li>
        <li className="flex gap-3"><span className="text-sky-400">•</span> <strong className="text-white">Fail-Closed Sandbox:</strong> No sandbox → no execution. The escape hatch is explicit and reported.</li>
        <li className="flex gap-3"><span className="text-sky-400">•</span> <strong className="text-white">Redacted Audit:</strong> Secrets are scrubbed before logging.</li>
      </ul>

      <h2 className="mb-4 text-2xl font-black text-white">Quick Example</h2>
      <div className="mb-8 rounded-2xl border border-white/5 bg-white/[0.02] p-6 font-mono text-xs leading-relaxed text-white/50">
        <span className="text-white/30">// Register a high-risk capability</span><br />
        rtq.registerCapability({"{"}<br />
        &nbsp;&nbsp;name: &quot;files.delete&quot;,<br />
        &nbsp;&nbsp;version: 1,<br />
        &nbsp;&nbsp;inputSchema: {"{"} type: &quot;object&quot;, properties: {"{"} path: {"{"} type: &quot;string&quot; {"}"} {"}"}, required: [&quot;path&quot;] {"}"},<br />
        &nbsp;&nbsp;risk: {"{"} base: &quot;high&quot;, factors: [&quot;irreversible&quot;] {"}"},<br />
        &nbsp;&nbsp;execute: <span className="text-sky-400">async</span> (ctx, input) =&gt; {"{"}<br />
        &nbsp;&nbsp;&nbsp;&nbsp;<span className="text-white/30">// Only runs if ticket is valid + sandbox is available</span><br />
        &nbsp;&nbsp;&nbsp;&nbsp;await fs.unlink(input.path);<br />
        &nbsp;&nbsp;&nbsp;&nbsp;return {"{"} ok: <span className="text-sky-400">true</span> {"}"};<br />
        &nbsp;&nbsp;{"}"},<br />
        {"}"});
      </div>

      <div className="mt-12 rounded-2xl border border-white/5 bg-white/[0.02] p-6">
        <p className="mb-4 text-xs font-black uppercase tracking-wider text-white/30">Next</p>
        <div className="flex flex-wrap gap-3">
          <Link href="/docs/threat-model" className="rounded-xl border border-sky-500/20 bg-sky-500/5 px-4 py-2 text-xs font-bold text-sky-400 transition hover:bg-sky-500/20">
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
