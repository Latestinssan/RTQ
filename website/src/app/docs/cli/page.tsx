import Link from "next/link";

export default function CLIPage() {
  return (
    <div>
      <div className="mb-12">
        <p className="mb-4 text-[10px] font-black uppercase tracking-[0.5em] text-sky-400">Tooling</p>
        <h1 className="mb-4 text-4xl font-black tracking-tight text-white">CLI Reference</h1>
        <p className="text-lg text-white/50">
          The <code className="text-sm bg-white/5 px-2 py-1 rounded text-sky-400">rtq</code> CLI provides
          commands for inspecting capabilities, testing policies, verifying
          sandbox enforcement, and running diagnostics.
        </p>
      </div>

      <h2 className="mb-4 text-2xl font-black text-white">Commands</h2>
      <div className="mb-8 space-y-4">
        {[
          { cmd: "rtq capabilities", desc: "List all registered capabilities with their risk levels and schemas.", example: "rtq capabilities\nrtq capabilities --json" },
          { cmd: "rtq policy check", desc: "Evaluate policy rules against a set of capabilities. Reports any gaps or conflicts.", example: "rtq policy check --config ./policy.yaml" },
          { cmd: "rtq sandbox test", desc: "Test sandbox enforcement on the current platform. Verifies filesystem, network, and process restrictions.", example: "rtq sandbox test --verbose" },
          { cmd: "rtq verify", desc: "Run all 12 security invariants. Reports pass/fail/skip for each.", example: "rtq verify\nrtq verify --invariant INV-01" },
          { cmd: "rtq diagnostics", desc: "System diagnostics: platform, sandbox availability, key status, package versions.", example: "rtq diagnostics" },
          { cmd: "rtq ticket inspect", desc: "Inspect a ticket's contents (signature, expiry, operation, single-use status).", example: "rtq ticket inspect <ticket-id>" },
        ].map((item) => (
          <div key={item.cmd} className="rounded-xl border border-white/5 bg-white/[0.02] p-5">
            <div className="mb-2 flex items-center gap-3">
              <code className="text-sm font-bold text-sky-400">{item.cmd}</code>
            </div>
            <p className="mb-3 text-sm text-white/40">{item.desc}</p>
            <div className="rounded-lg bg-black/30 p-3 font-mono text-xs text-white/50">
              <pre>{item.example}</pre>
            </div>
          </div>
        ))}
      </div>

      <h2 className="mb-4 text-2xl font-black text-white">Global Options</h2>
      <div className="mb-8 rounded-2xl border border-white/5 bg-white/[0.02] p-6">
        <table className="w-full text-left text-sm">
          <thead>
            <tr className="border-b border-white/10">
              <th className="pb-3 text-[10px] font-black uppercase tracking-wider text-white/40">Flag</th>
              <th className="pb-3 text-[10px] font-black uppercase tracking-wider text-white/40">Description</th>
            </tr>
          </thead>
          <tbody className="text-white/60">
            <tr className="border-b border-white/5"><td className="py-2 font-mono text-xs text-sky-400">--json</td><td className="py-2">Output as JSON</td></tr>
            <tr className="border-b border-white/5"><td className="py-2 font-mono text-xs text-sky-400">--verbose</td><td className="py-2">Detailed output</td></tr>
            <tr className="border-b border-white/5"><td className="py-2 font-mono text-xs text-sky-400">--config &lt;path&gt;</td><td className="py-2">Path to config file</td></tr>
            <tr><td className="py-2 font-mono text-xs text-sky-400">--help</td><td className="py-2">Show help</td></tr>
          </tbody>
        </table>
      </div>

      <div className="mt-12 rounded-2xl border border-white/5 bg-white/[0.02] p-6">
        <p className="mb-4 text-xs font-black uppercase tracking-wider text-white/30">Next</p>
        <div className="flex flex-wrap gap-3">
          <Link href="/docs/testing-strategy" className="rounded-xl border border-sky-500/20 bg-sky-500/5 px-4 py-2 text-xs font-bold text-sky-400 transition hover:bg-sky-500/20">
            Testing Strategy →
          </Link>
          <Link href="/docs/provenance" className="rounded-xl border border-white/10 bg-white/5 px-4 py-2 text-xs font-bold text-white/60 transition hover:bg-white/10">
            Provenance →
          </Link>
        </div>
      </div>
    </div>
  );
}
