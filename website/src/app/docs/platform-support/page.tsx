import Link from "next/link";

export default function PlatformSupportPage() {
  return (
    <div>
      <div className="mb-12">
        <p className="mb-4 text-[10px] font-black uppercase tracking-[0.5em] text-sky-400">Reference</p>
        <h1 className="mb-4 text-4xl font-black tracking-tight text-white">Platform Support</h1>
        <p className="text-lg text-white/50">
          RTQ uses native OS sandboxing on each platform. No sandbox = no
          execution.
        </p>
      </div>

      <div className="mb-8 grid gap-6 lg:grid-cols-3">
        {[
          {
            platform: "macOS",
            sandbox: "Seatbelt (sandbox-exec)",
            details: "Filesystem, network, and process restrictions via Seatbelt profiles. Workspace-scoped access only.",
            testSuite: "104 passing",
            source: "packages/sandbox/src/seatbelt.ts",
          },
          {
            platform: "Linux",
            sandbox: "bubblewrap (bwrap)",
            details: "Namespace-based isolation. Read-only root, private tmp, workspace-only access via bind mount.",
            testSuite: "57 passing",
            source: "packages/sandbox/src/bubblewrap.ts",
          },
          {
            platform: "Windows",
            sandbox: "AppContainer + Job Object",
            details: "Process isolation via AppContainer. Filesystem restrictions via Job Object. Limited capabilities.",
            testSuite: "61 passing",
            source: "packages/sandbox/src/appcontainer.ts",
          },
        ].map((p) => (
          <div key={p.platform} className="rounded-2xl border border-white/5 bg-white/[0.02] p-6">
            <h3 className="mb-2 text-lg font-black text-white">{p.platform}</h3>
            <p className="mb-3 text-sm font-bold text-sky-400">{p.sandbox}</p>
            <p className="mb-4 text-sm text-white/40 leading-relaxed">{p.details}</p>
            <div className="flex items-center justify-between border-t border-white/5 pt-3">
              <span className="rounded-full bg-emerald-500/10 px-2 py-0.5 text-[10px] font-bold text-emerald-400">{p.testSuite}</span>
              <code className="text-[10px] text-white/30">{p.source}</code>
            </div>
          </div>
        ))}
      </div>

      <h2 className="mb-4 text-2xl font-black text-white">Sandbox Policy</h2>
      <div className="mb-8 rounded-2xl border border-white/5 bg-white/[0.02] p-6 font-mono text-xs leading-relaxed text-white/50">
        <span className="text-white/30">// Default sandbox policy (macOS Seatbelt example)</span><br />
        (deny default)<br />
        (version 1)<br />
        (allow process-exec)<br />
        (allow file-read* (subpath &quot;{`{workspace}`}&quot;))<br />
        (deny file-write* (subpath &quot;/&quot;))<br />
        (deny network*)
      </div>

      <h2 className="mb-4 text-2xl font-black text-white">Fallback Behavior</h2>
      <ul className="mb-8 space-y-3 text-sm text-white/50">
        <li className="flex gap-3"><span className="text-sky-400">•</span> <strong className="text-white">macOS:</strong> Seatbelt available on all modern macOS versions.</li>
        <li className="flex gap-3"><span className="text-sky-400">•</span> <strong className="text-white">Linux:</strong> bubblewrap requires <code className="text-xs bg-white/5 px-1 py-0.5 rounded">bwrap</code> binary. Install via package manager.</li>
        <li className="flex gap-3"><span className="text-sky-400">•</span> <strong className="text-white">Windows:</strong> AppContainer requires Windows 10+ and appropriate tokens.</li>
        <li className="flex gap-3"><span className="text-amber-400">•</span> <strong className="text-white">No sandbox available:</strong> Execution is blocked. RTQ does not fall back to unsandboxed execution.</li>
      </ul>

      <div className="mt-12 rounded-2xl border border-white/5 bg-white/[0.02] p-6">
        <p className="mb-4 text-xs font-black uppercase tracking-wider text-white/30">Next</p>
        <div className="flex flex-wrap gap-3">
          <Link href="/docs/aartiq-integration" className="rounded-xl border border-sky-500/20 bg-sky-500/5 px-4 py-2 text-xs font-bold text-sky-400 transition hover:bg-sky-500/20">
            Aartiq Integration →
          </Link>
          <Link href="/docs/mobile-approval" className="rounded-xl border border-white/10 bg-white/5 px-4 py-2 text-xs font-bold text-white/60 transition hover:bg-white/10">
            Mobile Approval →
          </Link>
        </div>
      </div>
    </div>
  );
}
