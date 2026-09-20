import Link from "next/link";

export default function TestingStrategyPage() {
  return (
    <div>
      <div className="mb-12">
        <p className="mb-4 text-[10px] font-black uppercase tracking-[0.5em] text-sky-400">Reference</p>
        <h1 className="mb-4 text-4xl font-black tracking-tight text-white">Testing Strategy</h1>
        <p className="text-lg text-white/50">
          RTQ&apos;s test suite verifies every security invariant across all
          supported platforms. Tests are labeled, gated, and honest about what
          they cover.
        </p>
      </div>

      <h2 className="mb-4 text-2xl font-black text-white">Test Labels</h2>
      <div className="mb-8 grid gap-3 md:grid-cols-2">
        {[
          { label: "unit", desc: "Isolated function tests. No I/O, no network, no filesystem." },
          { label: "integration", desc: "Tests that exercise multiple packages together." },
          { label: "platform", desc: "Tests requiring a specific OS sandbox (macOS/Linux/Windows)." },
          { label: "security", desc: "Tests that verify security invariants (INV-01 through INV-12)." },
          { label: "approval", desc: "Tests for ticket signing, QR flow, and mobile pairing." },
          { label: "e2e", desc: "End-to-end pipeline tests (register → risk → policy → approve → execute)." },
        ].map((item) => (
          <div key={item.label} className="rounded-xl border border-white/5 bg-white/[0.02] p-4">
            <code className="text-xs font-bold text-sky-400">{item.label}</code>
            <p className="mt-1 text-xs text-white/40">{item.desc}</p>
          </div>
        ))}
      </div>

      <h2 className="mb-4 text-2xl font-black text-white">CI Pipeline</h2>
      <div className="mb-8 rounded-2xl border border-white/5 bg-white/[0.02] p-6 font-mono text-xs leading-relaxed text-white/50">
        <span className="text-white/30">.github/workflows/ci.yml</span><br /><br />
        <span className="text-sky-400">jobs:</span><br />
        &nbsp;&nbsp;core:<br />
        &nbsp;&nbsp;&nbsp;&nbsp;runs-on: ubuntu-latest<br />
        &nbsp;&nbsp;&nbsp;&nbsp;steps: [checkout, setup-node, npm ci, npm test]<br /><br />
        &nbsp;&nbsp;sandbox-macos:<br />
        &nbsp;&nbsp;&nbsp;&nbsp;runs-on: macos-latest<br />
        &nbsp;&nbsp;&nbsp;&nbsp;steps: [checkout, setup-node, npm ci, npm test -- --label platform=macos]<br /><br />
        &nbsp;&nbsp;sandbox-linux:<br />
        &nbsp;&nbsp;&nbsp;&nbsp;runs-on: ubuntu-latest<br />
        &nbsp;&nbsp;&nbsp;&nbsp;steps: [checkout, setup-node, npm ci, npm test -- --label platform=linux]<br /><br />
        &nbsp;&nbsp;sandbox-windows:<br />
        &nbsp;&nbsp;&nbsp;&nbsp;runs-on: windows-latest<br />
        &nbsp;&nbsp;&nbsp;&nbsp;steps: [checkout, setup-node, npm ci, npm test -- --label platform=windows]
      </div>

      <h2 className="mb-4 text-2xl font-black text-white">Honest Status</h2>
      <div className="mb-8 rounded-2xl border border-amber-500/20 bg-amber-500/[0.03] p-6">
        <p className="mb-3 text-sm text-white/50">
          <strong className="text-amber-400">Current CI run:</strong> 158+ passing / 40 environment-skipped / 0 failing.
        </p>
        <ul className="space-y-2 text-sm text-white/40">
          <li>• Platform-specific tests that cannot run on the CI host are counted as <strong className="text-white/60">skipped</strong>, never as passing.</li>
          <li>• If a test is skipped, it is documented and visible in CI output.</li>
          <li>• No test is marked as passing unless it actually executed and verified the invariant.</li>
        </ul>
      </div>

      <h2 className="mb-4 text-2xl font-black text-white">Running Tests Locally</h2>
      <div className="mb-8 rounded-2xl border border-white/5 bg-white/[0.02] p-6 font-mono text-xs leading-relaxed text-white/50">
        <span className="text-white/30"># Run all tests</span><br />
        npm test<br /><br />
        <span className="text-white/30"># Run only security invariants</span><br />
        npm test -- --label security<br /><br />
        <span className="text-white/30"># Run platform-specific tests</span><br />
        npm test -- --label platform=macos<br /><br />
        <span className="text-white/30"># Run with verbose output</span><br />
        npm test -- --verbose
      </div>

      <div className="mt-12 rounded-2xl border border-white/5 bg-white/[0.02] p-6">
        <p className="mb-4 text-xs font-black uppercase tracking-wider text-white/30">Next</p>
        <div className="flex flex-wrap gap-3">
          <Link href="/docs/provenance" className="rounded-xl border border-sky-500/20 bg-sky-500/5 px-4 py-2 text-xs font-bold text-sky-400 transition hover:bg-sky-500/20">
            Provenance →
          </Link>
          <Link href="/docs/overview" className="rounded-xl border border-white/10 bg-white/5 px-4 py-2 text-xs font-bold text-white/60 transition hover:bg-white/10">
            Back to Overview →
          </Link>
        </div>
      </div>
    </div>
  );
}
