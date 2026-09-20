import Link from "next/link";
import { APP_INFO } from "@/lib/version";
import { COMMIT_SHA } from "@/components/evidence/EvidenceBadge";
import { TestTube, Shield, BookOpen, ExternalLink, AlertTriangle } from "lucide-react";

export const metadata = {
  title: "RTQ Overview",
  description: "Introduction to RTQ pipeline, zero-npm-runtime-dependency packages, and evidence-backed security.",
};

export default function OverviewPage() {
  return (
    <div className="space-y-10">
      <div>
        <p className="mb-3 text-[10px] font-mono font-bold uppercase tracking-[0.5em] text-sky-400">
          Getting Started &bull; Overview
        </p>
        <h1 className="text-3xl font-black tracking-tight text-white md:text-5xl">
          RTQ Overview
        </h1>
        <p className="mt-4 text-base text-white/60 leading-relaxed">
          RTQ is an experimental (Alpha) capability-security runtime for autonomous agents and tools.
          Security-critical packages declare zero third-party npm runtime dependencies. Every operation
          requires an explicitly registered capability; authorizations are short-lived, single-use,
          cryptographically-signed tickets.
        </p>
      </div>

      {/* Alpha Status Banner */}
      <div className="rounded-xl border border-amber-500/20 bg-amber-500/5 p-4 text-xs text-amber-200/90 leading-relaxed flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-2.5">
          <AlertTriangle size={15} className="text-amber-400 shrink-0" />
          <span>
            <strong>Alpha Software:</strong> RTQ has not undergone an independent security audit. All
            claims link to automated tests pinned at commit <code className="text-white font-mono">{COMMIT_SHA}</code>.
          </span>
        </div>
        <Link
          href="/docs/evidence"
          className="font-mono font-bold text-sky-400 hover:text-sky-300 underline"
        >
          View Evidence &rarr;
        </Link>
      </div>

      <div>
        <h2 className="text-xl font-bold text-white mb-4">Core Pipeline</h2>
        <div className="rounded-2xl border border-white/5 bg-white/[0.02] p-5 font-mono text-xs leading-relaxed text-white/60">
          <span className="text-sky-400">Command</span> &rarr;{" "}
          <span className="text-white/80">Capability</span> (registered) &rarr;{" "}
          <span className="text-white/80">Risk</span> (authoritative) &rarr;{" "}
          <span className="text-white/80">Policy</span> (default-deny)
          <br />
          &nbsp;&nbsp;&nbsp;&rarr; <span className="text-white/80">Clarification</span> &rarr;{" "}
          <span className="text-white/80">Approval</span> (challenge-response) &rarr;{" "}
          <span className="text-white/80">Ticket</span> (signed, single-use)
          <br />
          &nbsp;&nbsp;&nbsp;&rarr; <span className="text-white/80">Execution</span> (OS-sandboxed) &rarr;{" "}
          <span className="text-white/80">Audit</span> (redacted)
        </div>
      </div>

      <div>
        <h2 className="text-xl font-bold text-white mb-4">Packages</h2>
        <div className="grid gap-3 md:grid-cols-2 text-xs">
          {[
            ["@rtq/core", "Security-model types, capability registry, atomic ticket store (0 npm deps)"],
            ["@rtq/risk", "Authoritative risk engine; ignores caller demotion attempts (0 npm deps)"],
            ["@rtq/policy", "Default-deny declarative rule evaluator (0 npm deps)"],
            ["@rtq/crypto", "RFC 8785 canonical JSON, HMAC-SHA256, constant-time compare (0 npm deps)"],
            ["@rtq/approval", "Verification strategies + QR/mobile challenge-response"],
            ["@rtq/sandbox", "macOS Seatbelt, Linux bubblewrap, Windows AppContainer wrappers"],
            ["@rtq/audit", "Structured, HMAC-integrity redacted event logging"],
            ["@rtq/clarification", "Structured questions for missing parameters with timeout"],
            ["@rtq/security", "Pipeline façade (createRTQ) unifying the security model"],
            ["@rtq/cli", "Operator tooling, verification suites, and sandbox test harnesses"],
          ].map(([pkg, desc]) => (
            <div key={pkg} className="rounded-xl border border-white/5 bg-white/[0.02] p-4">
              <code className="text-xs font-bold text-sky-400 font-mono">{pkg}</code>
              <p className="mt-1 text-white/50">{desc}</p>
            </div>
          ))}
        </div>
      </div>

      <div>
        <h2 className="text-xl font-bold text-white mb-4">Quick Start</h2>
        <div className="rounded-2xl border border-white/5 bg-white/[0.02] p-5 font-mono text-xs leading-relaxed text-white/60">
          <span className="text-white/30"># Install core security packages</span>
          <br />
          npm install @rtq/security @rtq/core @rtq/risk @rtq/policy
          <br />
          <br />
          <span className="text-white/30"># Register a capability</span>
          <br />
          <span className="text-sky-400">import</span> &#123; createRTQ &#125;{" "}
          <span className="text-sky-400">from</span>{" "}
          <span className="text-emerald-400">&quot;@rtq/security&quot;</span>;
          <br />
          <br />
          const rtq = createRTQ(&#123; signingKey: process.env.RTQ_SIGNING_KEY! &#125;);
          <br />
          <br />
          rtq.registerCapability(&#123;
          <br />
          &nbsp;&nbsp;name: &quot;files.read&quot;,
          <br />
          &nbsp;&nbsp;version: 1,
          <br />
          &nbsp;&nbsp;description: &quot;Read a file inside the workspace&quot;,
          <br />
          &nbsp;&nbsp;inputSchema: &#123; type: &quot;object&quot;, properties: &#123; path: &#123; type: &quot;string&quot; &#125; &#125;, required: [&quot;path&quot;] &#125;,
          <br />
          &nbsp;&nbsp;risk: &#123; base: &quot;low&quot; &#125;,
          <br />
          &nbsp;&nbsp;execute: <span className="text-sky-400">async</span> (ctx, input) =&gt; (&#123; ok: <span className="text-sky-400">true</span>, data: &#123; input &#125; &#125;),
          <br />
          &#125;);
        </div>
      </div>

      <div>
        <h2 className="text-xl font-bold text-white mb-4">Design Principles</h2>
        <ul className="space-y-3 text-xs text-white/60">
          <li className="flex gap-2.5">
            <span className="text-sky-400">&bull;</span>
            <span>
              <strong className="text-white">Zero npm runtime dependencies:</strong> Security-critical packages
              declare 0 external npm dependencies, minimizing supply-chain attack surface.
            </span>
          </li>
          <li className="flex gap-2.5">
            <span className="text-sky-400">&bull;</span>
            <span>
              <strong className="text-white">Fail-closed:</strong> Missing policy rules evaluate to denial (INV-03).
              Missing sandbox backends halt execution without silent fallback.
            </span>
          </li>
          <li className="flex gap-2.5">
            <span className="text-sky-400">&bull;</span>
            <span>
              <strong className="text-white">Authoritative risk:</strong> Caller claims cannot lower risk in tested
              authorization paths (INV-04).
            </span>
          </li>
          <li className="flex gap-2.5">
            <span className="text-sky-400">&bull;</span>
            <span>
              <strong className="text-white">Single-use tickets:</strong> HMAC-SHA256, bound to exact operation parameters.
              Replay attempts return ok: false in tested redemption paths (INV-09).
            </span>
          </li>
          <li className="flex gap-2.5">
            <span className="text-sky-400">&bull;</span>
            <span>
              <strong className="text-white">Platform sandbox delegation:</strong> Execution containment is passed
              to platform security mechanisms (macOS Seatbelt, Linux bubblewrap, Windows AppContainer).
            </span>
          </li>
        </ul>
      </div>

      <div className="flex flex-wrap gap-4 border-t border-white/10 pt-6">
        <Link
          href="/docs/evidence"
          className="rounded-xl border border-sky-500/20 bg-sky-500/10 px-4 py-2.5 font-mono text-xs font-bold text-sky-400 hover:bg-sky-500/20 transition inline-flex items-center gap-1.5"
        >
          <TestTube size={13} />
          <span>Security Evidence &rarr;</span>
        </Link>
        <Link
          href="/docs/threat-model"
          className="rounded-xl border border-white/10 bg-white/5 px-4 py-2.5 font-mono text-xs font-bold text-white/70 hover:bg-white/10 hover:text-white transition"
        >
          Threat Model &amp; Limitations &rarr;
        </Link>
        <Link
          href="/docs/verification-matrix"
          className="rounded-xl border border-white/10 bg-white/5 px-4 py-2.5 font-mono text-xs font-bold text-white/70 hover:bg-white/10 hover:text-white transition"
        >
          12 Tested Properties &rarr;
        </Link>
      </div>
    </div>
  );
}
