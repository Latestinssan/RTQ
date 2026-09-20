import Link from "next/link";
import { Shield, TestTube, AlertTriangle, ExternalLink } from "lucide-react";
import { COMMIT_SHA } from "@/components/evidence/EvidenceBadge";

export const metadata = {
  title: "Security Overview",
  description: "Architecture of the RTQ pipeline, authoritative risk engine, and single-use authorization tickets.",
};

export default function SecurityOverviewPage() {
  return (
    <div className="space-y-10">
      <div>
        <p className="mb-3 text-[10px] font-mono font-bold uppercase tracking-[0.5em] text-sky-400">
          Architecture &bull; Security Model
        </p>
        <h1 className="text-3xl font-black tracking-tight text-white md:text-5xl">
          Security Overview
        </h1>
        <p className="mt-4 text-base text-white/60 leading-relaxed">
          RTQ&apos;s security architecture delegates containment to platform isolation tools, computes
          risk authoritatively, and mandates explicit capability registration. Authorizations are
          represented as short-lived, single-use, cryptographically-signed tickets.
        </p>
      </div>

      {/* Alpha Disclaimer */}
      <div className="rounded-xl border border-amber-500/20 bg-amber-500/5 p-4 text-xs text-amber-200/90 leading-relaxed flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-2">
          <AlertTriangle size={15} className="text-amber-400 shrink-0" />
          <span>
            <strong>Alpha Software:</strong> RTQ has not undergone an independent security audit. All
            claims link to automated tests pinned at commit <code className="text-white font-mono">{COMMIT_SHA}</code>.
          </span>
        </div>
        <Link href="/docs/evidence" className="text-sky-400 underline font-mono font-bold">
          View Evidence Matrix &rarr;
        </Link>
      </div>

      <div>
        <h2 className="text-xl font-bold text-white mb-4">Pipeline Layers</h2>
        <div className="space-y-3">
          {[
            {
              name: "1. Capability Registry",
              desc: "Every operation must be explicitly registered before execution. Unregistered capability names return decision: 'denied'.",
              invariant: "INV-01",
            },
            {
              name: "2. Risk Engine",
              desc: "RTQ evaluates risk authoritatively. Caller claimedRisk cannot lower declared risk ratings.",
              invariant: "INV-04",
            },
            {
              name: "3. Policy Rules",
              desc: "Default-deny evaluation. A missing matching rule evaluates to decision: 'deny'.",
              invariant: "INV-03",
            },
            {
              name: "4. Clarification",
              desc: "When a capability requires parameters not provided, RTQ prompts with structured questions rather than guessing.",
              invariant: "Bounded Turns",
            },
            {
              name: "5. Approval",
              desc: "Human or device challenge-response via HMAC-SHA256-signed, single-use authorization tickets.",
              invariant: "INV-12",
            },
            {
              name: "6. Platform Sandbox",
              desc: "Execution containment is delegated to platform security mechanisms (macOS Seatbelt, Linux bubblewrap, Windows AppContainer).",
              invariant: "INV-07",
            },
            {
              name: "7. Redacted Audit",
              desc: "Structured audit events with HMAC integrity. Sensitive environment keys and tokens are stripped.",
              invariant: "INV-08",
            },
          ].map((layer) => (
            <div key={layer.name} className="rounded-xl border border-white/5 bg-white/[0.02] p-4">
              <div className="flex items-center justify-between mb-1.5">
                <h3 className="text-sm font-bold text-white">{layer.name}</h3>
                <span className="font-mono text-[10px] text-sky-400 rounded bg-sky-500/10 px-2 py-0.5 border border-sky-500/20">
                  {layer.invariant}
                </span>
              </div>
              <p className="text-xs text-white/50 leading-relaxed">{layer.desc}</p>
            </div>
          ))}
        </div>
      </div>

      <div>
        <h2 className="text-xl font-bold text-white mb-4">Tested Core Properties</h2>
        <ul className="space-y-3 text-xs text-white/60">
          <li className="flex gap-2.5">
            <span className="text-sky-400">&bull;</span>
            <span>
              <strong className="text-white">Explicit Surface:</strong> Only registered capabilities can execute.
              Unknown capabilities return code: &quot;capability.not_registered&quot; (INV-01).
            </span>
          </li>
          <li className="flex gap-2.5">
            <span className="text-sky-400">&bull;</span>
            <span>
              <strong className="text-white">Default Deny:</strong> A missing policy rule is a denial, never an implicit allow (INV-03).
            </span>
          </li>
          <li className="flex gap-2.5">
            <span className="text-sky-400">&bull;</span>
            <span>
              <strong className="text-white">Authoritative Risk:</strong> Caller claims cannot lower risk in tested authorization paths (INV-04).
            </span>
          </li>
          <li className="flex gap-2.5">
            <span className="text-sky-400">&bull;</span>
            <span>
              <strong className="text-white">Single-Use Tickets:</strong> HMAC-SHA256, bound to exact operation parameters.
              Second redemption returns ok: false (INV-09).
            </span>
          </li>
          <li className="flex gap-2.5">
            <span className="text-sky-400">&bull;</span>
            <span>
              <strong className="text-white">Fail-Closed Sandbox Initiation:</strong> If the platform sandbox backend
              cannot be initialized, execution halts.
            </span>
          </li>
        </ul>
      </div>

      <div>
        <h2 className="text-xl font-bold text-white mb-4">Code Example</h2>
        <div className="rounded-2xl border border-white/5 bg-white/[0.02] p-5 font-mono text-xs leading-relaxed text-white/60">
          <span className="text-white/30">// Register a capability with declared base risk</span>
          <br />
          rtq.registerCapability(&#123;
          <br />
          &nbsp;&nbsp;name: &quot;files.delete&quot;,
          <br />
          &nbsp;&nbsp;version: 1,
          <br />
          &nbsp;&nbsp;inputSchema: &#123; type: &quot;object&quot;, properties: &#123; path: &#123; type: &quot;string&quot; &#125; &#125;, required: [&quot;path&quot;] &#125;,
          <br />
          &nbsp;&nbsp;risk: &#123; base: &quot;high&quot;, factors: [&quot;irreversible&quot;] &#125;,
          <br />
          &nbsp;&nbsp;execute: <span className="text-sky-400">async</span> (ctx, input) =&gt; &#123;
          <br />
          &nbsp;&nbsp;&nbsp;&nbsp;<span className="text-white/30">// Executes inside OS sandbox with verified ticket</span>
          <br />
          &nbsp;&nbsp;&nbsp;&nbsp;await fs.unlink(input.path);
          <br />
          &nbsp;&nbsp;&nbsp;&nbsp;return &#123; ok: <span className="text-sky-400">true</span> &#125;;
          <br />
          &nbsp;&nbsp;&#125;,
          <br />
          &#125;);
        </div>
      </div>

      <div className="flex flex-wrap gap-4 border-t border-white/10 pt-6">
        <Link
          href="/docs/evidence"
          className="rounded-xl border border-sky-500/20 bg-sky-500/10 px-4 py-2.5 font-mono text-xs font-bold text-sky-400 hover:bg-sky-500/20 transition inline-flex items-center gap-1.5"
        >
          <TestTube size={13} />
          <span>View Security Evidence &rarr;</span>
        </Link>
        <Link
          href="/docs/threat-model"
          className="rounded-xl border border-white/10 bg-white/5 px-4 py-2.5 font-mono text-xs font-bold text-white/70 hover:bg-white/10 hover:text-white transition"
        >
          Threat Model &amp; Limitations &rarr;
        </Link>
      </div>
    </div>
  );
}
