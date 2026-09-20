import Link from "next/link";
import { Shield, AlertTriangle, ExternalLink, ArrowRight } from "lucide-react";
import { COMMIT_SHA, REPO_BASE, getGithubSourceUrl } from "@/components/evidence/EvidenceBadge";

export const metadata = {
  title: "Threat Model & Honest Limitations",
  description: "Trust boundaries, threats, mitigations, and explicit non-goals in the RTQ security architecture.",
};

export default function ThreatModelPage() {
  const threats = [
    {
      threat: "Capability Spoofing / Name Collisions",
      desc: "An untrusted caller attempts to register a capability mimicking a system operation or override an existing registration.",
      mitigation: "CapabilityRegistry enforces immutable schemas and rejects name collisions at registration time.",
      source: "packages/core/src/capability-registry.ts",
      lines: [40, 85] as [number, number],
      test: "tests/unit/registry.test.ts",
    },
    {
      threat: "Authorization Ticket Replay",
      desc: "Reusing a valid authorization ticket for a second execution attempt.",
      mitigation: "TicketStore atomically transitions ticket status to 'redeemed'. Replays return ok: false with code 'replay'.",
      source: "packages/core/src/ticket-store.ts",
      lines: [180, 206] as [number, number],
      test: "tests/invariants/invariants.test.ts#L245-L263",
    },
    {
      threat: "Caller Risk Manipulation",
      desc: "Caller claims a low risk (claimedRisk: 'low') to bypass mandatory human or device confirmation.",
      mitigation: "Authoritative risk evaluator ignores caller downgrade claims; risk is calculated independently from declared base and context factors.",
      source: "packages/security/src/index.ts",
      lines: [337, 347] as [number, number],
      test: "tests/invariants/invariants.test.ts#L84-L112",
    },
    {
      threat: "Implicit Policy Bypass",
      desc: "Executing a capability when no matching allow rule has been defined.",
      mitigation: "Strict default-deny policy evaluator. Missing rules evaluate to refusal (INV-03).",
      source: "packages/policy/src/index.ts",
      lines: [365, 382] as [number, number],
      test: "tests/invariants/invariants.test.ts#L74-L82",
    },
    {
      threat: "Uncontained Execution Fallback",
      desc: "Executing unsandboxed when platform sandbox tools are missing or misconfigured.",
      mitigation: "Sandbox adapters fail closed. If Seatbelt or bubblewrap cannot be initialized, execution is blocked.",
      source: "packages/sandbox/src/index.ts",
      lines: [220, 280] as [number, number],
      test: "tests/sandbox/darwin.test.ts#L63-L117",
    },
    {
      threat: "Audit Record Tampering & Secret Leakage",
      desc: "Hiding unauthorized activity or leaking sensitive credentials into audit streams.",
      mitigation: "Structured events with HMAC signatures. Environment variables and secrets are redacted prior to emission.",
      source: "packages/sandbox/src/index.ts",
      lines: [85, 125] as [number, number],
      test: "tests/invariants/invariants.test.ts#L219-L243",
    },
  ];

  return (
    <div className="space-y-10">
      <div>
        <p className="mb-3 text-[10px] font-mono font-bold uppercase tracking-[0.5em] text-sky-400">
          Security &bull; Architecture
        </p>
        <h1 className="text-3xl font-black tracking-tight text-white md:text-5xl">
          Threat Model &amp; Honest Limitations
        </h1>
        <p className="mt-4 text-base text-white/60 leading-relaxed">
          RTQ&apos;s threat model defines explicit trust boundaries, identified threats, concrete
          mitigations, and what RTQ explicitly does not attempt to solve.
        </p>
      </div>

      {/* Trust Boundaries */}
      <section className="space-y-4">
        <h2 className="text-xl font-bold text-white">Trust Boundaries</h2>
        <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-2 text-xs font-mono">
          {[
            { entity: "RTQ Runtime Process", status: "Trusted (in-memory execution)", safe: true },
            { entity: "Capability Registry", status: "Trusted (immutable after init)", safe: true },
            { entity: "Policy Engine", status: "Trusted (default-deny evaluator)", safe: true },
            { entity: "Ticket Signing Key", status: "Trusted (never leaves host memory)", safe: true },
            { entity: "Operating System Kernel", status: "Trusted (kernel sandbox driver)", safe: true },
            { entity: "Caller / Host Process", status: "Untrusted (may submit malicious claims)", safe: false },
            { entity: "Tool Arguments & Inputs", status: "Untrusted (subject to schema validation)", safe: false },
            { entity: "Network Peripherals", status: "Untrusted (blocked unless explicitly permitted)", safe: false },
          ].map((item, i) => (
            <div
              key={i}
              className="flex items-center justify-between rounded-xl border border-white/5 bg-white/[0.02] p-3.5"
            >
              <span className="text-white/80">{item.entity}</span>
              <span className={item.safe ? "text-emerald-400 font-bold" : "text-amber-400 font-bold"}>
                {item.safe ? "TRUSTED" : "UNTRUSTED"}
              </span>
            </div>
          ))}
        </div>
      </section>

      {/* Threats and Mitigations */}
      <section className="space-y-4">
        <h2 className="text-xl font-bold text-white">Threats &amp; Concrete Mitigations</h2>
        <p className="text-xs text-white/50">
          All mitigations link directly to exact source lines at commit <code className="text-sky-300 font-mono">{COMMIT_SHA}</code>.
        </p>
        <div className="space-y-4">
          {threats.map((t, idx) => {
            const sourceUrl = getGithubSourceUrl(t.source, t.lines[0], t.lines[1]);
            return (
              <div key={idx} className="rounded-xl border border-white/10 bg-[#070914] p-5 space-y-3">
                <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/5 pb-2">
                  <h3 className="font-mono text-xs font-bold text-rose-400">{t.threat}</h3>
                  <a
                    href={sourceUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="font-mono text-[11px] text-sky-400 hover:underline inline-flex items-center gap-1"
                  >
                    <span>{t.source.split("/").pop()} (L{t.lines[0]}-{t.lines[1]})</span>
                    <ExternalLink size={10} />
                  </a>
                </div>
                <p className="text-xs text-white/50">{t.desc}</p>
                <div className="rounded-lg border border-emerald-500/20 bg-emerald-500/[0.02] p-3 text-xs text-emerald-300/90">
                  <strong className="text-emerald-400 block font-mono text-[10px] uppercase">Mitigation:</strong>
                  {t.mitigation}
                </div>
              </div>
            );
          })}
        </div>
      </section>

      {/* Honest Limitations */}
      <section className="space-y-4 border-t border-white/10 pt-8">
        <div className="flex items-center gap-2">
          <AlertTriangle className="text-amber-400 h-5 w-5" />
          <h2 className="text-xl font-bold text-white">Honest Limitations &amp; Explicit Non-Goals</h2>
        </div>
        <p className="text-xs text-white/50 leading-relaxed">
          Documenting limitations is an essential requirement of technical honesty. RTQ does not
          claim to solve these threats:
        </p>

        <div className="space-y-3 text-xs text-white/70">
          <div className="rounded-xl border border-amber-500/20 bg-amber-500/[0.02] p-4 space-y-1.5">
            <h4 className="font-mono font-bold text-amber-300 uppercase text-[11px]">
              1. Compromised Operating System Kernel
            </h4>
            <p className="leading-relaxed">
              RTQ delegates execution isolation to kernel mechanisms (Seatbelt on macOS, bubblewrap
              namespaces on Linux, AppContainer on Windows). If the host kernel has been exploited or
              backdoored, userland sandboxes can be bypassed.
            </p>
          </div>

          <div className="rounded-xl border border-amber-500/20 bg-amber-500/[0.02] p-4 space-y-1.5">
            <h4 className="font-mono font-bold text-amber-300 uppercase text-[11px]">
              2. Human Approver Inattention (&quot;Rubber-Stamping&quot;)
            </h4>
            <p className="leading-relaxed">
              Cryptographic challenge-response guarantees that an authorized device signed the operation
              nonce. It cannot guarantee that the human operator read or understood the side effects of
              the action before tapping approval.
            </p>
          </div>

          <div className="rounded-xl border border-amber-500/20 bg-amber-500/[0.02] p-4 space-y-1.5">
            <h4 className="font-mono font-bold text-amber-300 uppercase text-[11px]">
              3. Microarchitectural &amp; Side-Channel Attacks
            </h4>
            <p className="leading-relaxed">
              RTQ does not protect against speculative execution vulnerabilities (Spectre, Meltdown) or
              CPU cache timing attacks between processes sharing identical hardware cores.
            </p>
          </div>

          <div className="rounded-xl border border-amber-500/20 bg-amber-500/[0.02] p-4 space-y-1.5">
            <h4 className="font-mono font-bold text-amber-300 uppercase text-[11px]">
              4. Code Running Outside the RTQ Runtime
            </h4>
            <p className="leading-relaxed">
              RTQ only governs operations that pass through <code className="text-white font-mono">rtq.authorize()</code> and{" "}
              <code className="text-white font-mono">rtq.execute()</code>. Host software that launches binaries directly
              without passing through RTQ cannot be constrained.
            </p>
          </div>

          <div className="rounded-xl border border-amber-500/20 bg-amber-500/[0.02] p-4 space-y-1.5">
            <h4 className="font-mono font-bold text-amber-300 uppercase text-[11px]">
              5. Supply Chain &amp; Third-Party Audits
            </h4>
            <p className="leading-relaxed">
              Security-critical RTQ packages currently declare zero third-party npm dependencies. However,
              zero npm dependencies does not eliminate all supply-chain risk (e.g. Node.js binary integrity,
              operating system utilities, compilers). RTQ has not undergone an independent third-party audit.
            </p>
          </div>
        </div>
      </section>

      <div className="flex flex-wrap gap-4 border-t border-white/10 pt-6">
        <Link
          href="/docs/evidence"
          className="rounded-xl border border-sky-500/20 bg-sky-500/10 px-4 py-2.5 font-mono text-xs font-bold text-sky-400 hover:bg-sky-500/20 transition"
        >
          View Evidence Matrix &rarr;
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
