import Link from "next/link";

export default function MobileApprovalPage() {
  return (
    <div>
      <div className="mb-12">
        <p className="mb-4 text-[10px] font-black uppercase tracking-[0.5em] text-sky-400">Integration</p>
        <h1 className="mb-4 text-4xl font-black tracking-tight text-white">Mobile Approval</h1>
        <p className="text-lg text-white/50">
          QR challenge-response approval for high-risk operations. No PINs, no
          biometrics — scanning grants nothing. The challenge is the authorization.
        </p>
      </div>

      <h2 className="mb-4 text-2xl font-black text-white">Protocol Overview</h2>
      <div className="mb-8 rounded-2xl border border-white/5 bg-white/[0.02] p-6 font-mono text-xs leading-relaxed text-white/50">
        1. RTQ generates a challenge (unique, time-bound, operation-specific)<br />
        2. Challenge encoded as QR code displayed to user<br />
        3. User scans QR with mobile device<br />
        4. Mobile device signs the challenge with device key<br />
        5. Signed response sent back to RTQ<br />
        6. RTQ verifies signature + expiry + operation match<br />
        7. If valid → single-use ticket issued → execution proceeds
      </div>

      <h2 className="mb-4 text-2xl font-black text-white">Security Properties</h2>
      <div className="mb-8 space-y-3">
        {[
          { prop: "Challenge-Response", desc: "Scanning the QR alone grants nothing. The mobile device must cryptographically sign the challenge." },
          { prop: "Time-Bound", desc: "Challenges expire after a configurable timeout (default: 60 seconds)." },
          { prop: "Operation-Bound", desc: "Each challenge is bound to the exact operation (capability name + input hash)." },
          { prop: "Single-Use", desc: "Once a challenge is answered, it cannot be reused." },
          { prop: "No PINs", desc: "No PINs, passwords, or biometrics are part of the protocol. The device key is the credential." },
        ].map((item, i) => (
          <div key={i} className="rounded-xl border border-white/5 bg-white/[0.02] p-4">
            <h3 className="mb-1 text-sm font-bold text-emerald-400">{item.prop}</h3>
            <p className="text-xs text-white/40">{item.desc}</p>
          </div>
        ))}
      </div>

      <h2 className="mb-4 text-2xl font-black text-white">Device Pairing</h2>
      <p className="mb-4 text-sm text-white/50">
        Before a mobile device can approve operations, it must be paired with the
        RTQ runtime. Pairing is a one-time process:
      </p>
      <div className="mb-8 rounded-2xl border border-white/5 bg-white/[0.02] p-6 font-mono text-xs leading-relaxed text-white/50">
        1. RTQ generates a pairing key<br />
        2. Pairing key displayed as QR code<br />
        3. Mobile app scans and stores the pairing key<br />
        4. Subsequent challenges are sent to paired devices only
      </div>

      <h2 className="mb-4 text-2xl font-black text-white">Configuration</h2>
      <div className="mb-8 rounded-2xl border border-white/5 bg-white/[0.02] p-6 font-mono text-xs leading-relaxed text-white/50">
        const rtq = createRTQ({"{"}<br />
        &nbsp;&nbsp;signingKey: process.env.RTQ_SIGNING_KEY!,<br />
        &nbsp;&nbsp;approval: {"{"}<br />
        &nbsp;&nbsp;&nbsp;&nbsp;strategy: &quot;qr-mobile&quot;,<br />
        &nbsp;&nbsp;&nbsp;&nbsp;timeout: 60_000, <span className="text-white/30">// 60 seconds</span><br />
        &nbsp;&nbsp;&nbsp;&nbsp;requireApproval: (cap) =&gt; cap.risk.base === &quot;high&quot; || cap.risk.base === &quot;critical&quot;,<br />
        &nbsp;&nbsp;{"}"},<br />
        {"}"});
      </div>

      <div className="mt-12 rounded-2xl border border-white/5 bg-white/[0.02] p-6">
        <p className="mb-4 text-xs font-black uppercase tracking-wider text-white/30">Next</p>
        <div className="flex flex-wrap gap-3">
          <Link href="/docs/cli" className="rounded-xl border border-sky-500/20 bg-sky-500/5 px-4 py-2 text-xs font-bold text-sky-400 transition hover:bg-sky-500/20">
            CLI Reference →
          </Link>
          <Link href="/docs/testing-strategy" className="rounded-xl border border-white/10 bg-white/5 px-4 py-2 text-xs font-bold text-white/60 transition hover:bg-white/10">
            Testing Strategy →
          </Link>
        </div>
      </div>
    </div>
  );
}
