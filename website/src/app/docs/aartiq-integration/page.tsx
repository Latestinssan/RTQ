import Link from "next/link";

export default function AartiqIntegrationPage() {
  return (
    <div>
      <div className="mb-12">
        <p className="mb-4 text-[10px] font-black uppercase tracking-[0.5em] text-sky-400">Integration</p>
        <h1 className="mb-4 text-4xl font-black tracking-tight text-white">Aartiq Integration</h1>
        <p className="text-lg text-white/50">
          How to bring RTQ into an Aartiq-style federated MCP application.
        </p>
      </div>

      <h2 className="mb-4 text-2xl font-black text-white">Architecture</h2>
      <div className="mb-8 rounded-2xl border border-white/5 bg-white/[0.02] p-6 font-mono text-xs leading-relaxed text-white/50">
        Aartiq App → MCP Bridge → RTQ Runtime<br />
        &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;↓<br />
        &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Capability Registry<br />
        &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;→ Risk Engine<br />
        &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;→ Policy Rules<br />
        &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;→ Sandbox (OS-native)<br />
        &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;→ Audit Log
      </div>

      <h2 className="mb-4 text-2xl font-black text-white">Integration Steps</h2>
      <div className="mb-8 space-y-4">
        {[
          { step: "1", title: "Install RTQ packages", desc: "npm install @rtq/security @rtq/core @rtq/risk @rtq/policy @rtq/approval @rtq/sandbox @rtq/audit" },
          { step: "2", title: "Initialize RTQ runtime", desc: "const rtq = createRTQ({ signingKey, sandbox: 'auto' });" },
          { step: "3", title: "Register MCP tool capabilities", desc: "For each MCP tool, register an RTQ capability with appropriate risk level and input schema." },
          { step: "4", title: "Wrap MCP bridge calls", desc: "Before executing any MCP tool call, route through RTQ's pipeline: capability → risk → policy → approval → execute." },
          { step: "5", title: "Configure approval for high-risk tools", desc: "Tools that access filesystem, network, or system resources should require human approval via QR/mobile." },
          { step: "6", title: "Enable audit logging", desc: "All RTQ pipeline events are emitted as structured audit events with redacted secrets." },
        ].map((item) => (
          <div key={item.step} className="flex gap-4 rounded-xl border border-white/5 bg-white/[0.02] p-5">
            <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-sky-500/10 text-sm font-bold text-sky-400">{item.step}</div>
            <div>
              <h3 className="mb-1 text-sm font-bold text-white">{item.title}</h3>
              <p className="text-xs text-white/40">{item.desc}</p>
            </div>
          </div>
        ))}
      </div>

      <h2 className="mb-4 text-2xl font-black text-white">Example: Wrapping an MCP Tool</h2>
      <div className="mb-8 rounded-2xl border border-white/5 bg-white/[0.02] p-6 font-mono text-xs leading-relaxed text-white/50">
        <span className="text-white/30">// Register the MCP file-read tool as an RTQ capability</span><br />
        rtq.registerCapability({"{"}<br />
        &nbsp;&nbsp;name: &quot;mcp.files.read&quot;,<br />
        &nbsp;&nbsp;version: 1,<br />
        &nbsp;&nbsp;inputSchema: {"{"} /* MCP tool input schema */ {"}"},<br />
        &nbsp;&nbsp;risk: {"{"} base: &quot;low&quot; {"}"},<br />
        &nbsp;&nbsp;execute: <span className="text-sky-400">async</span> (ctx, input) =&gt; {"{"}<br />
        &nbsp;&nbsp;&nbsp;&nbsp;<span className="text-white/30">// Call the actual MCP tool</span><br />
        &nbsp;&nbsp;&nbsp;&nbsp;return await mcpClient.callTool(&quot;read_file&quot;, input);<br />
        &nbsp;&nbsp;{"}"},<br />
        {"}"});<br /><br />
        <span className="text-white/30">// Now every call goes through RTQ pipeline</span><br />
        const result = await rtq.execute(&quot;mcp.files.read&quot;, {"{"} path: &quot;./config.json&quot; {"}"});
      </div>

      <div className="mt-12 rounded-2xl border border-white/5 bg-white/[0.02] p-6">
        <p className="mb-4 text-xs font-black uppercase tracking-wider text-white/30">Next</p>
        <div className="flex flex-wrap gap-3">
          <Link href="/docs/mobile-approval" className="rounded-xl border border-sky-500/20 bg-sky-500/5 px-4 py-2 text-xs font-bold text-sky-400 transition hover:bg-sky-500/20">
            Mobile Approval →
          </Link>
          <Link href="/docs/cli" className="rounded-xl border border-white/10 bg-white/5 px-4 py-2 text-xs font-bold text-white/60 transition hover:bg-white/10">
            CLI Reference →
          </Link>
        </div>
      </div>
    </div>
  );
}
