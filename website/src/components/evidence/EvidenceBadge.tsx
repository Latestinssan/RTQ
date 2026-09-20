import React from "react";
import { CheckCircle2, AlertTriangle, ExternalLink, Shield, TestTube, Cpu, FileCode } from "lucide-react";

export type EvidenceLevel =
  | "LEVEL 0 — DOCUMENTED DESIGN"
  | "LEVEL 1 — UNIT TESTED"
  | "LEVEL 2 — INTEGRATION TESTED"
  | "LEVEL 3 — REAL OS ENFORCEMENT"
  | "LEVEL 4 — ADVERSARIAL TESTED"
  | "LEVEL 5 — INDEPENDENTLY AUDITED";

export const COMMIT_SHA = "e179d2b";
export const REPO_BASE = `https://github.com/Latestinssan/RTQ`;

export function getGithubSourceUrl(path: string, startLine?: number, endLine?: number): string {
  if (!startLine) {
    return `${REPO_BASE}/blob/${COMMIT_SHA}/${path}`;
  }
  if (!endLine || startLine === endLine) {
    return `${REPO_BASE}/blob/${COMMIT_SHA}/${path}#L${startLine}`;
  }
  return `${REPO_BASE}/blob/${COMMIT_SHA}/${path}#L${startLine}-L${endLine}`;
}

export function getWorkflowUrl(workflow: string): string {
  return `${REPO_BASE}/blob/${COMMIT_SHA}/.github/workflows/${workflow}`;
}

export function EvidenceBadge({ level }: { level: EvidenceLevel }) {
  let colorClasses = "text-sky-400 border-sky-500/30 bg-sky-500/10";
  let icon = <TestTube size={11} className="shrink-0" />;

  if (level.startsWith("LEVEL 0")) {
    colorClasses = "text-slate-400 border-slate-500/30 bg-slate-500/10";
    icon = <FileCode size={11} className="shrink-0" />;
  } else if (level.startsWith("LEVEL 1")) {
    colorClasses = "text-cyan-400 border-cyan-500/30 bg-cyan-500/10";
    icon = <TestTube size={11} className="shrink-0" />;
  } else if (level.startsWith("LEVEL 2")) {
    colorClasses = "text-indigo-400 border-indigo-500/30 bg-indigo-500/10";
    icon = <TestTube size={11} className="shrink-0" />;
  } else if (level.startsWith("LEVEL 3")) {
    colorClasses = "text-emerald-400 border-emerald-500/30 bg-emerald-500/10";
    icon = <Cpu size={11} className="shrink-0" />;
  } else if (level.startsWith("LEVEL 4")) {
    colorClasses = "text-amber-400 border-amber-500/30 bg-amber-500/10";
    icon = <AlertTriangle size={11} className="shrink-0" />;
  } else if (level.startsWith("LEVEL 5")) {
    colorClasses = "text-purple-400 border-purple-500/30 bg-purple-500/10";
    icon = <Shield size={11} className="shrink-0" />;
  }

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 font-mono text-[10px] font-bold uppercase tracking-wider ${colorClasses}`}
    >
      {icon}
      <span>{level}</span>
    </span>
  );
}

export interface EvidenceItemProps {
  id?: string;
  claim: string;
  level: EvidenceLevel;
  implementationFile: string;
  implementationLines?: [number, number];
  testFile: string;
  testLines?: [number, number];
  workflow: string;
  runner: string;
  commitSha?: string;
  scope: string;
  notProven: string;
}

export function EvidenceBlock({
  id,
  claim,
  level,
  implementationFile,
  implementationLines,
  testFile,
  testLines,
  workflow,
  runner,
  commitSha = COMMIT_SHA,
  scope,
  notProven,
}: EvidenceItemProps) {
  const implUrl = getGithubSourceUrl(
    implementationFile,
    implementationLines?.[0],
    implementationLines?.[1],
  );
  const testUrl = getGithubSourceUrl(testFile, testLines?.[0], testLines?.[1]);
  const wfUrl = getWorkflowUrl(workflow);

  return (
    <div className="rounded-2xl border border-white/[0.08] bg-[#070914] p-5 md:p-6 shadow-xl space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/[0.06] pb-3">
        <div className="flex items-center gap-2">
          {id && (
            <span className="rounded bg-sky-500/10 px-2 py-0.5 font-mono text-xs font-black text-sky-400 border border-sky-500/20">
              {id}
            </span>
          )}
          <span className="font-mono text-xs text-white/50">Commit:</span>
          <a
            href={`${REPO_BASE}/commit/${commitSha}`}
            target="_blank"
            rel="noopener noreferrer"
            className="font-mono text-xs text-sky-400 underline hover:text-sky-300"
          >
            {commitSha}
          </a>
        </div>
        <EvidenceBadge level={level} />
      </div>

      <div>
        <span className="font-mono text-[10px] font-bold uppercase tracking-widest text-sky-400">
          Claimed Property
        </span>
        <h4 className="mt-1 text-base font-bold text-white leading-snug">{claim}</h4>
      </div>

      <div className="grid grid-cols-1 gap-3 sm:grid-cols-3 border-t border-b border-white/[0.06] py-3 text-xs">
        <div>
          <span className="block font-mono text-[10px] uppercase text-white/40">Implementation</span>
          <a
            href={implUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="mt-1 inline-flex items-center gap-1 font-mono text-sky-300 hover:text-sky-200 hover:underline"
          >
            <span className="truncate max-w-[200px]">{implementationFile}</span>
            <ExternalLink size={11} className="shrink-0" />
          </a>
          {implementationLines && (
            <span className="block font-mono text-[10px] text-white/40">
              Lines {implementationLines[0]}-{implementationLines[1]}
            </span>
          )}
        </div>

        <div>
          <span className="block font-mono text-[10px] uppercase text-white/40">Automated Test</span>
          <a
            href={testUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="mt-1 inline-flex items-center gap-1 font-mono text-sky-300 hover:text-sky-200 hover:underline"
          >
            <span className="truncate max-w-[200px]">{testFile}</span>
            <ExternalLink size={11} className="shrink-0" />
          </a>
          {testLines && (
            <span className="block font-mono text-[10px] text-white/40">
              Lines {testLines[0]}-{testLines[1]}
            </span>
          )}
        </div>

        <div>
          <span className="block font-mono text-[10px] uppercase text-white/40">CI Environment</span>
          <a
            href={wfUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="mt-1 inline-flex items-center gap-1 font-mono text-sky-300 hover:text-sky-200 hover:underline"
          >
            <span className="truncate max-w-[180px]">{workflow}</span>
            <ExternalLink size={11} className="shrink-0" />
          </a>
          <span className="block font-mono text-[10px] text-white/40">Runner: {runner}</span>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-3 md:grid-cols-2 text-xs">
        <div className="rounded-lg border border-emerald-500/20 bg-emerald-500/[0.03] p-3">
          <span className="block font-mono text-[10px] font-bold uppercase tracking-wider text-emerald-400">
            Tested Behavior (Scope)
          </span>
          <p className="mt-1 leading-relaxed text-slate-300">{scope}</p>
        </div>

        <div className="rounded-lg border border-amber-500/20 bg-amber-500/[0.03] p-3">
          <span className="block font-mono text-[10px] font-bold uppercase tracking-wider text-amber-400">
            Not Established By This Test
          </span>
          <p className="mt-1 leading-relaxed text-slate-400">{notProven}</p>
        </div>
      </div>
    </div>
  );
}
