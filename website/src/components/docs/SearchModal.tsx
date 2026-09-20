"use client";

import { useState, useEffect, useCallback } from "react";
import { Search, X, FileText } from "lucide-react";

interface SearchResult {
  title: string;
  href: string;
  description: string;
}

const PAGES: SearchResult[] = [
  { title: "Overview", href: "/docs/overview", description: "RTQ overview — pipeline, packages, getting started" },
  { title: "Security Overview", href: "/docs/security-overview", description: "Pipeline, core principles, quick example" },
  { title: "Threat Model", href: "/docs/threat-model", description: "Trust boundaries, threats, mitigations, honest limitations" },
  { title: "Verification Matrix", href: "/docs/verification-matrix", description: "Twelve automated invariants, platform gating, test suites" },
  { title: "Verification & Traceability", href: "/docs/verification-traceability", description: "Source file:line citations for every security claim" },
  { title: "Platform Support", href: "/docs/platform-support", description: "macOS Seatbelt, Linux bwrap, Windows AppContainer" },
  { title: "Aartiq Integration", href: "/docs/aartiq-integration", description: "How to bring RTQ to an Aartiq-style federated MCP app" },
  { title: "Mobile Approval", href: "/docs/mobile-approval", description: "QR challenge-response, signing, pairing, protocol" },
  { title: "CLI Reference", href: "/docs/cli", description: "Capabilities, policy check, sandbox test, verify, diagnostics" },
  { title: "Testing Strategy", href: "/docs/testing-strategy", description: "Labels, suites, platform gating, CI" },
  { title: "Provenance", href: "/docs/provenance", description: "Original implementation, audit trail, design inputs" },
];

interface Props {
  isOpen: boolean;
  onClose: () => void;
}

export function SearchModal({ isOpen, onClose }: Props) {
  const [query, setQuery] = useState("");

  const results = query.trim()
    ? PAGES.filter(
        (p) =>
          p.title.toLowerCase().includes(query.toLowerCase()) ||
          p.description.toLowerCase().includes(query.toLowerCase())
      )
    : PAGES;

  const handleKeyDown = useCallback(
    (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    },
    [onClose]
  );

  useEffect(() => {
    if (isOpen) document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [isOpen, handleKeyDown]);

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-[100] flex items-start justify-center bg-black/60 pt-20 backdrop-blur-sm">
      <div className="w-full max-w-lg rounded-2xl border border-white/10 bg-[#0a0e1a] shadow-2xl">
        <div className="flex items-center gap-3 border-b border-white/5 px-4 py-3">
          <Search size={16} className="text-white/30" />
          <input
            autoFocus
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search docs..."
            className="flex-1 bg-transparent text-sm text-white outline-none placeholder:text-white/30"
          />
          <button onClick={onClose}>
            <X size={16} className="text-white/30 hover:text-white transition" />
          </button>
        </div>
        <div className="max-h-80 overflow-y-auto p-2">
          {results.map((r) => (
            <a
              key={r.href}
              href={r.href}
              onClick={onClose}
              className="flex items-center gap-3 rounded-lg px-3 py-3 text-sm text-white/60 transition hover:bg-white/5 hover:text-white"
            >
              <FileText size={14} className="shrink-0 text-white/20" />
              <div>
                <p className="font-medium">{r.title}</p>
                <p className="text-xs text-white/30">{r.description}</p>
              </div>
            </a>
          ))}
          {results.length === 0 && (
            <p className="py-8 text-center text-sm text-white/30">No results found.</p>
          )}
        </div>
      </div>
    </div>
  );
}
