"use client";

import { useState, useEffect } from "react";
import Link from "next/link";
import Image from "next/image";
import { Shield, Search, Github, BookOpen, Menu, X, ArrowUpRight, Terminal } from "lucide-react";
import { APP_INFO } from "@/lib/version";
import { SearchModal } from "@/components/docs/SearchModal";

export function Navbar() {
  const [scrolled, setScrolled] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [searchOpen, setSearchOpen] = useState(false);

  useEffect(() => {
    const handleScroll = () => {
      setScrolled(window.scrollY > 20);
    };
    window.addEventListener("scroll", handleScroll);
    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

  // Keyboard shortcut for Cmd+K
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        setSearchOpen(true);
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, []);

  return (
    <>
      <SearchModal isOpen={searchOpen} onClose={() => setSearchOpen(false)} />

      <header
        className={`fixed top-0 left-0 right-0 z-50 transition-all duration-300 ${
          scrolled
            ? "border-b border-white/[0.08] bg-[#03050c]/85 backdrop-blur-xl shadow-2xl py-3"
            : "border-b border-transparent bg-transparent py-5"
        }`}
      >
        <div className="mx-auto flex max-w-7xl items-center justify-between px-6">
          {/* Brand */}
          <div className="flex items-center gap-6">
            <Link href="/" className="group flex items-center gap-3">
              <div className="relative flex h-9 w-9 items-center justify-center rounded-xl border border-sky-500/30 bg-sky-500/10 transition group-hover:border-sky-400 group-hover:bg-sky-500/20 group-hover:shadow-[0_0_20px_rgba(56,189,248,0.3)]">
                <Shield className="h-5 w-5 text-sky-400 transition group-hover:scale-105" />
              </div>
              <div className="flex flex-col">
                <span className="font-mono text-base font-black tracking-wider text-white">
                  RTQ
                </span>
                <span className="text-[10px] font-semibold uppercase tracking-wider text-sky-400/70">
                  v{APP_INFO.version}
                </span>
              </div>
            </Link>

            {/* Live Verification Badge */}
            <Link
              href="/docs/evidence"
              className="hidden lg:inline-flex items-center gap-2 rounded-full border border-sky-500/20 bg-sky-500/5 px-3 py-1 text-[11px] font-mono text-sky-400 hover:border-sky-500/40 hover:bg-sky-500/10 transition"
              title="View verification evidence chains"
            >
              <span className="relative flex h-2 w-2">
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-75"></span>
                <span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-500"></span>
              </span>
              <span>CI: 12 Properties Tested (e179d2b)</span>
            </Link>
          </div>

          {/* Desktop Navigation */}
          <nav className="hidden items-center gap-1 md:flex">
            <Link
              href="/#pipeline"
              className="rounded-lg px-3.5 py-1.5 text-xs font-semibold uppercase tracking-wider text-white/60 transition hover:bg-white/5 hover:text-white"
            >
              Pipeline
            </Link>
            <Link
              href="/#invariants"
              className="rounded-lg px-3.5 py-1.5 text-xs font-semibold uppercase tracking-wider text-white/60 transition hover:bg-white/5 hover:text-white"
            >
              CI Properties
            </Link>
            <Link
              href="/#sandbox"
              className="rounded-lg px-3.5 py-1.5 text-xs font-semibold uppercase tracking-wider text-white/60 transition hover:bg-white/5 hover:text-white"
            >
              OS Sandboxes
            </Link>
            <Link
              href="/docs/evidence"
              className="rounded-lg px-3.5 py-1.5 text-xs font-semibold uppercase tracking-wider text-emerald-400 transition hover:bg-emerald-500/10 hover:text-emerald-300 font-mono"
            >
              Evidence
            </Link>
            <Link
              href="/docs/overview"
              className="flex items-center gap-1.5 rounded-lg px-3.5 py-1.5 text-xs font-semibold uppercase tracking-wider text-sky-400 transition hover:bg-sky-500/10 hover:text-sky-300"
            >
              <BookOpen size={14} />
              <span>Docs</span>
            </Link>
          </nav>

          {/* Action CTAs */}
          <div className="hidden items-center gap-3 sm:flex">
            {/* Search Trigger */}
            <button
              onClick={() => setSearchOpen(true)}
              className="group flex h-9 w-44 items-center gap-2 rounded-xl border border-white/10 bg-white/[0.03] px-3 text-xs text-white/40 transition hover:border-sky-500/40 hover:bg-white/[0.06] hover:text-white/80"
              title="Search documentation"
            >
              <Search size={14} className="transition group-hover:text-sky-400" />
              <span className="flex-1 text-left">Search docs...</span>
              <kbd className="rounded border border-white/10 bg-white/5 px-1.5 py-0.5 font-mono text-[10px] text-white/40">
                ⌘K
              </kbd>
            </button>

            {/* GitHub */}
            <a
              href={APP_INFO.repo}
              target="_blank"
              rel="noopener noreferrer"
              className="flex h-9 items-center gap-2 rounded-xl border border-white/10 bg-white/[0.04] px-3.5 text-xs font-semibold text-white/80 transition hover:border-white/20 hover:bg-white/10 hover:text-white"
            >
              <Github size={15} />
              <span>GitHub</span>
            </a>
          </div>

          {/* Mobile menu trigger */}
          <button
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            className="flex h-9 w-9 items-center justify-center rounded-xl border border-white/10 bg-white/5 text-white/60 md:hidden"
            aria-label="Toggle menu"
          >
            {mobileMenuOpen ? <X size={18} /> : <Menu size={18} />}
          </button>
        </div>

        {/* Mobile dropdown */}
        {mobileMenuOpen && (
          <div className="border-b border-white/10 bg-[#070914] px-6 py-6 md:hidden">
            <div className="flex flex-col gap-3">
              <button
                onClick={() => {
                  setMobileMenuOpen(false);
                  setSearchOpen(true);
                }}
                className="flex h-10 items-center gap-2 rounded-xl border border-white/10 bg-white/5 px-4 text-left text-xs text-white/50"
              >
                <Search size={14} /> Search documentation...
              </button>
              <Link
                href="/#pipeline"
                onClick={() => setMobileMenuOpen(false)}
                className="rounded-lg px-3 py-2 text-sm font-semibold text-white/70 hover:bg-white/5 hover:text-white"
              >
                Pipeline Simulator
              </Link>
              <Link
                href="/#invariants"
                onClick={() => setMobileMenuOpen(false)}
                className="rounded-lg px-3 py-2 text-sm font-semibold text-white/70 hover:bg-white/5 hover:text-white"
              >
                Security Invariants
              </Link>
              <Link
                href="/#sandbox"
                onClick={() => setMobileMenuOpen(false)}
                className="rounded-lg px-3 py-2 text-sm font-semibold text-white/70 hover:bg-white/5 hover:text-white"
              >
                Platform Sandbox
              </Link>
              <Link
                href="/#packages"
                onClick={() => setMobileMenuOpen(false)}
                className="rounded-lg px-3 py-2 text-sm font-semibold text-white/70 hover:bg-white/5 hover:text-white"
              >
                Packages
              </Link>
              <Link
                href="/docs/evidence"
                onClick={() => setMobileMenuOpen(false)}
                className="flex items-center justify-between rounded-lg bg-emerald-500/10 px-3 py-2 text-sm font-semibold text-emerald-400 font-mono"
              >
                <span>Security Evidence</span>
                <ArrowUpRight size={16} />
              </Link>
              <Link
                href="/docs/overview"
                onClick={() => setMobileMenuOpen(false)}
                className="flex items-center justify-between rounded-lg bg-sky-500/10 px-3 py-2 text-sm font-semibold text-sky-400"
              >
                <span>Documentation</span>
                <ArrowUpRight size={16} />
              </Link>
              <a
                href={APP_INFO.repo}
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center justify-between rounded-lg border border-white/10 bg-white/5 px-3 py-2 text-sm font-semibold text-white/80"
              >
                <span className="flex items-center gap-2">
                  <Github size={16} /> GitHub Repository
                </span>
                <ArrowUpRight size={16} />
              </a>
            </div>
          </div>
        )}
      </header>
    </>
  );
}
