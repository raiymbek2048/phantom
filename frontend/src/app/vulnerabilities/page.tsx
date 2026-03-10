"use client";

import { useState, useEffect, useCallback, useMemo, useRef } from "react";
import { useAuthStore } from "@/lib/store";
import LoginForm from "@/components/LoginForm";
import Sidebar from "@/components/Sidebar";
import {
  getVulnerabilities,
  getTargets,
  validateVulnerability,
  calculateCVSS,
  updateVulnStatus,
  bulkValidateVulnerabilities,
  bulkCalculateCVSS,
  getLifecycleInfo,
  transitionVuln,
} from "@/lib/api";
import { severityColor, cn } from "@/lib/utils";
import { useNotifications } from "@/lib/notifications";
import {
  ShieldAlert,
  Search,
  ExternalLink,
  CheckSquare,
  Square,
  MinusSquare,
  Download,
  Shield,
  Calculator,
  Ban,
  Loader2,
  ArrowUpDown,
  CheckCircle2,
  XCircle,
  Target,
  MoreHorizontal,
  ChevronRight,
} from "lucide-react";
import Link from "next/link";

function downloadFile(data: string, filename: string, type: string) {
  const blob = new Blob([data], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export default function VulnerabilitiesPage() {
  const { isLoggedIn, init } = useAuthStore();
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    init();
    setLoaded(true);
  }, [init]);
  if (!loaded) return null;
  if (!isLoggedIn) return <LoginForm />;

  return (
    <div className="flex">
      <Sidebar />
      <main className="ml-60 flex-1 min-h-screen p-6">
        <VulnsContent />
      </main>
    </div>
  );
}

type SortOption = "severity" | "newest" | "cvss" | "confidence";

const STATUS_CONFIG: Record<string, { label: string; bg: string; text: string; border: string; icon?: "check" | "x" }> = {
  new:             { label: "New",            bg: "bg-gray-800",         text: "text-gray-400",    border: "border-gray-700" },
  triaged:         { label: "Triaged",        bg: "bg-blue-900/50",      text: "text-blue-400",    border: "border-blue-800" },
  confirmed:       { label: "Confirmed",      bg: "bg-emerald-900/50",   text: "text-emerald-400", border: "border-emerald-800", icon: "check" },
  reported:        { label: "Reported",       bg: "bg-orange-900/50",    text: "text-orange-400",  border: "border-orange-800" },
  fixed:           { label: "Fixed",          bg: "bg-green-900/50",     text: "text-green-400",   border: "border-green-800" },
  verified:        { label: "Verified",       bg: "bg-green-900/50",     text: "text-green-300",   border: "border-green-700", icon: "check" },
  false_positive:  { label: "False Positive", bg: "bg-red-900/50",       text: "text-red-400",     border: "border-red-800", icon: "x" },
  bounty_received: { label: "Bounty",         bg: "bg-yellow-900/50",    text: "text-yellow-400",  border: "border-yellow-800" },
};

const STATUS_FILTER_ACTIVE: Record<string, string> = {
  all:             "bg-gray-600 text-white",
  new:             "bg-gray-600 text-white",
  triaged:         "bg-blue-700 text-white",
  confirmed:       "bg-emerald-700 text-white",
  reported:        "bg-orange-700 text-white",
  fixed:           "bg-green-700 text-white",
  verified:        "bg-green-700 text-white",
  false_positive:  "bg-red-700 text-white",
  bounty_received: "bg-yellow-700 text-white",
};

const VULN_TRANSITIONS: Record<string, string[]> = {
  new:             ["triaged", "false_positive", "confirmed"],
  triaged:         ["confirmed", "false_positive"],
  confirmed:       ["reported", "fixed", "false_positive"],
  reported:        ["fixed", "bounty_received"],
  fixed:           ["verified", "confirmed"],
  verified:        [],
  bounty_received: ["verified"],
  false_positive:  ["new"],
};

const ALL_STATUSES = ["all", "new", "triaged", "confirmed", "reported", "fixed", "verified", "bounty_received", "false_positive"];

function StatusBadge({ status }: { status: string }) {
  const cfg = STATUS_CONFIG[status] || STATUS_CONFIG.new;
  return (
    <span className={cn("flex items-center gap-1 text-[10px] px-1.5 py-0.5 rounded border flex-shrink-0", cfg.bg, cfg.text, cfg.border)}>
      {cfg.icon === "check" && <CheckCircle2 className="w-3 h-3" />}
      {cfg.icon === "x" && <XCircle className="w-3 h-3" />}
      {cfg.label}
    </span>
  );
}

function TransitionMenu({ vulnId, status, onTransitioned }: { vulnId: string; status: string; onTransitioned: () => void }) {
  const [open, setOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  const transitions = VULN_TRANSITIONS[status] || [];

  useEffect(() => {
    function handleClick(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    }
    if (open) document.addEventListener("mousedown", handleClick);
    return () => document.removeEventListener("mousedown", handleClick);
  }, [open]);

  if (transitions.length === 0) return null;

  const notify = useNotifications((s) => s.add);
  async function doTransition(newStatus: string) {
    setLoading(true);
    try {
      await transitionVuln(vulnId, newStatus);
      onTransitioned();
    } catch (e: any) {
      notify({ type: "error", title: "Transition failed", message: e?.message });
    }
    setLoading(false);
    setOpen(false);
  }

  return (
    <div ref={ref} className="relative flex-shrink-0">
      <button
        onClick={(e) => { e.preventDefault(); e.stopPropagation(); setOpen(!open); }}
        className="p-1 rounded hover:bg-gray-700 text-gray-600 hover:text-gray-300 transition opacity-0 group-hover:opacity-100"
        title="Transition status"
      >
        {loading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <MoreHorizontal className="w-3.5 h-3.5" />}
      </button>
      {open && (
        <div className="absolute right-0 top-full mt-1 z-50 bg-gray-900 border border-gray-700 rounded-lg shadow-xl py-1 min-w-[160px]">
          <div className="px-3 py-1.5 text-[10px] text-gray-500 uppercase tracking-wider">Transition to</div>
          {transitions.map((t) => {
            const cfg = STATUS_CONFIG[t] || STATUS_CONFIG.new;
            return (
              <button
                key={t}
                onClick={(e) => { e.preventDefault(); e.stopPropagation(); doTransition(t); }}
                disabled={loading}
                className="w-full flex items-center gap-2 px-3 py-1.5 text-xs hover:bg-gray-800 transition text-left disabled:opacity-50"
              >
                <ChevronRight className={cn("w-3 h-3", cfg.text)} />
                <span className={cfg.text}>{cfg.label}</span>
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}

function VulnsContent() {
  const [vulns, setVulns] = useState<any[]>([]);
  const [targets, setTargets] = useState<any[]>([]);
  const [sevFilter, setSevFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");
  const [targetFilter, setTargetFilter] = useState("all");
  const [search, setSearch] = useState("");
  const [sortBy, setSortBy] = useState<SortOption>("severity");

  // Bulk selection
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());

  // Bulk operation progress
  const [bulkProgress, setBulkProgress] = useState<{
    running: boolean;
    current: number;
    total: number;
    label: string;
  }>({ running: false, current: 0, total: 0, label: "" });

  const [loading, setLoading] = useState(true);
  const notify = useNotifications((s) => s.add);

  const load = useCallback(async () => {
    try {
      const [v, t] = await Promise.all([getVulnerabilities(), getTargets()]);
      setVulns(v);
      setTargets(t);
    } catch (e: any) {
      notify({ type: "error", title: "Failed to load vulnerabilities", message: e?.message });
    } finally {
      setLoading(false);
    }
  }, [notify]);

  useEffect(() => {
    load();
  }, [load]);

  const getTarget = (id: string) => targets.find((t: any) => t.id === id);

  // Unique targets that have vulns
  const vulnTargets = useMemo(() => {
    const ids = new Set(vulns.map((v: any) => v.target_id));
    return targets.filter((t: any) => ids.has(t.id));
  }, [vulns, targets]);

  const filtered = useMemo(() => {
    let result = vulns;
    if (sevFilter !== "all")
      result = result.filter((v: any) => v.severity === sevFilter);
    if (statusFilter !== "all")
      result = result.filter((v: any) => (v.status || "new") === statusFilter);
    if (targetFilter !== "all")
      result = result.filter((v: any) => v.target_id === targetFilter);
    if (search) {
      const q = search.toLowerCase();
      result = result.filter(
        (v: any) =>
          (v.title || "").toLowerCase().includes(q) ||
          (v.url || "").toLowerCase().includes(q) ||
          (v.vuln_type || "").toLowerCase().includes(q) ||
          (v.payload_used || "").toLowerCase().includes(q)
      );
    }

    const sevOrder: Record<string, number> = {
      critical: 0,
      high: 1,
      medium: 2,
      low: 3,
      info: 4,
    };

    switch (sortBy) {
      case "severity":
        return [...result].sort(
          (a: any, b: any) =>
            (sevOrder[a.severity] ?? 5) - (sevOrder[b.severity] ?? 5)
        );
      case "newest":
        return [...result].sort(
          (a: any, b: any) =>
            new Date(b.created_at || 0).getTime() -
            new Date(a.created_at || 0).getTime()
        );
      case "cvss":
        return [...result].sort((a: any, b: any) => {
          const aScore = a.ai_analysis?.cvss?.cvss_score ?? 0;
          const bScore = b.ai_analysis?.cvss?.cvss_score ?? 0;
          return bScore - aScore;
        });
      case "confidence":
        return [...result].sort(
          (a: any, b: any) =>
            (b.ai_confidence || 0) - (a.ai_confidence || 0)
        );
      default:
        return result;
    }
  }, [vulns, sevFilter, statusFilter, targetFilter, search, sortBy]);

  const severityCounts: Record<string, number> = {};
  vulns.forEach((v: any) => {
    severityCounts[v.severity] = (severityCounts[v.severity] || 0) + 1;
  });

  const statusCounts: Record<string, number> = {};
  vulns.forEach((v: any) => {
    const st = v.status || "new";
    statusCounts[st] = (statusCounts[st] || 0) + 1;
  });

  // Select all logic
  const allFilteredSelected =
    filtered.length > 0 &&
    filtered.every((v: any) => selectedIds.has(v.id));
  const someFilteredSelected =
    filtered.some((v: any) => selectedIds.has(v.id)) && !allFilteredSelected;

  function toggleSelectAll() {
    if (allFilteredSelected) {
      setSelectedIds((prev) => {
        const next = new Set(prev);
        filtered.forEach((v: any) => next.delete(v.id));
        return next;
      });
    } else {
      setSelectedIds((prev) => {
        const next = new Set(prev);
        filtered.forEach((v: any) => next.add(v.id));
        return next;
      });
    }
  }

  function toggleSelect(id: string) {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  const selectedVulns = useMemo(
    () => vulns.filter((v: any) => selectedIds.has(v.id)),
    [vulns, selectedIds]
  );

  // Bulk operations — sequential processing with progress
  async function bulkValidate() {
    const ids = Array.from(selectedIds);
    setBulkProgress({ running: true, current: 0, total: ids.length, label: "Validating" });
    let failed = 0;
    for (let i = 0; i < ids.length; i++) {
      try {
        await validateVulnerability(ids[i]);
      } catch { failed++; }
      setBulkProgress((p) => ({ ...p, current: i + 1 }));
    }
    setBulkProgress({ running: false, current: 0, total: 0, label: "" });
    if (failed) notify({ type: "warning", title: `${failed}/${ids.length} validations failed` });
    else notify({ type: "success", title: `Validated ${ids.length} vulns` });
    setSelectedIds(new Set());
    await load();
  }

  async function bulkCVSS() {
    const ids = Array.from(selectedIds);
    setBulkProgress({ running: true, current: 0, total: ids.length, label: "Calculating CVSS" });
    let failed = 0;
    for (let i = 0; i < ids.length; i++) {
      try {
        await calculateCVSS(ids[i]);
      } catch { failed++; }
      setBulkProgress((p) => ({ ...p, current: i + 1 }));
    }
    setBulkProgress({ running: false, current: 0, total: 0, label: "" });
    if (failed) notify({ type: "warning", title: `${failed}/${ids.length} CVSS calculations failed` });
    else notify({ type: "success", title: `CVSS calculated for ${ids.length} vulns` });
    setSelectedIds(new Set());
    await load();
  }

  async function bulkMarkFalsePositive() {
    const ids = Array.from(selectedIds);
    setBulkProgress({ running: true, current: 0, total: ids.length, label: "Marking False Positive" });
    let failed = 0;
    for (let i = 0; i < ids.length; i++) {
      try {
        await updateVulnStatus(ids[i], "false_positive");
      } catch { failed++; }
      setBulkProgress((p) => ({ ...p, current: i + 1 }));
    }
    setBulkProgress({ running: false, current: 0, total: 0, label: "" });
    setSelectedIds(new Set());
    await load();
  }

  function exportSelectedJSON() {
    const data = JSON.stringify(selectedVulns, null, 2);
    downloadFile(data, "vulnerabilities.json", "application/json");
  }

  function exportSelectedCSV() {
    if (selectedVulns.length === 0) return;
    const headers = [
      "id", "title", "severity", "vuln_type", "url",
      "parameter", "method", "ai_confidence", "status", "description",
    ];
    const rows = selectedVulns.map((v: any) =>
      headers
        .map((h) => {
          const val = v[h] ?? "";
          const str = String(val).replace(/"/g, '""');
          return `"${str}"`;
        })
        .join(",")
    );
    const csv = [headers.join(","), ...rows].join("\n");
    downloadFile(csv, "vulnerabilities.csv", "text/csv");
  }

  // Bulk target actions
  async function validateAllForTarget() {
    if (targetFilter === "all") return;
    setBulkProgress({ running: true, current: 0, total: 1, label: "Validating all for target" });
    try {
      await bulkValidateVulnerabilities(targetFilter);
      notify({ type: "success", title: "Validation started for target" });
    } catch (e: any) {
      notify({ type: "error", title: "Bulk validation failed", message: e?.message });
    }
    setBulkProgress({ running: false, current: 0, total: 0, label: "" });
    await load();
  }

  async function cvssAllForTarget() {
    if (targetFilter === "all") return;
    setBulkProgress({ running: true, current: 0, total: 1, label: "Calculating CVSS for target" });
    try {
      await bulkCalculateCVSS(targetFilter);
      notify({ type: "success", title: "CVSS calculation started for target" });
    } catch (e: any) {
      notify({ type: "error", title: "Bulk CVSS failed", message: e?.message });
    }
    setBulkProgress({ running: false, current: 0, total: 0, label: "" });
    await load();
  }

  const sortOptions: { value: SortOption; label: string }[] = [
    { value: "severity", label: "Severity" },
    { value: "newest", label: "Newest first" },
    { value: "cvss", label: "CVSS Score (highest)" },
    { value: "confidence", label: "AI Confidence" },
  ];

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="w-6 h-6 text-red-500 animate-spin" />
        <span className="ml-2 text-gray-400">Loading vulnerabilities...</span>
      </div>
    );
  }

  return (
    <div>
      <div className="mb-6">
        <h1 className="text-xl font-bold text-white">Vulnerabilities</h1>
        <p className="text-sm text-gray-500">
          {vulns.length} total findings across {vulnTargets.length} targets
        </p>
      </div>

      {/* Filters Row */}
      <div className="flex items-center gap-3 mb-3 flex-wrap">
        {/* Severity Filter */}
        <div className="flex gap-1.5">
          {["all", "critical", "high", "medium", "low"].map((s) => (
            <button
              key={s}
              onClick={() => setSevFilter(s)}
              className={cn(
                "px-2.5 py-1.5 rounded-lg text-xs font-medium transition capitalize",
                sevFilter === s
                  ? "bg-red-600 text-white"
                  : "bg-gray-800 text-gray-400 hover:bg-gray-700"
              )}
            >
              {s}{" "}
              {s !== "all" && severityCounts[s] ? `(${severityCounts[s]})` : ""}
            </button>
          ))}
        </div>

        {/* Target Filter */}
        {vulnTargets.length > 1 && (
          <select
            value={targetFilter}
            onChange={(e) => setTargetFilter(e.target.value)}
            className="bg-gray-800 border border-gray-700 rounded-lg px-2.5 py-1.5 text-xs text-white"
          >
            <option value="all">All targets</option>
            {vulnTargets.map((t: any) => (
              <option key={t.id} value={t.id}>
                {t.domain}
              </option>
            ))}
          </select>
        )}

        {/* Sort Dropdown */}
        <div className="flex items-center gap-1.5">
          <ArrowUpDown className="w-3.5 h-3.5 text-gray-500" />
          <select
            value={sortBy}
            onChange={(e) => setSortBy(e.target.value as SortOption)}
            className="bg-gray-800 border border-gray-700 rounded-lg px-2.5 py-1.5 text-xs text-white"
          >
            {sortOptions.map((opt) => (
              <option key={opt.value} value={opt.value}>
                {opt.label}
              </option>
            ))}
          </select>
        </div>

        {/* Search */}
        <div className="relative ml-auto">
          <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-gray-600" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search vulns..."
            className="bg-gray-800 border border-gray-700 rounded-lg pl-8 pr-3 py-1.5 text-xs text-white placeholder-gray-600 w-48 focus:outline-none focus:border-red-500"
          />
        </div>
      </div>

      {/* Status Filter Row */}
      <div className="flex items-center gap-3 mb-4 flex-wrap">
        <span className="text-xs text-gray-500">Status:</span>
        <div className="flex gap-1.5 flex-wrap">
          {ALL_STATUSES.map((s) => {
            const inactiveStyle = "bg-gray-800 text-gray-400 hover:bg-gray-700";
            const label = s === "all" ? "All" : (STATUS_CONFIG[s]?.label || s);
            return (
              <button
                key={s}
                onClick={() => setStatusFilter(s)}
                className={cn(
                  "px-2.5 py-1.5 rounded-lg text-xs font-medium transition",
                  statusFilter === s ? (STATUS_FILTER_ACTIVE[s] || "bg-gray-600 text-white") : inactiveStyle
                )}
              >
                {label}{" "}
                {s !== "all" && statusCounts[s] ? `(${statusCounts[s]})` : ""}
              </button>
            );
          })}
        </div>

        {/* Bulk Target Actions */}
        {targetFilter !== "all" && (
          <div className="flex gap-1.5 ml-auto">
            <button
              onClick={validateAllForTarget}
              disabled={bulkProgress.running}
              className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium bg-blue-900/50 text-blue-400 border border-blue-800 hover:bg-blue-900 transition disabled:opacity-50"
            >
              <Target className="w-3 h-3" />
              Validate All for Target
            </button>
            <button
              onClick={cvssAllForTarget}
              disabled={bulkProgress.running}
              className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium bg-purple-900/50 text-purple-400 border border-purple-800 hover:bg-purple-900 transition disabled:opacity-50"
            >
              <Calculator className="w-3 h-3" />
              CVSS All for Target
            </button>
          </div>
        )}
      </div>

      {/* Progress Bar */}
      {bulkProgress.running && (
        <div className="mb-4 bg-gray-900 rounded-xl border border-gray-800 p-3">
          <div className="flex items-center gap-3 mb-2">
            <Loader2 className="w-4 h-4 text-blue-400 animate-spin" />
            <span className="text-sm text-white font-medium">
              {bulkProgress.label}...{" "}
              {bulkProgress.total > 1
                ? `Processing ${bulkProgress.current}/${bulkProgress.total}`
                : ""}
            </span>
          </div>
          {bulkProgress.total > 1 && (
            <div className="w-full bg-gray-800 rounded-full h-1.5">
              <div
                className="bg-blue-500 h-1.5 rounded-full transition-all duration-300"
                style={{
                  width: `${(bulkProgress.current / bulkProgress.total) * 100}%`,
                }}
              />
            </div>
          )}
        </div>
      )}

      {/* Bulk Actions Toolbar */}
      {selectedIds.size > 0 && (
        <div className="mb-4 bg-gray-900 rounded-xl border border-blue-800/50 p-3 flex items-center gap-3 flex-wrap">
          <span className="text-xs text-blue-400 font-medium">
            {selectedIds.size} selected
          </span>
          <div className="h-4 w-px bg-gray-700" />
          <button
            onClick={bulkValidate}
            disabled={bulkProgress.running}
            className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium bg-emerald-900/50 text-emerald-400 border border-emerald-800 hover:bg-emerald-900 transition disabled:opacity-50"
          >
            <Shield className="w-3 h-3" />
            Validate Selected
          </button>
          <button
            onClick={bulkCVSS}
            disabled={bulkProgress.running}
            className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium bg-purple-900/50 text-purple-400 border border-purple-800 hover:bg-purple-900 transition disabled:opacity-50"
          >
            <Calculator className="w-3 h-3" />
            Calculate CVSS
          </button>
          <button
            onClick={exportSelectedJSON}
            className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium bg-gray-800 text-gray-300 border border-gray-700 hover:bg-gray-700 transition"
          >
            <Download className="w-3 h-3" />
            Export JSON
          </button>
          <button
            onClick={exportSelectedCSV}
            className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium bg-gray-800 text-gray-300 border border-gray-700 hover:bg-gray-700 transition"
          >
            <Download className="w-3 h-3" />
            Export CSV
          </button>
          <button
            onClick={bulkMarkFalsePositive}
            disabled={bulkProgress.running}
            className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium bg-red-900/50 text-red-400 border border-red-800 hover:bg-red-900 transition disabled:opacity-50"
          >
            <Ban className="w-3 h-3" />
            Mark False Positive
          </button>
          <button
            onClick={() => setSelectedIds(new Set())}
            className="ml-auto text-xs text-gray-500 hover:text-gray-300 transition"
          >
            Clear selection
          </button>
        </div>
      )}

      {filtered.length === 0 ? (
        <div className="text-center py-20 text-gray-600">
          <ShieldAlert className="w-12 h-12 mx-auto mb-3 opacity-30" />
          <p>
            {vulns.length === 0
              ? "No vulnerabilities found yet."
              : "No vulnerabilities match filters."}
          </p>
        </div>
      ) : (
        <div className="space-y-2">
          {/* Select All Header */}
          <div className="flex items-center gap-3 px-4 py-2">
            <button
              onClick={toggleSelectAll}
              className="text-gray-500 hover:text-gray-300 transition"
            >
              {allFilteredSelected ? (
                <CheckSquare className="w-4 h-4 text-blue-400" />
              ) : someFilteredSelected ? (
                <MinusSquare className="w-4 h-4 text-blue-400" />
              ) : (
                <Square className="w-4 h-4" />
              )}
            </button>
            <span className="text-xs text-gray-500">
              {allFilteredSelected
                ? "Deselect all"
                : `Select all ${filtered.length} vulnerabilities`}
            </span>
          </div>

          {filtered.map((v: any) => {
            const target = getTarget(v.target_id);
            const isSelected = selectedIds.has(v.id);
            const cvssScore = v.ai_analysis?.cvss?.cvss_score;
            const status = v.status || "new";
            const source = v.source || "scanner";
            const isFP = status === "false_positive";

            return (
              <div
                key={v.id}
                className={cn(
                  "bg-gray-900 rounded-xl border p-4 hover:border-gray-700 transition group",
                  isSelected ? "border-blue-700/60" : "border-gray-800"
                )}
              >
                <div className="flex items-center gap-3">
                  {/* Checkbox */}
                  <button
                    onClick={(e) => {
                      e.preventDefault();
                      e.stopPropagation();
                      toggleSelect(v.id);
                    }}
                    className="text-gray-500 hover:text-gray-300 transition flex-shrink-0"
                  >
                    {isSelected ? (
                      <CheckSquare className="w-4 h-4 text-blue-400" />
                    ) : (
                      <Square className="w-4 h-4" />
                    )}
                  </button>

                  {/* Severity Badge */}
                  <span
                    className={cn(
                      "text-[10px] px-2 py-0.5 rounded border font-bold uppercase w-[70px] text-center flex-shrink-0",
                      severityColor(v.severity)
                    )}
                  >
                    {v.severity}
                  </span>

                  {/* Title as Link */}
                  <Link
                    href={`/vulnerabilities/${v.id}`}
                    className={cn(
                      "font-medium flex-1 truncate hover:underline",
                      isFP
                        ? "line-through text-gray-500"
                        : "text-white"
                    )}
                  >
                    {v.title}
                  </Link>

                  {/* CVSS Badge */}
                  {cvssScore != null && (
                    <span
                      className={cn(
                        "text-[10px] px-1.5 py-0.5 rounded font-bold flex-shrink-0",
                        cvssScore >= 9
                          ? "bg-red-900/60 text-red-300 border border-red-800"
                          : cvssScore >= 7
                          ? "bg-orange-900/60 text-orange-300 border border-orange-800"
                          : cvssScore >= 4
                          ? "bg-yellow-900/60 text-yellow-300 border border-yellow-800"
                          : "bg-gray-800 text-gray-400 border border-gray-700"
                      )}
                    >
                      CVSS {cvssScore.toFixed(1)}
                    </span>
                  )}

                  {/* Lifecycle Status Badge */}
                  <StatusBadge status={status} />

                  {/* Lifecycle Transition Menu */}
                  <TransitionMenu vulnId={v.id} status={status} onTransitioned={load} />

                  {/* Source Badge */}
                  <span
                    className={cn(
                      "text-[10px] px-1.5 py-0.5 rounded border flex-shrink-0",
                      source === "claude_collab"
                        ? "bg-violet-900/50 text-violet-400 border-violet-800"
                        : source === "manual"
                        ? "bg-cyan-900/50 text-cyan-400 border-cyan-800"
                        : "bg-gray-800 text-gray-500 border-gray-700"
                    )}
                  >
                    {source === "claude_collab"
                      ? "AI"
                      : source === "manual"
                      ? "Manual"
                      : "Scanner"}
                  </span>

                  {/* Target Domain */}
                  <span className="text-xs text-gray-600 flex-shrink-0">
                    {target?.domain}
                  </span>

                  {/* Vuln Type */}
                  <span className="text-[10px] text-gray-700 font-mono bg-gray-800 px-1.5 py-0.5 rounded flex-shrink-0">
                    {v.vuln_type}
                  </span>

                  {/* Detail Link Arrow */}
                  <Link href={`/vulnerabilities/${v.id}`}>
                    <ExternalLink className="w-3.5 h-3.5 text-gray-700 group-hover:text-gray-400 transition flex-shrink-0" />
                  </Link>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
