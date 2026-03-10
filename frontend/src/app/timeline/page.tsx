"use client";

import { useState, useEffect, useCallback } from "react";
import { useAuthStore } from "@/lib/store";
import LoginForm from "@/components/LoginForm";
import Sidebar from "@/components/Sidebar";
import { getTargets, getScans, compareScans, getComparisonReport, getTargetChanges } from "@/lib/api";
import { timeAgo, statusColor, cn, parseUTC } from "@/lib/utils";
import {
  GitCompareArrows,
  ChevronDown,
  ChevronRight,
  Clock,
  Shield,
  Globe,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Minus,
  Plus,
  X,
  Loader2,
  Target,
  Activity,
  FileText,
} from "lucide-react";

export default function TimelinePage() {
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
        <TimelineContent />
      </main>
    </div>
  );
}

const STATUS_BADGES: Record<string, string> = {
  completed: "bg-green-950/50 text-green-400 border-green-900/50",
  running: "bg-blue-950/50 text-blue-400 border-blue-900/50",
  pending: "bg-yellow-950/50 text-yellow-400 border-yellow-900/50",
  failed: "bg-red-950/50 text-red-400 border-red-900/50",
  stopped: "bg-gray-800/50 text-gray-400 border-gray-700/50",
};

const TYPE_BADGES: Record<string, string> = {
  full: "bg-purple-950/50 text-purple-400 border-purple-900/50",
  quick: "bg-green-950/50 text-green-400 border-green-900/50",
  stealth: "bg-yellow-950/50 text-yellow-400 border-yellow-900/50",
  recon: "bg-blue-950/50 text-blue-400 border-blue-900/50",
};

interface DiffSummary {
  newVulns: number;
  fixedVulns: number;
  newEndpoints: number;
}

function computeQuickDiff(newer: any, older: any): DiffSummary {
  const nv = newer.vulns_found ?? newer.vulnerabilities_count ?? 0;
  const ov = older.vulns_found ?? older.vulnerabilities_count ?? 0;
  const ne = newer.endpoints_found ?? newer.endpoints_count ?? 0;
  const oe = older.endpoints_found ?? older.endpoints_count ?? 0;
  const vulnDiff = nv - ov;
  return {
    newVulns: vulnDiff > 0 ? vulnDiff : 0,
    fixedVulns: vulnDiff < 0 ? Math.abs(vulnDiff) : 0,
    newEndpoints: ne - oe,
  };
}

function TimelineContent() {
  const [targets, setTargets] = useState<any[]>([]);
  const [allScans, setAllScans] = useState<any[]>([]);
  const [selectedTarget, setSelectedTarget] = useState<string>("");
  const [loading, setLoading] = useState(true);
  const [compareMode, setCompareMode] = useState(false);
  const [selectedForCompare, setSelectedForCompare] = useState<string[]>([]);
  const [comparisonResult, setComparisonResult] = useState<any>(null);
  const [comparingLoading, setComparingLoading] = useState(false);
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const [reportHtml, setReportHtml] = useState<string | null>(null);
  const [reportLoading, setReportLoading] = useState(false);

  const load = useCallback(async () => {
    try {
      const [t, s] = await Promise.all([getTargets(), getScans()]);
      setTargets(t);
      setAllScans(s);
    } catch {
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const filteredScans = allScans
    .filter((s: any) => !selectedTarget || s.target_id === selectedTarget)
    .sort((a: any, b: any) => {
      const da = a.created_at ? parseUTC(a.created_at).getTime() : 0;
      const db = b.created_at ? parseUTC(b.created_at).getTime() : 0;
      return db - da;
    });

  const selectedTargetObj = targets.find((t: any) => t.id === selectedTarget);

  function toggleCompareSelect(scanId: string) {
    setSelectedForCompare((prev) => {
      if (prev.includes(scanId)) return prev.filter((id) => id !== scanId);
      if (prev.length >= 2) return [prev[1], scanId];
      return [...prev, scanId];
    });
  }

  async function runComparison() {
    if (selectedForCompare.length !== 2) return;
    setComparingLoading(true);
    try {
      const result = await compareScans(selectedForCompare[0], selectedForCompare[1]);
      setComparisonResult(result);
    } catch {
      setComparisonResult(null);
    } finally {
      setComparingLoading(false);
    }
  }

  function closeComparison() {
    setComparisonResult(null);
    setCompareMode(false);
    setSelectedForCompare([]);
  }

  async function generateReport() {
    if (selectedForCompare.length !== 2) return;
    setReportLoading(true);
    try {
      const html = await getComparisonReport(selectedForCompare[0], selectedForCompare[1]);
      setReportHtml(html);
    } catch {
      setReportHtml(null);
    } finally {
      setReportLoading(false);
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-96">
        <Loader2 className="w-8 h-8 text-red-500 animate-spin" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-red-950/50 rounded-lg border border-red-900/30">
            <GitCompareArrows className="w-6 h-6 text-red-500" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white">Scan Comparison Timeline</h1>
            <p className="text-sm text-gray-500">Track changes between scans over time</p>
          </div>
        </div>
        <button
          onClick={() => {
            setCompareMode(!compareMode);
            if (compareMode) {
              setSelectedForCompare([]);
              setComparisonResult(null);
            }
          }}
          className={cn(
            "px-4 py-2 rounded-lg text-sm font-medium flex items-center gap-2 transition-colors",
            compareMode
              ? "bg-red-600 text-white hover:bg-red-700"
              : "bg-gray-800 text-gray-300 hover:bg-gray-700 border border-gray-700"
          )}
        >
          <GitCompareArrows className="w-4 h-4" />
          {compareMode ? "Cancel Compare" : "Compare Scans"}
        </button>
      </div>

      {/* Target Selector */}
      <div className="relative">
        <button
          onClick={() => setDropdownOpen(!dropdownOpen)}
          className="w-full md:w-96 flex items-center justify-between px-4 py-3 bg-gray-900 border border-gray-800 rounded-lg text-left hover:border-gray-700 transition-colors"
        >
          <div className="flex items-center gap-3">
            <Target className="w-4 h-4 text-red-500" />
            <span className={selectedTarget ? "text-white" : "text-gray-500"}>
              {selectedTargetObj ? selectedTargetObj.domain : "All targets"}
            </span>
          </div>
          <ChevronDown
            className={cn(
              "w-4 h-4 text-gray-500 transition-transform",
              dropdownOpen && "rotate-180"
            )}
          />
        </button>
        {dropdownOpen && (
          <div className="absolute z-20 mt-1 w-full md:w-96 bg-gray-900 border border-gray-800 rounded-lg shadow-xl overflow-hidden">
            <button
              onClick={() => {
                setSelectedTarget("");
                setDropdownOpen(false);
              }}
              className={cn(
                "w-full px-4 py-3 text-left hover:bg-gray-800 transition-colors flex items-center gap-3",
                !selectedTarget ? "text-red-400 bg-gray-800/50" : "text-gray-300"
              )}
            >
              <Globe className="w-4 h-4" />
              All targets
            </button>
            {targets.map((t: any) => (
              <button
                key={t.id}
                onClick={() => {
                  setSelectedTarget(t.id);
                  setDropdownOpen(false);
                  setComparisonResult(null);
                  setSelectedForCompare([]);
                }}
                className={cn(
                  "w-full px-4 py-3 text-left hover:bg-gray-800 transition-colors flex items-center gap-3",
                  selectedTarget === t.id ? "text-red-400 bg-gray-800/50" : "text-gray-300"
                )}
              >
                <Target className="w-4 h-4" />
                {t.domain}
              </button>
            ))}
          </div>
        )}
      </div>

      {/* Compare bar */}
      {compareMode && (
        <div className="bg-gray-900 border border-red-900/30 rounded-lg p-4 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <span className="text-sm text-gray-400">
              Select 2 scans to compare ({selectedForCompare.length}/2 selected)
            </span>
            {selectedForCompare.length === 2 && (
              <button
                onClick={runComparison}
                disabled={comparingLoading}
                className="px-4 py-1.5 bg-red-600 text-white text-sm rounded-lg hover:bg-red-700 transition-colors flex items-center gap-2 disabled:opacity-50"
              >
                {comparingLoading ? (
                  <Loader2 className="w-4 h-4 animate-spin" />
                ) : (
                  <GitCompareArrows className="w-4 h-4" />
                )}
                Compare
              </button>
            )}
          </div>
          {selectedForCompare.length > 0 && (
            <button
              onClick={() => setSelectedForCompare([])}
              className="text-sm text-gray-500 hover:text-gray-300"
            >
              Clear selection
            </button>
          )}
        </div>
      )}

      {/* Main layout: timeline + comparison panel */}
      <div className={cn("flex gap-6", comparisonResult && "flex-col lg:flex-row")}>
        {/* Timeline */}
        <div className={cn("flex-1 space-y-0", comparisonResult && "lg:w-1/2")}>
          {filteredScans.length === 0 ? (
            <div className="text-center py-16 text-gray-500">
              <Activity className="w-12 h-12 mx-auto mb-3 opacity-30" />
              <p>No scans found{selectedTarget ? " for this target" : ""}</p>
            </div>
          ) : (
            filteredScans.map((scan: any, idx: number) => {
              const isLast = idx === filteredScans.length - 1;
              const prevScan = idx < filteredScans.length - 1 ? filteredScans[idx + 1] : null;
              const diff = prevScan ? computeQuickDiff(scan, prevScan) : null;
              const isSelected = selectedForCompare.includes(scan.id);
              const vulns = scan.vulns_found ?? scan.vulnerabilities_count ?? 0;
              const endpoints = scan.endpoints_found ?? scan.endpoints_count ?? 0;
              const target = targets.find((t: any) => t.id === scan.target_id);
              const scanDate = scan.created_at ? parseUTC(scan.created_at) : null;
              const statusCls =
                STATUS_BADGES[scan.status] || "bg-gray-800/50 text-gray-400 border-gray-700/50";
              const typeCls =
                TYPE_BADGES[scan.scan_type] || "bg-gray-800/50 text-gray-400 border-gray-700/50";

              return (
                <div key={scan.id}>
                  {/* Scan node */}
                  <div className="flex gap-4">
                    {/* Timeline line + dot */}
                    <div className="flex flex-col items-center w-8 flex-shrink-0">
                      <div
                        className={cn(
                          "w-4 h-4 rounded-full border-2 flex-shrink-0 mt-5 transition-all",
                          isSelected
                            ? "bg-red-500 border-red-400 ring-2 ring-red-500/30"
                            : scan.status === "completed"
                            ? "bg-green-500 border-green-400"
                            : scan.status === "running"
                            ? "bg-blue-500 border-blue-400 animate-pulse"
                            : scan.status === "failed"
                            ? "bg-red-500 border-red-400"
                            : "bg-gray-600 border-gray-500"
                        )}
                      />
                      {!isLast && <div className="w-0.5 flex-1 bg-gray-800 min-h-[2rem]" />}
                    </div>

                    {/* Card */}
                    <div
                      className={cn(
                        "flex-1 bg-gray-900 border rounded-lg p-4 mb-2 transition-all cursor-pointer",
                        isSelected
                          ? "border-red-500/50 ring-1 ring-red-500/20"
                          : "border-gray-800 hover:border-gray-700"
                      )}
                      onClick={() => compareMode && toggleCompareSelect(scan.id)}
                    >
                      <div className="flex items-start justify-between">
                        <div className="space-y-2">
                          <div className="flex items-center gap-2 flex-wrap">
                            {scanDate && (
                              <span className="text-white font-medium">
                                {scanDate.toLocaleDateString("en-US", {
                                  month: "short",
                                  day: "numeric",
                                  year: "numeric",
                                })}
                              </span>
                            )}
                            <span className="text-gray-600">|</span>
                            <span className="text-gray-500 text-sm">
                              {scanDate
                                ? scanDate.toLocaleTimeString("en-US", {
                                    hour: "2-digit",
                                    minute: "2-digit",
                                  })
                                : ""}
                            </span>
                            {scanDate && (
                              <span className="text-gray-600 text-xs">
                                ({timeAgo(scanDate.toISOString())})
                              </span>
                            )}
                          </div>
                          <div className="flex items-center gap-2 flex-wrap">
                            <span
                              className={cn(
                                "text-xs px-2 py-0.5 rounded border font-medium uppercase",
                                typeCls
                              )}
                            >
                              {scan.scan_type || "full"}
                            </span>
                            <span
                              className={cn(
                                "text-xs px-2 py-0.5 rounded border font-medium capitalize",
                                statusCls
                              )}
                            >
                              {scan.status}
                            </span>
                            {!selectedTarget && target && (
                              <span className="text-xs text-gray-500 bg-gray-800 px-2 py-0.5 rounded">
                                {target.domain}
                              </span>
                            )}
                          </div>
                        </div>

                        <div className="flex items-center gap-4 text-right">
                          <div>
                            <div className="flex items-center gap-1.5 justify-end">
                              <AlertTriangle className="w-3.5 h-3.5 text-red-400" />
                              <span className="text-white font-semibold">{vulns}</span>
                            </div>
                            <span className="text-xs text-gray-500">vulns</span>
                          </div>
                          <div>
                            <div className="flex items-center gap-1.5 justify-end">
                              <Globe className="w-3.5 h-3.5 text-blue-400" />
                              <span className="text-white font-semibold">{endpoints}</span>
                            </div>
                            <span className="text-xs text-gray-500">endpoints</span>
                          </div>
                          {compareMode && (
                            <div
                              className={cn(
                                "w-5 h-5 rounded border-2 flex items-center justify-center transition-colors",
                                isSelected
                                  ? "bg-red-500 border-red-500"
                                  : "border-gray-600 hover:border-gray-400"
                              )}
                            >
                              {isSelected && <CheckCircle2 className="w-3.5 h-3.5 text-white" />}
                            </div>
                          )}
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Diff summary between scans */}
                  {diff && !isLast && (
                    <div className="flex gap-4">
                      <div className="flex flex-col items-center w-8 flex-shrink-0">
                        <div className="w-0.5 flex-1 bg-gray-800" />
                      </div>
                      <div className="flex-1 flex items-center gap-3 px-4 py-2 mb-2">
                        <div className="h-px flex-1 bg-gray-800/50" />
                        <div className="flex items-center gap-3 text-xs flex-shrink-0">
                          {diff.newVulns > 0 && (
                            <span className="flex items-center gap-1 text-red-400">
                              <Plus className="w-3 h-3" />
                              {diff.newVulns} new vuln{diff.newVulns !== 1 ? "s" : ""}
                            </span>
                          )}
                          {diff.fixedVulns > 0 && (
                            <span className="flex items-center gap-1 text-green-400">
                              <Minus className="w-3 h-3" />
                              {diff.fixedVulns} fixed
                            </span>
                          )}
                          {diff.newVulns === 0 && diff.fixedVulns === 0 && (
                            <span className="text-gray-600">no vuln change</span>
                          )}
                          {diff.newEndpoints !== 0 && (
                            <span
                              className={cn(
                                "flex items-center gap-1",
                                diff.newEndpoints > 0 ? "text-blue-400" : "text-gray-500"
                              )}
                            >
                              {diff.newEndpoints > 0 ? (
                                <Plus className="w-3 h-3" />
                              ) : (
                                <Minus className="w-3 h-3" />
                              )}
                              {Math.abs(diff.newEndpoints)} endpoint
                              {Math.abs(diff.newEndpoints) !== 1 ? "s" : ""}
                            </span>
                          )}
                        </div>
                        <div className="h-px flex-1 bg-gray-800/50" />
                      </div>
                    </div>
                  )}
                </div>
              );
            })
          )}
        </div>

        {/* Comparison Panel */}
        {comparisonResult && (
          <div className="lg:w-1/2 bg-gray-900 border border-gray-800 rounded-lg overflow-hidden flex-shrink-0">
            <div className="flex items-center justify-between p-4 border-b border-gray-800">
              <div className="flex items-center gap-2">
                <GitCompareArrows className="w-5 h-5 text-red-500" />
                <h2 className="text-lg font-semibold text-white">Comparison Results</h2>
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={generateReport}
                  disabled={reportLoading}
                  className="px-3 py-1.5 bg-purple-600 text-white text-sm rounded-lg hover:bg-purple-700 transition-colors flex items-center gap-2 disabled:opacity-50"
                >
                  {reportLoading ? (
                    <Loader2 className="w-4 h-4 animate-spin" />
                  ) : (
                    <FileText className="w-4 h-4" />
                  )}
                  Generate Report
                </button>
                <button
                  onClick={closeComparison}
                  className="p-1 hover:bg-gray-800 rounded transition-colors"
                >
                  <X className="w-5 h-5 text-gray-400" />
                </button>
              </div>
            </div>

            {/* Summary stats */}
            <div className="grid grid-cols-3 gap-3 p-4 border-b border-gray-800">
              <div className="bg-red-950/30 border border-red-900/30 rounded-lg p-3 text-center">
                <div className="text-2xl font-bold text-red-400">
                  {comparisonResult.summary?.new_count ?? comparisonResult.new?.length ?? 0}
                </div>
                <div className="text-xs text-red-400/70 mt-1">New Vulns</div>
              </div>
              <div className="bg-green-950/30 border border-green-900/30 rounded-lg p-3 text-center">
                <div className="text-2xl font-bold text-green-400">
                  {comparisonResult.summary?.fixed_count ?? comparisonResult.fixed?.length ?? 0}
                </div>
                <div className="text-xs text-green-400/70 mt-1">Fixed</div>
              </div>
              <div className="bg-gray-800/50 border border-gray-700/50 rounded-lg p-3 text-center">
                <div className="text-2xl font-bold text-gray-300">
                  {comparisonResult.summary?.unchanged_count ??
                    comparisonResult.unchanged?.length ??
                    0}
                </div>
                <div className="text-xs text-gray-500 mt-1">Unchanged</div>
              </div>
            </div>

            {/* Scan info */}
            <div className="grid grid-cols-2 gap-3 p-4 border-b border-gray-800">
              {comparisonResult.scan_a && (
                <div className="bg-gray-800/50 rounded-lg p-3">
                  <div className="text-xs text-gray-500 mb-1">Scan A</div>
                  <div className="text-sm text-white truncate">
                    {comparisonResult.scan_a.created_at
                      ? parseUTC(comparisonResult.scan_a.created_at).toLocaleDateString()
                      : comparisonResult.scan_a.id?.slice(0, 8)}
                  </div>
                  <div className="text-xs text-gray-500 mt-1">
                    {comparisonResult.scan_a.vulns_count ?? 0} vulns
                  </div>
                </div>
              )}
              {comparisonResult.scan_b && (
                <div className="bg-gray-800/50 rounded-lg p-3">
                  <div className="text-xs text-gray-500 mb-1">Scan B</div>
                  <div className="text-sm text-white truncate">
                    {comparisonResult.scan_b.created_at
                      ? parseUTC(comparisonResult.scan_b.created_at).toLocaleDateString()
                      : comparisonResult.scan_b.id?.slice(0, 8)}
                  </div>
                  <div className="text-xs text-gray-500 mt-1">
                    {comparisonResult.scan_b.vulns_count ?? 0} vulns
                  </div>
                </div>
              )}
            </div>

            {/* Vuln lists */}
            <div className="max-h-[60vh] overflow-y-auto">
              <VulnSection
                title="New Vulnerabilities"
                vulns={comparisonResult.new || []}
                color="red"
                icon={<Plus className="w-4 h-4" />}
              />
              <VulnSection
                title="Fixed Vulnerabilities"
                vulns={comparisonResult.fixed || []}
                color="green"
                icon={<CheckCircle2 className="w-4 h-4" />}
              />
              <VulnSection
                title="Unchanged"
                vulns={comparisonResult.unchanged || []}
                color="gray"
                icon={<Minus className="w-4 h-4" />}
                collapsedByDefault
              />
            </div>
          </div>
        )}
      </div>

      {/* Comparison Report Modal */}
      {reportHtml && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm">
          <div className="relative w-[90vw] h-[90vh] bg-gray-900 border border-gray-800 rounded-xl shadow-2xl overflow-hidden flex flex-col">
            <div className="flex items-center justify-between px-6 py-4 border-b border-gray-800 flex-shrink-0">
              <div className="flex items-center gap-2">
                <FileText className="w-5 h-5 text-purple-500" />
                <h2 className="text-lg font-semibold text-white">Scan Comparison Report</h2>
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => {
                    const blob = new Blob([reportHtml], { type: "text/html" });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement("a");
                    a.href = url;
                    a.download = "phantom-comparison-report.html";
                    a.click();
                    URL.revokeObjectURL(url);
                  }}
                  className="px-3 py-1.5 bg-gray-800 text-gray-300 text-sm rounded-lg hover:bg-gray-700 transition-colors border border-gray-700"
                >
                  Download HTML
                </button>
                <button
                  onClick={() => setReportHtml(null)}
                  className="p-1.5 hover:bg-gray-800 rounded-lg transition-colors"
                >
                  <X className="w-5 h-5 text-gray-400" />
                </button>
              </div>
            </div>
            <iframe
              srcDoc={reportHtml}
              className="flex-1 w-full bg-[#0a0a0f]"
              title="Comparison Report"
              sandbox="allow-same-origin"
            />
          </div>
        </div>
      )}
    </div>
  );
}

function VulnSection({
  title,
  vulns,
  color,
  icon,
  collapsedByDefault = false,
}: {
  title: string;
  vulns: any[];
  color: "red" | "green" | "gray";
  icon: React.ReactNode;
  collapsedByDefault?: boolean;
}) {
  const [expanded, setExpanded] = useState(!collapsedByDefault);

  const colorMap = {
    red: {
      bg: "bg-red-950/20",
      border: "border-red-900/30",
      text: "text-red-400",
      badge: "bg-red-950/50 text-red-400",
      dot: "bg-red-500",
    },
    green: {
      bg: "bg-green-950/20",
      border: "border-green-900/30",
      text: "text-green-400",
      badge: "bg-green-950/50 text-green-400",
      dot: "bg-green-500",
    },
    gray: {
      bg: "bg-gray-900/20",
      border: "border-gray-800/30",
      text: "text-gray-400",
      badge: "bg-gray-800/50 text-gray-400",
      dot: "bg-gray-500",
    },
  };

  const c = colorMap[color];

  return (
    <div className={cn("border-b border-gray-800 last:border-b-0")}>
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center justify-between p-4 hover:bg-gray-800/30 transition-colors"
      >
        <div className="flex items-center gap-2">
          <span className={c.text}>{icon}</span>
          <span className={cn("font-medium text-sm", c.text)}>{title}</span>
          <span className={cn("text-xs px-1.5 py-0.5 rounded", c.badge)}>{vulns.length}</span>
        </div>
        {expanded ? (
          <ChevronDown className="w-4 h-4 text-gray-500" />
        ) : (
          <ChevronRight className="w-4 h-4 text-gray-500" />
        )}
      </button>
      {expanded && vulns.length > 0 && (
        <div className="px-4 pb-4 space-y-2">
          {vulns.map((vuln: any, i: number) => (
            <div
              key={vuln.id || i}
              className="flex items-start gap-3 p-3 bg-gray-800/30 rounded-lg"
            >
              <div className={cn("w-2 h-2 rounded-full mt-1.5 flex-shrink-0", c.dot)} />
              <div className="flex-1 min-w-0">
                <div className="text-sm text-white font-medium truncate">
                  {vuln.vuln_type || vuln.type || vuln.name || "Unknown"}
                </div>
                {(vuln.url || vuln.endpoint) && (
                  <div className="text-xs text-gray-500 truncate mt-0.5">
                    {vuln.url || vuln.endpoint}
                  </div>
                )}
                {vuln.severity && (
                  <span
                    className={cn(
                      "inline-block text-xs px-1.5 py-0.5 rounded mt-1 capitalize",
                      vuln.severity === "critical"
                        ? "bg-red-950/50 text-red-400"
                        : vuln.severity === "high"
                        ? "bg-orange-950/50 text-orange-400"
                        : vuln.severity === "medium"
                        ? "bg-yellow-950/50 text-yellow-400"
                        : "bg-blue-950/50 text-blue-400"
                    )}
                  >
                    {vuln.severity}
                  </span>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
      {expanded && vulns.length === 0 && (
        <div className="px-4 pb-4">
          <p className="text-sm text-gray-600 italic">None</p>
        </div>
      )}
    </div>
  );
}
