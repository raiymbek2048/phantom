"use client";

import { useState, useEffect, useCallback } from "react";
import { useAuthStore } from "@/lib/store";
import { useT } from "@/lib/i18n";
import LoginForm from "@/components/LoginForm";
import Sidebar from "@/components/Sidebar";
import {
  getDashboardStats,
  getVulnsOverTime,
  getTopVulnTypes,
  getVulnerabilities,
  getScans,
  getGraphSummary,
} from "@/lib/api";
import { cn } from "@/lib/utils";
import {
  BarChart3,
  ShieldAlert,
  Scan,
  TrendingUp,
  Loader2,
  AlertTriangle,
  RefreshCw,
  CheckCircle,
  XCircle,
  Activity,
} from "lucide-react";

// --- Types ---
interface DashboardData {
  total_targets: number;
  total_scans: number;
  total_vulns: number;
  active_scans: number;
  vulns_by_severity: Record<string, number>;
  scans_by_status: Record<string, number>;
  kb_patterns: number;
}

interface VulnOverTimeEntry {
  date: string;
  count: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

interface TopVulnTypeEntry {
  type: string;
  count: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-red-500",
  high: "bg-orange-500",
  medium: "bg-yellow-500",
  low: "bg-blue-500",
  info: "bg-gray-500",
};

const SEVERITY_TEXT: Record<string, string> = {
  critical: "text-red-400",
  high: "text-orange-400",
  medium: "text-yellow-400",
  low: "text-blue-400",
  info: "text-gray-400",
};

export default function AnalyticsPage() {
  const { isLoggedIn } = useAuthStore();
  const t = useT();

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [stats, setStats] = useState<DashboardData | null>(null);
  const [vulnsOverTime, setVulnsOverTime] = useState<VulnOverTimeEntry[]>([]);
  const [topTypes, setTopTypes] = useState<TopVulnTypeEntry[]>([]);
  const [vulns, setVulns] = useState<any[]>([]);
  const [scans, setScans] = useState<any[]>([]);
  const [graphSummary, setGraphSummary] = useState<any>(null);

  const loadData = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const [s, vot, tt, v, sc, gs] = await Promise.allSettled([
        getDashboardStats(),
        getVulnsOverTime(),
        getTopVulnTypes(),
        getVulnerabilities(),
        getScans(),
        getGraphSummary(),
      ]);
      if (s.status === "fulfilled") setStats(s.value);
      if (vot.status === "fulfilled") setVulnsOverTime(vot.value);
      if (tt.status === "fulfilled") setTopTypes(tt.value);
      if (v.status === "fulfilled") setVulns(Array.isArray(v.value) ? v.value : []);
      if (sc.status === "fulfilled") setScans(Array.isArray(sc.value) ? sc.value : []);
      if (gs.status === "fulfilled") setGraphSummary(gs.value);
    } catch (e: any) {
      setError(e.message || "Failed to load analytics");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  if (!isLoggedIn) return <LoginForm />;

  // Derived metrics
  const totalScans = stats?.total_scans || 0;
  const totalVulns = stats?.total_vulns || 0;
  const completedScans = stats?.scans_by_status?.completed || 0;
  const avgVulnsPerScan = completedScans > 0 ? (totalVulns / completedScans).toFixed(1) : "0";

  const confirmedVulns = vulns.filter((v: any) => v.title?.includes("[CONFIRMED]") || v.status === "confirmed").length;
  const unconfirmedVulns = totalVulns - confirmedVulns;
  const confirmRate = totalVulns > 0 ? Math.round((confirmedVulns / totalVulns) * 100) : 0;

  // Severity breakdown
  const sevData = stats?.vulns_by_severity || {};
  const sevTotal = Object.values(sevData).reduce((a, b) => a + b, 0) || 1;

  // Technology data from vulns
  const techCounts: Record<string, number> = {};
  scans.forEach((s: any) => {
    const techs = s.scan_results?.fingerprint?.technologies || s.scan_results?.technologies || [];
    if (Array.isArray(techs)) {
      techs.forEach((tech: string) => {
        techCounts[tech] = (techCounts[tech] || 0) + 1;
      });
    }
  });
  const topTechs = Object.entries(techCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10);

  // Max for bar scaling
  const maxTypeCount = topTypes.length > 0 ? Math.max(...topTypes.map((t) => t.count)) : 1;
  const maxTechCount = topTechs.length > 0 ? Math.max(...topTechs.map(([, c]) => c)) : 1;

  // Timeline: last 14 entries
  const timelineData = vulnsOverTime.slice(-14);
  const maxTimelineCount = timelineData.length > 0 ? Math.max(...timelineData.map((d) => d.count), 1) : 1;

  return (
    <div className="flex min-h-screen bg-[#0a0a0a]">
      <Sidebar />
      <main className="flex-1 ml-60 p-6">
        {/* Header */}
        <div className="flex items-center justify-between mb-8">
          <div>
            <h1 className="text-2xl font-bold text-white flex items-center gap-3">
              <BarChart3 className="w-7 h-7 text-green-400" />
              {t("analytics.title")}
            </h1>
            <p className="text-sm text-gray-500 mt-1">{t("analytics.subtitle")}</p>
          </div>
          <button
            onClick={loadData}
            disabled={loading}
            className="flex items-center gap-2 px-4 py-2 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded-lg text-sm transition-colors"
          >
            <RefreshCw className={cn("w-4 h-4", loading && "animate-spin")} />
            {t("common.refresh")}
          </button>
        </div>

        {error && (
          <div className="mb-6 p-4 bg-red-950/50 border border-red-800 rounded-lg text-red-400 text-sm flex items-center gap-2">
            <AlertTriangle className="w-4 h-4" /> {error}
          </div>
        )}

        {loading && !stats ? (
          <div className="flex items-center justify-center h-64 text-gray-500">
            <Loader2 className="w-8 h-8 animate-spin" />
          </div>
        ) : (
          <>
            {/* KPI Cards */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
              {/* Total Scans */}
              <div className="bg-gray-900/50 border border-gray-800 rounded-xl p-5">
                <div className="flex items-center justify-between mb-3">
                  <span className="text-xs text-gray-500 uppercase tracking-wider">{t("analytics.total_scans")}</span>
                  <Scan className="w-5 h-5 text-blue-400" />
                </div>
                <div className="text-3xl font-bold text-white font-mono">{totalScans}</div>
                <div className="text-xs text-gray-600 mt-1">
                  {completedScans} {t("analytics.completed")} / {stats?.active_scans || 0} {t("analytics.active")}
                </div>
              </div>

              {/* Total Vulns */}
              <div className="bg-gray-900/50 border border-gray-800 rounded-xl p-5">
                <div className="flex items-center justify-between mb-3">
                  <span className="text-xs text-gray-500 uppercase tracking-wider">{t("analytics.total_vulns")}</span>
                  <ShieldAlert className="w-5 h-5 text-red-400" />
                </div>
                <div className="text-3xl font-bold text-white font-mono">{totalVulns}</div>
                <div className="flex items-center gap-2 mt-1">
                  <span className="text-xs text-red-400">{sevData.critical || 0} crit</span>
                  <span className="text-xs text-orange-400">{sevData.high || 0} high</span>
                  <span className="text-xs text-yellow-400">{sevData.medium || 0} med</span>
                </div>
              </div>

              {/* Confirmed Ratio */}
              <div className="bg-gray-900/50 border border-gray-800 rounded-xl p-5">
                <div className="flex items-center justify-between mb-3">
                  <span className="text-xs text-gray-500 uppercase tracking-wider">{t("analytics.confirmed_ratio")}</span>
                  <CheckCircle className="w-5 h-5 text-green-400" />
                </div>
                <div className="text-3xl font-bold text-white font-mono">{confirmRate}%</div>
                <div className="flex items-center gap-3 mt-2">
                  <div className="flex-1 h-2 bg-gray-800 rounded-full overflow-hidden">
                    <div className="h-full bg-green-500 rounded-full" style={{ width: `${confirmRate}%` }} />
                  </div>
                  <span className="text-xs text-gray-500">{confirmedVulns}/{totalVulns}</span>
                </div>
              </div>

              {/* Avg Vulns/Scan */}
              <div className="bg-gray-900/50 border border-gray-800 rounded-xl p-5">
                <div className="flex items-center justify-between mb-3">
                  <span className="text-xs text-gray-500 uppercase tracking-wider">{t("analytics.avg_per_scan")}</span>
                  <TrendingUp className="w-5 h-5 text-yellow-400" />
                </div>
                <div className="text-3xl font-bold text-white font-mono">{avgVulnsPerScan}</div>
                <div className="text-xs text-gray-600 mt-1">{t("analytics.vulns_per_completed")}</div>
              </div>
            </div>

            {/* Middle Section: Vuln Distribution */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
              {/* By Type - Horizontal Bar */}
              <div className="lg:col-span-2 bg-gray-900/50 border border-gray-800 rounded-xl p-5">
                <h3 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
                  <BarChart3 className="w-4 h-4 text-blue-400" />
                  {t("analytics.by_type")}
                </h3>
                <div className="space-y-3">
                  {topTypes.length === 0 && (
                    <p className="text-gray-600 text-sm">{t("common.no_data")}</p>
                  )}
                  {topTypes.map((item) => (
                    <div key={item.type} className="group">
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-xs text-gray-400 font-mono uppercase">{item.type}</span>
                        <span className="text-xs text-gray-500 font-mono">{item.count}</span>
                      </div>
                      <div className="h-5 bg-gray-800 rounded overflow-hidden flex">
                        {["critical", "high", "medium", "low"].map((sev) => {
                          const val = (item as any)[sev] || 0;
                          const pct = (val / (maxTypeCount || 1)) * 100;
                          return pct > 0 ? (
                            <div
                              key={sev}
                              className={cn("h-full transition-all", SEVERITY_COLORS[sev])}
                              style={{ width: `${pct}%` }}
                              title={`${sev}: ${val}`}
                            />
                          ) : null;
                        })}
                      </div>
                    </div>
                  ))}
                </div>
                {topTypes.length > 0 && (
                  <div className="flex items-center gap-4 mt-4 text-xs text-gray-600">
                    {["critical", "high", "medium", "low"].map((sev) => (
                      <span key={sev} className="flex items-center gap-1.5">
                        <span className={cn("w-2.5 h-2.5 rounded-sm", SEVERITY_COLORS[sev])} />
                        {sev}
                      </span>
                    ))}
                  </div>
                )}
              </div>

              {/* By Severity - Visual Breakdown */}
              <div className="bg-gray-900/50 border border-gray-800 rounded-xl p-5">
                <h3 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4 text-red-400" />
                  {t("analytics.by_severity")}
                </h3>
                <div className="space-y-3">
                  {["critical", "high", "medium", "low", "info"].map((sev) => {
                    const count = sevData[sev] || 0;
                    const pct = Math.round((count / sevTotal) * 100);
                    return (
                      <div key={sev}>
                        <div className="flex items-center justify-between mb-1">
                          <span className={cn("text-xs font-medium capitalize", SEVERITY_TEXT[sev])}>{sev}</span>
                          <span className="text-xs text-gray-500 font-mono">{count} ({pct}%)</span>
                        </div>
                        <div className="h-3 bg-gray-800 rounded-full overflow-hidden">
                          <div
                            className={cn("h-full rounded-full transition-all", SEVERITY_COLORS[sev])}
                            style={{ width: `${pct}%` }}
                          />
                        </div>
                      </div>
                    );
                  })}
                </div>
                {/* Donut-like summary */}
                <div className="mt-5 pt-4 border-t border-gray-800">
                  <div className="flex items-center justify-center">
                    <div className="relative w-24 h-24">
                      <svg viewBox="0 0 36 36" className="w-24 h-24 transform -rotate-90">
                        {(() => {
                          let offset = 0;
                          const colors: Record<string, string> = {
                            critical: "#ef4444",
                            high: "#f97316",
                            medium: "#eab308",
                            low: "#3b82f6",
                            info: "#6b7280",
                          };
                          return ["critical", "high", "medium", "low", "info"].map((sev) => {
                            const pct = ((sevData[sev] || 0) / sevTotal) * 100;
                            const el = (
                              <circle
                                key={sev}
                                cx="18"
                                cy="18"
                                r="15.9155"
                                fill="none"
                                stroke={colors[sev]}
                                strokeWidth="3"
                                strokeDasharray={`${pct} ${100 - pct}`}
                                strokeDashoffset={-offset}
                              />
                            );
                            offset += pct;
                            return el;
                          });
                        })()}
                      </svg>
                      <div className="absolute inset-0 flex items-center justify-center">
                        <span className="text-lg font-bold text-white font-mono">{totalVulns}</span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* Timeline */}
            <div className="bg-gray-900/50 border border-gray-800 rounded-xl p-5 mb-8">
              <h3 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
                <Activity className="w-4 h-4 text-green-400" />
                {t("analytics.timeline")}
              </h3>
              {timelineData.length === 0 ? (
                <p className="text-gray-600 text-sm">{t("common.no_data")}</p>
              ) : (
                <div className="flex items-end gap-1.5 h-40">
                  {timelineData.map((entry, i) => {
                    const pct = (entry.count / maxTimelineCount) * 100;
                    return (
                      <div
                        key={i}
                        className="flex-1 flex flex-col items-center gap-1 group"
                      >
                        <span className="text-[10px] text-gray-500 font-mono opacity-0 group-hover:opacity-100 transition-opacity">
                          {entry.count}
                        </span>
                        <div className="w-full flex flex-col-reverse" style={{ height: "120px" }}>
                          {["info", "low", "medium", "high", "critical"].map((sev) => {
                            const val = (entry as any)[sev] || 0;
                            const segPct = (val / maxTimelineCount) * 120;
                            return segPct > 0 ? (
                              <div
                                key={sev}
                                className={cn("w-full rounded-sm", SEVERITY_COLORS[sev])}
                                style={{ height: `${segPct}px` }}
                                title={`${sev}: ${val}`}
                              />
                            ) : null;
                          })}
                        </div>
                        <span className="text-[9px] text-gray-600 font-mono truncate w-full text-center">
                          {entry.date.slice(5)}
                        </span>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>

            {/* Bottom Section: Tech Intelligence */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Most Scanned Technologies */}
              <div className="bg-gray-900/50 border border-gray-800 rounded-xl p-5">
                <h3 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
                  <TrendingUp className="w-4 h-4 text-purple-400" />
                  {t("analytics.top_techs")}
                </h3>
                {topTechs.length === 0 ? (
                  <p className="text-gray-600 text-sm">{t("common.no_data")}</p>
                ) : (
                  <div className="space-y-2.5">
                    {topTechs.map(([tech, count]) => (
                      <div key={tech}>
                        <div className="flex items-center justify-between mb-1">
                          <span className="text-xs text-gray-300 font-mono">{tech}</span>
                          <span className="text-xs text-gray-500 font-mono">{count}</span>
                        </div>
                        <div className="h-2.5 bg-gray-800 rounded-full overflow-hidden">
                          <div
                            className="h-full bg-purple-500/70 rounded-full"
                            style={{ width: `${(count / maxTechCount) * 100}%` }}
                          />
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* KB & Graph Stats */}
              <div className="bg-gray-900/50 border border-gray-800 rounded-xl p-5">
                <h3 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
                  <Activity className="w-4 h-4 text-cyan-400" />
                  {t("analytics.kb_stats")}
                </h3>
                <div className="grid grid-cols-2 gap-3">
                  <div className="bg-gray-800/50 rounded-lg p-3 text-center">
                    <div className="text-2xl font-bold text-white font-mono">{stats?.kb_patterns || 0}</div>
                    <div className="text-[10px] text-gray-500 uppercase mt-1">{t("analytics.kb_patterns")}</div>
                  </div>
                  <div className="bg-gray-800/50 rounded-lg p-3 text-center">
                    <div className="text-2xl font-bold text-white font-mono">{stats?.total_targets || 0}</div>
                    <div className="text-[10px] text-gray-500 uppercase mt-1">{t("analytics.targets_tracked")}</div>
                  </div>
                  {graphSummary && (
                    <>
                      <div className="bg-gray-800/50 rounded-lg p-3 text-center">
                        <div className="text-2xl font-bold text-white font-mono">
                          {graphSummary.total_nodes || 0}
                        </div>
                        <div className="text-[10px] text-gray-500 uppercase mt-1">{t("analytics.graph_nodes")}</div>
                      </div>
                      <div className="bg-gray-800/50 rounded-lg p-3 text-center">
                        <div className="text-2xl font-bold text-white font-mono">
                          {graphSummary.total_edges || 0}
                        </div>
                        <div className="text-[10px] text-gray-500 uppercase mt-1">{t("analytics.graph_edges")}</div>
                      </div>
                    </>
                  )}
                </div>

                {/* Scan Success Rate */}
                <div className="mt-4 pt-4 border-t border-gray-800">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs text-gray-500">{t("analytics.scan_success_rate")}</span>
                    <span className="text-xs text-green-400 font-mono">
                      {totalScans > 0 ? Math.round((completedScans / totalScans) * 100) : 0}%
                    </span>
                  </div>
                  <div className="h-2 bg-gray-800 rounded-full overflow-hidden">
                    <div
                      className="h-full bg-green-500 rounded-full"
                      style={{ width: `${totalScans > 0 ? (completedScans / totalScans) * 100 : 0}%` }}
                    />
                  </div>
                  <div className="flex items-center justify-between mt-2 text-[10px] text-gray-600">
                    <span className="flex items-center gap-1">
                      <CheckCircle className="w-3 h-3 text-green-500" />
                      {completedScans} {t("analytics.completed")}
                    </span>
                    <span className="flex items-center gap-1">
                      <XCircle className="w-3 h-3 text-red-500" />
                      {stats?.scans_by_status?.failed || 0} {t("analytics.failed")}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          </>
        )}
      </main>
    </div>
  );
}
