"use client";

import { useState, useEffect, useCallback } from "react";
import { useAuthStore } from "@/lib/store";
import { useNotifications } from "@/lib/notifications";
import LoginForm from "@/components/LoginForm";
import Sidebar from "@/components/Sidebar";
import {
  getDashboardStats,
  getVulnsOverTime,
  getTopVulnTypes,
  getRecentActivity,
  getTargetRisk,
  createTarget,
  createScan,
  getTargets,
} from "@/lib/api";
import { timeAgo, severityColor, statusColor, cn } from "@/lib/utils";
import { useT } from "@/lib/i18n";
import {
  Target,
  Scan,
  ShieldAlert,
  Activity,
  ArrowRight,
  Eye,
  Cpu,
  BarChart3,
  Bug,
  Clock,
  Globe,
  TrendingUp,
  Zap,
  AlertTriangle,
  Info,
  ChevronRight,
  Database,
  Crosshair,
  Shield,
} from "lucide-react";

interface DashboardData {
  total_targets: number;
  total_scans: number;
  total_vulns: number;
  active_scans: number;
  monitored_targets: number;
  vulns_by_severity: Record<string, number>;
  vulns_by_type: Record<string, number>;
  recent_vulns: Array<{
    id: string;
    title: string;
    severity: string;
    vuln_type: string;
    url: string;
    created_at: string;
    target_domain: string;
  }>;
  recent_scans: Array<{
    id: string;
    target_domain: string;
    status: string;
    scan_type: string;
    vulns_found: number;
    endpoints_found: number;
    started_at: string | null;
    completed_at: string | null;
    created_at: string | null;
  }>;
  scan_activity: Array<{
    date: string;
    scans: number;
    vulns: number;
  }>;
  llm_provider: string;
  training_active: boolean;
  kb_patterns?: number;
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

interface ActivityEntry {
  type: "vuln" | "scan";
  id: string;
  title: string;
  severity?: string;
  status?: string;
  target_domain: string;
  created_at: string;
}

interface TargetRiskEntry {
  id: string;
  domain: string;
  risk_score: number;
  total_vulns: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  last_scan: string | null;
}

export default function DashboardPage() {
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
      <main className="ml-60 flex-1 min-h-screen">
        <DashboardContent />
      </main>
    </div>
  );
}

function DashboardContent() {
  const [data, setData] = useState<DashboardData | null>(null);
  const [vulnsOverTime, setVulnsOverTime] = useState<VulnOverTimeEntry[]>([]);
  const [topVulnTypes, setTopVulnTypes] = useState<TopVulnTypeEntry[]>([]);
  const [recentActivity, setRecentActivity] = useState<ActivityEntry[]>([]);
  const [targetRisk, setTargetRisk] = useState<TargetRiskEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [domain, setDomain] = useState("");
  const [scanType, setScanType] = useState("full");
  const [launching, setLaunching] = useState(false);
  const notify = useNotifications((s) => s.add);
  const t = useT();

  const load = useCallback(async () => {
    try {
      const [stats, vot, tvt, ra, tr] = await Promise.allSettled([
        getDashboardStats(),
        getVulnsOverTime(),
        getTopVulnTypes(),
        getRecentActivity(),
        getTargetRisk(),
      ]);
      if (stats.status === "fulfilled") setData(stats.value);
      if (vot.status === "fulfilled") setVulnsOverTime(vot.value);
      if (tvt.status === "fulfilled") setTopVulnTypes(tvt.value);
      if (ra.status === "fulfilled") setRecentActivity(ra.value);
      if (tr.status === "fulfilled") setTargetRisk(tr.value);
    } catch {
      // ignore
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
    const interval = setInterval(load, 8000);
    return () => clearInterval(interval);
  }, [load]);

  async function handleQuickScan() {
    if (!domain.trim()) return;
    setLaunching(true);
    try {
      const target = await createTarget(domain.trim());
      const scan = await createScan(target.id, scanType);
      notify({ type: "success", title: t("dash.scan_launched"), message: `${scanType} ${t("dash.scan_started")} ${domain.trim()}` });
      setDomain("");
      window.location.href = `/scans/${scan.id}`;
    } catch {
      try {
        const allTargets = await getTargets();
        const existing = allTargets.find(
          (tgt: any) => tgt.domain === domain.trim().toLowerCase()
        );
        if (existing) {
          const scan = await createScan(existing.id, scanType);
          notify({ type: "success", title: t("dash.scan_launched"), message: `${scanType} ${t("dash.scan_started")} ${domain.trim()}` });
          window.location.href = `/scans/${scan.id}`;
        } else {
          notify({ type: "error", title: t("dash.scan_failed"), message: t("dash.scan_failed_target") });
        }
      } catch {
        notify({ type: "error", title: t("dash.scan_failed"), message: t("dash.scan_failed_error") });
      }
    } finally {
      setLaunching(false);
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-screen">
        <div className="flex flex-col items-center gap-4">
          <div className="w-10 h-10 border-2 border-red-600/30 border-t-red-600 rounded-full animate-spin" />
          <p className="text-gray-500 text-sm">{t("dash.loading")}</p>
        </div>
      </div>
    );
  }

  if (!data) {
    return (
      <div className="flex items-center justify-center h-screen">
        <p className="text-gray-500">{t("dash.load_failed")}</p>
      </div>
    );
  }

  const totalSevVulns =
    (data.vulns_by_severity.critical || 0) +
    (data.vulns_by_severity.high || 0) +
    (data.vulns_by_severity.medium || 0) +
    (data.vulns_by_severity.low || 0) +
    (data.vulns_by_severity.info || 0);

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">{t("dash.title")}</h1>
          <p className="text-sm text-gray-500 mt-1">
            {t("dash.subtitle")}
          </p>
        </div>
        <div className="flex items-center gap-3">
          <div className={cn(
            "flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-medium border",
            data.active_scans > 0
              ? "bg-green-950/50 text-green-400 border-green-900/50"
              : "bg-gray-900 text-gray-500 border-gray-800"
          )}>
            <div className={cn(
              "w-1.5 h-1.5 rounded-full",
              data.active_scans > 0 ? "bg-green-400 animate-pulse" : "bg-gray-600"
            )} />
            {data.active_scans > 0 ? `${data.active_scans} ${t("dash.scans_running")}` : t("dash.idle")}
          </div>
        </div>
      </div>

      {/* Quick Scan Bar */}
      <div className="bg-[#12121a] rounded-xl border border-[#1e1e2e] p-4">
        <div className="flex gap-2">
          <div className="relative flex-1">
            <Globe className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-600" />
            <input
              type="text"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleQuickScan()}
              placeholder={t("dash.placeholder")}
              className="w-full bg-[#0a0a0f] border border-[#1e1e2e] rounded-lg pl-9 pr-3 py-2.5 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-purple-500/50 focus:ring-1 focus:ring-purple-500/20 transition"
            />
          </div>
          <select
            value={scanType}
            onChange={(e) => setScanType(e.target.value)}
            className="bg-[#0a0a0f] border border-[#1e1e2e] rounded-lg px-3 py-2.5 text-sm text-white focus:outline-none focus:border-purple-500/50"
          >
            <option value="AI">{t("scan.ai_agent")}</option>
            <option value="quick">{t("scan.quick")}</option>
            <option value="full">{t("scan.full")}</option>
            <option value="stealth">{t("scan.stealth")}</option>
            <option value="recon">{t("scan.recon")}</option>
          </select>
          <button
            onClick={handleQuickScan}
            disabled={launching || !domain.trim()}
            className="bg-purple-600 hover:bg-purple-500 disabled:opacity-40 disabled:hover:bg-purple-600 text-white px-6 py-2.5 rounded-lg text-sm font-medium transition flex items-center gap-2"
          >
            {launching ? (
              <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
            ) : (
              <>
                <Zap className="w-4 h-4" />
                {t("dash.launch")}
              </>
            )}
          </button>
        </div>
      </div>

      {/* Stats Cards Row */}
      <div className="grid grid-cols-4 gap-4">
        <StatCard
          icon={Target}
          label={t("dash.targets")}
          value={data.total_targets}
          color="blue"
          href="/targets"
        />
        <StatCard
          icon={Scan}
          label={t("dash.total_scans")}
          value={data.total_scans}
          color="purple"
          href="/scans"
        />
        <StatCard
          icon={ShieldAlert}
          label={t("dash.vulnerabilities")}
          value={data.total_vulns}
          color="red"
          href="/vulnerabilities"
        />
        <StatCard
          icon={Database}
          label="KB Patterns"
          value={data.kb_patterns ?? "---"}
          color="cyan"
        />
      </div>

      {/* Severity Distribution Bar */}
      {totalSevVulns > 0 && (
        <div className="bg-[#12121a] rounded-xl border border-[#1e1e2e] p-5">
          <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-4 flex items-center gap-2">
            <Shield className="w-4 h-4" />
            Severity Distribution
          </h2>
          <div className="flex h-8 rounded-lg overflow-hidden">
            {[
              { key: "critical", color: "bg-red-600", label: t("sev.critical") },
              { key: "high", color: "bg-orange-500", label: t("sev.high") },
              { key: "medium", color: "bg-amber-500", label: t("sev.medium") },
              { key: "low", color: "bg-blue-500", label: t("sev.low") },
              { key: "info", color: "bg-gray-600", label: t("sev.info") },
            ].map(({ key, color }) => {
              const count = data.vulns_by_severity[key] || 0;
              const pct = totalSevVulns > 0 ? (count / totalSevVulns) * 100 : 0;
              if (pct === 0) return null;
              return (
                <div
                  key={key}
                  className={cn(color, "relative group flex items-center justify-center min-w-[2px] transition-all")}
                  style={{ width: `${pct}%` }}
                >
                  {pct > 8 && (
                    <span className="text-[11px] font-bold text-white/90">{count}</span>
                  )}
                  <div className="absolute -top-9 left-1/2 -translate-x-1/2 bg-gray-800 border border-gray-700 rounded px-2 py-1 text-[10px] text-gray-200 whitespace-nowrap opacity-0 group-hover:opacity-100 transition pointer-events-none z-10">
                    {key}: {count} ({pct.toFixed(1)}%)
                  </div>
                </div>
              );
            })}
          </div>
          <div className="flex items-center gap-5 mt-3">
            {[
              { key: "critical", color: "bg-red-600", textColor: "text-red-400" },
              { key: "high", color: "bg-orange-500", textColor: "text-orange-400" },
              { key: "medium", color: "bg-amber-500", textColor: "text-amber-400" },
              { key: "low", color: "bg-blue-500", textColor: "text-blue-400" },
              { key: "info", color: "bg-gray-600", textColor: "text-gray-400" },
            ].map(({ key, color, textColor }) => (
              <span key={key} className="flex items-center gap-1.5 text-[11px] text-gray-500">
                <span className={cn("w-2.5 h-2.5 rounded-sm", color)} />
                <span className={textColor}>{key}</span>
                <span className="text-gray-600">{data.vulns_by_severity[key] || 0}</span>
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Middle Row: Vulns Over Time + Top Vuln Types */}
      <div className="grid grid-cols-2 gap-4">
        {/* Vulns Over Time */}
        <div className="bg-[#12121a] rounded-xl border border-[#1e1e2e] p-5">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider flex items-center gap-2">
              <TrendingUp className="w-4 h-4" />
              Vulns Over Time
            </h2>
            <span className="text-xs text-gray-600">{t("dash.last_14")}</span>
          </div>
          <VulnsOverTimeChart data={vulnsOverTime} fallback={data.scan_activity} />
        </div>

        {/* Top Vuln Types */}
        <div className="bg-[#12121a] rounded-xl border border-[#1e1e2e] p-5">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider flex items-center gap-2">
              <AlertTriangle className="w-4 h-4" />
              {t("dash.top_vuln_types")}
            </h2>
            <span className="text-xs text-gray-600">Top 10</span>
          </div>
          <TopVulnTypesChart apiData={topVulnTypes} fallback={data.vulns_by_type} />
        </div>
      </div>

      {/* Bottom Row: Recent Activity + Riskiest Targets */}
      <div className="grid grid-cols-2 gap-4">
        {/* Recent Activity Feed */}
        <div className="bg-[#12121a] rounded-xl border border-[#1e1e2e] p-5">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider flex items-center gap-2">
              <Activity className="w-4 h-4" />
              Recent Activity
            </h2>
          </div>
          <RecentActivityFeed apiData={recentActivity} fallbackVulns={data.recent_vulns} fallbackScans={data.recent_scans} />
        </div>

        {/* Riskiest Targets */}
        <div className="bg-[#12121a] rounded-xl border border-[#1e1e2e] p-5">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider flex items-center gap-2">
              <Crosshair className="w-4 h-4" />
              Riskiest Targets
            </h2>
            <a href="/targets" className="text-xs text-purple-400 hover:text-purple-300 flex items-center gap-1 transition">
              {t("dash.view_all")} <ArrowRight className="w-3 h-3" />
            </a>
          </div>
          <RiskiestTargetsTable apiData={targetRisk} />
        </div>
      </div>
    </div>
  );
}

// --- Vulns Over Time Bar Chart ---
function VulnsOverTimeChart({
  data,
  fallback,
}: {
  data: VulnOverTimeEntry[];
  fallback: DashboardData["scan_activity"];
}) {
  // Use API data if available, else build from fallback scan_activity
  const entries: { date: string; critical: number; high: number; medium: number; low: number; info: number; total: number }[] =
    data.length > 0
      ? data.slice(-14).map((d) => ({
          date: d.date,
          critical: d.critical || 0,
          high: d.high || 0,
          medium: d.medium || 0,
          low: d.low || 0,
          info: d.info || 0,
          total: d.count || 0,
        }))
      : fallback.slice(-14).map((d) => ({
          date: d.date,
          critical: 0,
          high: 0,
          medium: 0,
          low: 0,
          info: 0,
          total: d.vulns,
        }));

  const maxTotal = Math.max(...entries.map((e) => e.total), 1);

  if (entries.length === 0) {
    return (
      <div className="flex items-center justify-center h-36 text-gray-600 text-sm">
        No data yet
      </div>
    );
  }

  return (
    <>
      <div className="flex items-end gap-1 h-36">
        {entries.map((day, i) => {
          const dateObj = new Date(day.date + "T00:00:00");
          const dateNum = dateObj.getDate();
          const totalH = maxTotal > 0 ? (day.total / maxTotal) * 100 : 0;

          // Stacked segments
          const segments = [
            { count: day.critical, color: "bg-red-600" },
            { count: day.high, color: "bg-orange-500" },
            { count: day.medium, color: "bg-amber-500" },
            { count: day.low, color: "bg-blue-500" },
            { count: day.info, color: "bg-gray-600" },
          ];
          const hasBreakdown = segments.some((s) => s.count > 0);

          return (
            <div key={i} className="flex-1 flex flex-col items-center gap-0.5 group relative">
              {/* Tooltip */}
              <div className="absolute -top-10 left-1/2 -translate-x-1/2 bg-gray-800 border border-gray-700 rounded px-2 py-1 text-[10px] text-gray-300 whitespace-nowrap opacity-0 group-hover:opacity-100 transition pointer-events-none z-10">
                {day.total} vulns
              </div>
              <div className="w-full flex-1 flex items-end justify-center" style={{ height: 120 }}>
                {hasBreakdown ? (
                  <div
                    className="w-[70%] flex flex-col-reverse rounded-t overflow-hidden transition-all"
                    style={{ height: `${Math.max(totalH > 0 ? 4 : 0, totalH)}%` }}
                  >
                    {segments.map((seg, si) => {
                      if (seg.count === 0 || day.total === 0) return null;
                      const segPct = (seg.count / day.total) * 100;
                      return (
                        <div
                          key={si}
                          className={cn(seg.color, "w-full")}
                          style={{ height: `${segPct}%`, minHeight: seg.count > 0 ? 2 : 0 }}
                        />
                      );
                    })}
                  </div>
                ) : (
                  <div
                    className="w-[70%] bg-purple-600/70 rounded-t transition-all"
                    style={{ height: `${Math.max(totalH > 0 ? 4 : 0, totalH)}%` }}
                  />
                )}
              </div>
              <span className="text-[9px] text-gray-600 leading-none">{dateNum}</span>
            </div>
          );
        })}
      </div>
      <div className="flex items-center justify-center gap-4 mt-3 text-[10px] text-gray-600">
        <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-sm bg-red-600" /> Critical</span>
        <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-sm bg-orange-500" /> High</span>
        <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-sm bg-amber-500" /> Medium</span>
        <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-sm bg-blue-500" /> Low</span>
      </div>
    </>
  );
}

// --- Top Vuln Types Horizontal Bar Chart ---
function TopVulnTypesChart({
  apiData,
  fallback,
}: {
  apiData: TopVulnTypeEntry[];
  fallback: Record<string, number>;
}) {
  const entries: { type: string; count: number }[] =
    apiData.length > 0
      ? apiData.slice(0, 10)
      : Object.entries(fallback)
          .sort((a, b) => b[1] - a[1])
          .slice(0, 10)
          .map(([type, count]) => ({ type, count }));

  const maxCount = Math.max(...entries.map((e) => e.count), 1);

  if (entries.length === 0) {
    return (
      <div className="flex items-center justify-center h-36 text-gray-600 text-sm">
        No vulnerability types found yet
      </div>
    );
  }

  return (
    <div className="space-y-2">
      {entries.map((entry, i) => {
        const pct = (entry.count / maxCount) * 100;
        return (
          <div key={entry.type} className="flex items-center gap-3">
            <span className="text-[11px] text-gray-400 w-32 truncate font-mono" title={entry.type}>
              {formatVulnType(entry.type)}
            </span>
            <div className="flex-1 h-5 bg-[#0a0a0f] rounded overflow-hidden">
              <div
                className="h-full rounded transition-all duration-500"
                style={{
                  width: `${Math.max(pct > 0 ? 3 : 0, pct)}%`,
                  background: `linear-gradient(90deg, rgba(168,85,247,0.7) 0%, rgba(168,85,247,0.3) 100%)`,
                }}
              />
            </div>
            <span className="text-xs text-gray-300 font-medium w-8 text-right">{entry.count}</span>
          </div>
        );
      })}
    </div>
  );
}

// --- Recent Activity Feed ---
function RecentActivityFeed({
  apiData,
  fallbackVulns,
  fallbackScans,
}: {
  apiData: ActivityEntry[];
  fallbackVulns: DashboardData["recent_vulns"];
  fallbackScans: DashboardData["recent_scans"];
}) {
  // Merge from API or build from fallback
  const items: ActivityEntry[] =
    apiData.length > 0
      ? apiData.slice(0, 15)
      : [
          ...fallbackVulns.map((v) => ({
            type: "vuln" as const,
            id: v.id,
            title: v.title,
            severity: v.severity,
            target_domain: v.target_domain,
            created_at: v.created_at,
          })),
          ...fallbackScans.map((s) => ({
            type: "scan" as const,
            id: s.id,
            title: `${s.scan_type} scan`,
            status: s.status,
            target_domain: s.target_domain,
            created_at: s.created_at || "",
          })),
        ]
          .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime())
          .slice(0, 15);

  if (items.length === 0) {
    return (
      <div className="flex items-center justify-center h-36 text-gray-600 text-sm">
        No recent activity
      </div>
    );
  }

  return (
    <div className="space-y-1 max-h-[400px] overflow-y-auto pr-1 custom-scrollbar">
      {items.map((item, i) => (
        <div
          key={`${item.type}-${item.id}-${i}`}
          className="flex items-start gap-3 p-2.5 rounded-lg hover:bg-[#0a0a0f]/50 transition cursor-pointer group"
          onClick={() =>
            window.location.href = item.type === "vuln"
              ? `/vulnerabilities/${item.id}`
              : `/scans/${item.id}`
          }
        >
          {/* Timeline dot */}
          <div className="flex flex-col items-center mt-1">
            <div className={cn(
              "w-2 h-2 rounded-full flex-shrink-0",
              item.type === "vuln"
                ? severityDotColor(item.severity || "info")
                : statusDotColor(item.status || "completed")
            )} />
            {i < items.length - 1 && (
              <div className="w-px h-8 bg-[#1e1e2e] mt-1" />
            )}
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-sm text-gray-200 truncate group-hover:text-purple-300 transition">
              {item.title}
            </p>
            <div className="flex items-center gap-2 mt-0.5">
              {item.type === "vuln" && item.severity && (
                <SeverityBadge severity={item.severity} />
              )}
              {item.type === "scan" && item.status && (
                <span className={cn(
                  "text-[9px] px-1.5 py-0.5 rounded border font-medium uppercase",
                  scanStatusBadge(item.status)
                )}>
                  {item.status}
                </span>
              )}
              <span className="text-[10px] text-gray-500">{item.target_domain}</span>
            </div>
          </div>
          <span className="text-[10px] text-gray-600 whitespace-nowrap mt-0.5">
            {timeAgo(item.created_at)}
          </span>
        </div>
      ))}
    </div>
  );
}

// --- Riskiest Targets Table ---
function RiskiestTargetsTable({ apiData }: { apiData: TargetRiskEntry[] }) {
  if (apiData.length === 0) {
    return (
      <div className="flex items-center justify-center h-36 text-gray-600 text-sm">
        No targets scanned yet
      </div>
    );
  }

  const maxRisk = Math.max(...apiData.map((t) => t.risk_score), 1);

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="text-[10px] text-gray-500 uppercase tracking-wider border-b border-[#1e1e2e]">
            <th className="text-left py-2 font-medium">Domain</th>
            <th className="text-center py-2 font-medium">Risk</th>
            <th className="text-center py-2 font-medium">C</th>
            <th className="text-center py-2 font-medium">H</th>
            <th className="text-center py-2 font-medium">M</th>
            <th className="text-center py-2 font-medium">L</th>
            <th className="text-center py-2 font-medium">Total</th>
          </tr>
        </thead>
        <tbody>
          {apiData.slice(0, 10).map((target) => {
            const riskPct = (target.risk_score / maxRisk) * 100;
            return (
              <tr
                key={target.id}
                className="border-b border-[#1e1e2e]/50 hover:bg-[#0a0a0f]/50 transition cursor-pointer"
                onClick={() => window.location.href = `/targets/${target.id}`}
              >
                <td className="py-2.5 pr-3">
                  <div className="flex items-center gap-2">
                    <span className="text-gray-200 font-mono text-xs truncate max-w-[160px]">{target.domain}</span>
                  </div>
                </td>
                <td className="py-2.5 px-1">
                  <div className="flex items-center gap-2">
                    <div className="flex-1 h-2 bg-[#0a0a0f] rounded-full overflow-hidden">
                      <div
                        className="h-full rounded-full transition-all"
                        style={{
                          width: `${riskPct}%`,
                          background: riskGradient(target.risk_score, maxRisk),
                        }}
                      />
                    </div>
                    <span className={cn(
                      "text-[10px] font-bold w-6 text-right",
                      riskColor(target.risk_score, maxRisk)
                    )}>
                      {target.risk_score}
                    </span>
                  </div>
                </td>
                <td className="py-2.5 text-center">
                  <span className={cn("text-[11px] font-medium", target.critical > 0 ? "text-red-400" : "text-gray-700")}>
                    {target.critical}
                  </span>
                </td>
                <td className="py-2.5 text-center">
                  <span className={cn("text-[11px] font-medium", target.high > 0 ? "text-orange-400" : "text-gray-700")}>
                    {target.high}
                  </span>
                </td>
                <td className="py-2.5 text-center">
                  <span className={cn("text-[11px] font-medium", target.medium > 0 ? "text-amber-400" : "text-gray-700")}>
                    {target.medium}
                  </span>
                </td>
                <td className="py-2.5 text-center">
                  <span className={cn("text-[11px] font-medium", target.low > 0 ? "text-blue-400" : "text-gray-700")}>
                    {target.low}
                  </span>
                </td>
                <td className="py-2.5 text-center">
                  <span className="text-[11px] text-gray-300 font-medium">{target.total_vulns}</span>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

// --- Sub-components ---

function StatCard({
  icon: Icon,
  label,
  value,
  color,
  pulse,
  href,
  isText,
}: {
  icon: any;
  label: string;
  value: number | string;
  color: string;
  pulse?: boolean;
  href?: string;
  isText?: boolean;
}) {
  const colorMap: Record<string, { border: string; text: string; bg: string; icon: string }> = {
    blue: { border: "border-blue-900/50", text: "text-blue-400", bg: "bg-blue-950/30", icon: "text-blue-400" },
    purple: { border: "border-purple-900/50", text: "text-purple-400", bg: "bg-purple-950/30", icon: "text-purple-400" },
    red: { border: "border-red-900/50", text: "text-red-400", bg: "bg-red-950/30", icon: "text-red-400" },
    green: { border: "border-green-900/50", text: "text-green-400", bg: "bg-green-950/30", icon: "text-green-400" },
    yellow: { border: "border-yellow-900/50", text: "text-yellow-400", bg: "bg-yellow-950/30", icon: "text-yellow-400" },
    cyan: { border: "border-cyan-900/50", text: "text-cyan-400", bg: "bg-cyan-950/30", icon: "text-cyan-400" },
  };
  const c = colorMap[color] || colorMap.blue;

  const content = (
    <div className={cn(
      "bg-[#12121a] rounded-xl border p-4 transition hover:bg-[#1a1a28]",
      c.border,
      href && "cursor-pointer"
    )}>
      <div className="flex items-center justify-between mb-3">
        <div className={cn("w-9 h-9 rounded-lg flex items-center justify-center", c.bg, pulse && "animate-pulse")}>
          <Icon className={cn("w-4.5 h-4.5", c.icon)} />
        </div>
        {href && <ArrowRight className="w-3.5 h-3.5 text-gray-700" />}
      </div>
      <p className={cn(
        "font-bold text-white",
        isText ? "text-lg capitalize" : "text-3xl"
      )}>
        {typeof value === "number" ? value.toLocaleString() : value}
      </p>
      <p className="text-[11px] text-gray-500 mt-0.5">{label}</p>
    </div>
  );

  if (href) {
    return <a href={href}>{content}</a>;
  }
  return content;
}

function SeverityBadge({ severity }: { severity: string }) {
  const colors: Record<string, string> = {
    critical: "bg-red-950/80 text-red-400 border-red-900/60",
    high: "bg-orange-950/80 text-orange-400 border-orange-900/60",
    medium: "bg-amber-950/80 text-amber-400 border-amber-900/60",
    low: "bg-blue-950/80 text-blue-400 border-blue-900/60",
    info: "bg-gray-800 text-gray-400 border-gray-700",
  };
  return (
    <span className={cn(
      "text-[9px] px-2 py-0.5 rounded border font-bold uppercase tracking-wide whitespace-nowrap",
      colors[severity] || colors.info
    )}>
      {severity}
    </span>
  );
}

// --- Helpers ---

function formatVulnType(type: string): string {
  return type
    .replace(/_/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

function severityDotColor(severity: string): string {
  const map: Record<string, string> = {
    critical: "bg-red-500",
    high: "bg-orange-500",
    medium: "bg-amber-500",
    low: "bg-blue-500",
    info: "bg-gray-500",
  };
  return map[severity] || "bg-gray-500";
}

function statusDotColor(status: string): string {
  const map: Record<string, string> = {
    running: "bg-green-400 animate-pulse",
    queued: "bg-yellow-400 animate-pulse",
    completed: "bg-blue-400",
    failed: "bg-red-400",
    stopped: "bg-gray-500",
  };
  return map[status] || "bg-gray-500";
}

function scanStatusBadge(status: string): string {
  const map: Record<string, string> = {
    running: "bg-green-950/50 text-green-400 border-green-900/50",
    queued: "bg-yellow-950/50 text-yellow-400 border-yellow-900/50",
    completed: "bg-blue-950/50 text-blue-400 border-blue-900/50",
    failed: "bg-red-950/50 text-red-400 border-red-900/50",
    stopped: "bg-gray-800 text-gray-400 border-gray-700",
  };
  return map[status] || "bg-gray-800 text-gray-400 border-gray-700";
}

function riskGradient(score: number, max: number): string {
  const ratio = max > 0 ? score / max : 0;
  if (ratio > 0.7) return "linear-gradient(90deg, #dc2626, #ef4444)";
  if (ratio > 0.4) return "linear-gradient(90deg, #f59e0b, #f97316)";
  return "linear-gradient(90deg, #3b82f6, #6366f1)";
}

function riskColor(score: number, max: number): string {
  const ratio = max > 0 ? score / max : 0;
  if (ratio > 0.7) return "text-red-400";
  if (ratio > 0.4) return "text-orange-400";
  return "text-blue-400";
}
