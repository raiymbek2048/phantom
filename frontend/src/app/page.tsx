"use client";

import { useState, useEffect, useCallback } from "react";
import { useAuthStore } from "@/lib/store";
import { useNotifications } from "@/lib/notifications";
import LoginForm from "@/components/LoginForm";
import Sidebar from "@/components/Sidebar";
import { getDashboardStats, createTarget, createScan, getTargets } from "@/lib/api";
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
  const [loading, setLoading] = useState(true);
  const [domain, setDomain] = useState("");
  const [scanType, setScanType] = useState("full");
  const [launching, setLaunching] = useState(false);
  const notify = useNotifications((s) => s.add);
  const t = useT();

  const load = useCallback(async () => {
    try {
      const stats = await getDashboardStats();
      setData(stats);
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
    data.vulns_by_severity.critical +
    data.vulns_by_severity.high +
    data.vulns_by_severity.medium +
    data.vulns_by_severity.low +
    data.vulns_by_severity.info;
  const maxSevCount = Math.max(
    ...Object.values(data.vulns_by_severity),
    1
  );
  const maxTypeCount = Math.max(
    ...Object.values(data.vulns_by_type),
    1
  );

  // Scan activity for last 14 days
  const last14 = data.scan_activity.slice(-14);
  const maxDayScans = Math.max(...last14.map((d) => d.scans), 1);
  const maxDayVulns = Math.max(...last14.map((d) => d.vulns), 1);

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
      <div className="bg-gray-900 rounded-xl border border-gray-800 p-4">
        <div className="flex gap-2">
          <div className="relative flex-1">
            <Globe className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-600" />
            <input
              type="text"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleQuickScan()}
              placeholder={t("dash.placeholder")}
              className="w-full bg-gray-800 border border-gray-700 rounded-lg pl-9 pr-3 py-2.5 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-red-500/50 focus:ring-1 focus:ring-red-500/20 transition"
            />
          </div>
          <select
            value={scanType}
            onChange={(e) => setScanType(e.target.value)}
            className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2.5 text-sm text-white focus:outline-none focus:border-red-500/50"
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
            className="bg-red-600 hover:bg-red-500 disabled:opacity-40 disabled:hover:bg-red-600 text-white px-6 py-2.5 rounded-lg text-sm font-medium transition flex items-center gap-2"
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

      {/* Stats Row */}
      <div className="grid grid-cols-6 gap-3">
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
          icon={Activity}
          label={t("dash.active_scans")}
          value={data.active_scans}
          color="green"
          pulse={data.active_scans > 0}
        />
        <StatCard
          icon={Eye}
          label={t("dash.monitored")}
          value={data.monitored_targets}
          color="yellow"
        />
        <StatCard
          icon={Cpu}
          label={t("dash.llm")}
          value={data.llm_provider}
          color="cyan"
          isText
        />
      </div>

      {/* Middle Row: Severity Chart + Scan Activity */}
      <div className="grid grid-cols-2 gap-4">
        {/* Vulnerability Severity */}
        <div className="bg-gray-900 rounded-xl border border-gray-800 p-5">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider flex items-center gap-2">
              <BarChart3 className="w-4 h-4" />
              {t("dash.vuln_severity")}
            </h2>
            <span className="text-xs text-gray-600">{totalSevVulns} {t("dash.total")}</span>
          </div>
          <div className="space-y-3">
            <SeverityBar label={t("sev.critical")} count={data.vulns_by_severity.critical} max={maxSevCount} color="bg-red-600" textColor="text-red-400" />
            <SeverityBar label={t("sev.high")} count={data.vulns_by_severity.high} max={maxSevCount} color="bg-orange-500" textColor="text-orange-400" />
            <SeverityBar label={t("sev.medium")} count={data.vulns_by_severity.medium} max={maxSevCount} color="bg-amber-500" textColor="text-amber-400" />
            <SeverityBar label={t("sev.low")} count={data.vulns_by_severity.low} max={maxSevCount} color="bg-blue-500" textColor="text-blue-400" />
            <SeverityBar label={t("sev.info")} count={data.vulns_by_severity.info} max={maxSevCount} color="bg-gray-500" textColor="text-gray-400" />
          </div>
        </div>

        {/* Scan Activity */}
        <div className="bg-gray-900 rounded-xl border border-gray-800 p-5">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider flex items-center gap-2">
              <TrendingUp className="w-4 h-4" />
              {t("dash.scan_activity")}
            </h2>
            <span className="text-xs text-gray-600">{t("dash.last_14")}</span>
          </div>
          <div className="flex items-end gap-1 h-32">
            {last14.map((day, i) => {
              const scanH = maxDayScans > 0 ? (day.scans / maxDayScans) * 100 : 0;
              const vulnH = maxDayVulns > 0 ? (day.vulns / maxDayVulns) * 100 : 0;
              const dateObj = new Date(day.date + "T00:00:00");
              const dayLabel = dateObj.toLocaleDateString("en", { weekday: "short" }).charAt(0);
              const dateNum = dateObj.getDate();
              return (
                <div key={i} className="flex-1 flex flex-col items-center gap-0.5 group relative">
                  {/* Tooltip */}
                  <div className="absolute -top-10 left-1/2 -translate-x-1/2 bg-gray-800 border border-gray-700 rounded px-2 py-1 text-[10px] text-gray-300 whitespace-nowrap opacity-0 group-hover:opacity-100 transition pointer-events-none z-10">
                    {day.scans}s / {day.vulns}v
                  </div>
                  <div className="w-full flex flex-col items-center gap-0.5" style={{ height: 100 }}>
                    <div className="w-full flex-1 flex items-end justify-center gap-px">
                      <div
                        className="w-[45%] bg-red-600/80 rounded-t transition-all"
                        style={{ height: `${Math.max(scanH > 0 ? 4 : 0, scanH)}%` }}
                      />
                      <div
                        className="w-[45%] bg-amber-500/60 rounded-t transition-all"
                        style={{ height: `${Math.max(vulnH > 0 ? 4 : 0, vulnH)}%` }}
                      />
                    </div>
                  </div>
                  <span className="text-[9px] text-gray-600 leading-none">{dateNum}</span>
                </div>
              );
            })}
          </div>
          <div className="flex items-center justify-center gap-4 mt-3 text-[10px] text-gray-600">
            <span className="flex items-center gap-1">
              <span className="w-2 h-2 rounded-sm bg-red-600/80" /> {t("dash.scans_legend")}
            </span>
            <span className="flex items-center gap-1">
              <span className="w-2 h-2 rounded-sm bg-amber-500/60" /> {t("dash.vulns_legend")}
            </span>
          </div>
        </div>
      </div>

      {/* Tables Row: Recent Vulns + Recent Scans */}
      <div className="grid grid-cols-2 gap-4">
        {/* Recent Vulnerabilities */}
        <div className="bg-gray-900 rounded-xl border border-gray-800 p-5">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider flex items-center gap-2">
              <Bug className="w-4 h-4" />
              {t("dash.recent_vulns")}
            </h2>
            <a href="/vulnerabilities" className="text-xs text-red-400 hover:text-red-300 flex items-center gap-1 transition">
              {t("dash.view_all")} <ArrowRight className="w-3 h-3" />
            </a>
          </div>
          {data.recent_vulns.length === 0 ? (
            <div className="text-center py-8">
              <ShieldAlert className="w-8 h-8 text-gray-700 mx-auto mb-2" />
              <p className="text-gray-600 text-sm">{t("dash.no_vulns")}</p>
            </div>
          ) : (
            <div className="space-y-1">
              {data.recent_vulns.map((v) => (
                <div
                  key={v.id}
                  className="flex items-center gap-3 p-2.5 rounded-lg hover:bg-gray-800/50 transition cursor-pointer group"
                  onClick={() => window.location.href = `/vulnerabilities/${v.id}`}
                >
                  <SeverityBadge severity={v.severity} />
                  <div className="flex-1 min-w-0">
                    <p className="text-sm text-white truncate group-hover:text-red-300 transition">
                      {v.title}
                    </p>
                    <div className="flex items-center gap-2 mt-0.5">
                      <span className="text-[10px] text-gray-600 font-mono">{formatVulnType(v.vuln_type)}</span>
                      <span className="text-[10px] text-gray-700">|</span>
                      <span className="text-[10px] text-gray-500">{v.target_domain}</span>
                    </div>
                  </div>
                  <span className="text-[10px] text-gray-600 whitespace-nowrap">
                    {timeAgo(v.created_at)}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Recent Scans */}
        <div className="bg-gray-900 rounded-xl border border-gray-800 p-5">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider flex items-center gap-2">
              <Clock className="w-4 h-4" />
              {t("dash.recent_scans")}
            </h2>
            <a href="/scans" className="text-xs text-red-400 hover:text-red-300 flex items-center gap-1 transition">
              {t("dash.view_all")} <ArrowRight className="w-3 h-3" />
            </a>
          </div>
          {data.recent_scans.length === 0 ? (
            <div className="text-center py-8">
              <Scan className="w-8 h-8 text-gray-700 mx-auto mb-2" />
              <p className="text-gray-600 text-sm">{t("dash.no_scans")}</p>
            </div>
          ) : (
            <div className="space-y-1">
              {data.recent_scans.map((s) => {
                const duration = getDuration(s.started_at, s.completed_at);
                return (
                  <div
                    key={s.id}
                    className="flex items-center gap-3 p-2.5 rounded-lg hover:bg-gray-800/50 transition cursor-pointer group"
                    onClick={() => window.location.href = `/scans/${s.id}`}
                  >
                    <StatusDot status={s.status} />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <p className="text-sm text-white truncate group-hover:text-red-300 transition">
                          {s.target_domain || "Unknown"}
                        </p>
                        <span className={cn(
                          "text-[9px] px-1.5 py-0.5 rounded border font-medium uppercase",
                          scanTypeBadge(s.scan_type)
                        )}>
                          {s.scan_type}
                        </span>
                      </div>
                      <div className="flex items-center gap-3 mt-0.5 text-[10px]">
                        <span className="text-gray-500">
                          {s.endpoints_found} {t("dash.endpoints")}
                        </span>
                        <span className={cn(
                          "font-medium",
                          s.vulns_found > 0 ? "text-red-400" : "text-gray-600"
                        )}>
                          {s.vulns_found} {t("dash.vulns")}
                        </span>
                        {duration && (
                          <span className="text-gray-600">{duration}</span>
                        )}
                      </div>
                    </div>
                    <div className="text-right">
                      <span className="text-[10px] text-gray-600 whitespace-nowrap">
                        {timeAgo(s.created_at || "")}
                      </span>
                    </div>
                    <ChevronRight className="w-3.5 h-3.5 text-gray-700 group-hover:text-gray-500 transition" />
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>

      {/* Bottom Row: Top Vuln Types */}
      {Object.keys(data.vulns_by_type).length > 0 && (
        <div className="bg-gray-900 rounded-xl border border-gray-800 p-5">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider flex items-center gap-2">
              <AlertTriangle className="w-4 h-4" />
              {t("dash.top_vuln_types")}
            </h2>
            <span className="text-xs text-gray-600">{t("dash.top")} {Object.keys(data.vulns_by_type).length}</span>
          </div>
          <div className="grid grid-cols-2 gap-x-6 gap-y-2.5">
            {Object.entries(data.vulns_by_type).map(([type, count]) => (
              <div key={type} className="flex items-center gap-3">
                <span className="text-xs text-gray-400 w-36 truncate font-mono" title={type}>
                  {formatVulnType(type)}
                </span>
                <div className="flex-1 h-5 bg-gray-800 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-gradient-to-r from-red-600/70 to-red-500/50 rounded-full transition-all duration-500"
                    style={{ width: `${Math.max((count / maxTypeCount) * 100, 3)}%` }}
                  />
                </div>
                <span className="text-xs text-gray-400 font-medium w-8 text-right">{count}</span>
              </div>
            ))}
          </div>
        </div>
      )}
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
      "bg-gray-900 rounded-xl border p-4 transition hover:bg-gray-800/50",
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
        isText ? "text-lg capitalize" : "text-2xl"
      )}>
        {value}
      </p>
      <p className="text-[11px] text-gray-500 mt-0.5">{label}</p>
    </div>
  );

  if (href) {
    return <a href={href}>{content}</a>;
  }
  return content;
}

function SeverityBar({
  label,
  count,
  max,
  color,
  textColor,
}: {
  label: string;
  count: number;
  max: number;
  color: string;
  textColor: string;
}) {
  const pct = max > 0 ? (count / max) * 100 : 0;
  return (
    <div className="flex items-center gap-3">
      <span className={cn("text-xs w-16 font-medium", textColor)}>{label}</span>
      <div className="flex-1 h-6 bg-gray-800 rounded-md overflow-hidden relative">
        <div
          className={cn("h-full rounded-md transition-all duration-700", color)}
          style={{ width: `${Math.max(pct > 0 ? 2 : 0, pct)}%`, opacity: 0.7 }}
        />
        {count > 0 && (
          <span className="absolute right-2 top-1/2 -translate-y-1/2 text-[11px] text-gray-300 font-medium">
            {count}
          </span>
        )}
      </div>
    </div>
  );
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

function StatusDot({ status }: { status: string }) {
  const colors: Record<string, string> = {
    running: "bg-green-400 animate-pulse",
    queued: "bg-yellow-400 animate-pulse",
    completed: "bg-blue-400",
    failed: "bg-red-400",
    stopped: "bg-gray-500",
    paused: "bg-yellow-500",
  };
  return (
    <div className={cn("w-2 h-2 rounded-full flex-shrink-0", colors[status] || "bg-gray-500")} />
  );
}

function scanTypeBadge(scanType: string): string {
  const map: Record<string, string> = {
    AI: "bg-purple-950/50 text-purple-400 border-purple-900/50",
    quick: "bg-green-950/50 text-green-400 border-green-900/50",
    full: "bg-blue-950/50 text-blue-400 border-blue-900/50",
    stealth: "bg-yellow-950/50 text-yellow-400 border-yellow-900/50",
    recon: "bg-cyan-950/50 text-cyan-400 border-cyan-900/50",
  };
  return map[scanType] || "bg-gray-800 text-gray-400 border-gray-700";
}

function formatVulnType(type: string): string {
  return type
    .replace(/_/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

function getDuration(
  start: string | null,
  end: string | null
): string | null {
  if (!start || !end) return null;
  const ms = new Date(end).getTime() - new Date(start).getTime();
  if (ms < 0) return null;
  const secs = Math.floor(ms / 1000);
  if (secs < 60) return `${secs}s`;
  const mins = Math.floor(secs / 60);
  const remSecs = secs % 60;
  if (mins < 60) return `${mins}m ${remSecs}s`;
  const hours = Math.floor(mins / 60);
  const remMins = mins % 60;
  return `${hours}h ${remMins}m`;
}
