"use client";

import { useState, useEffect } from "react";
import { useT } from "@/lib/i18n";
import { useAuthStore } from "@/lib/store";
import LoginForm from "@/components/LoginForm";
import Sidebar from "@/components/Sidebar";
import {
  getProgramsDashboard,
  getProgramRecommendations,
  refreshPrograms,
  getProgram,
} from "@/lib/api";
import {
  Bug,
  RefreshCw,
  Star,
  Globe,
  ChevronDown,
  ChevronUp,
} from "lucide-react";

export default function ProgramsPage() {
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
        <ProgramsContent />
      </main>
    </div>
  );
}

function ProgramsContent() {
  const t = useT();
  const [dashboard, setDashboard] = useState<any>(null);
  const [recommendations, setRecommendations] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [expandedProgram, setExpandedProgram] = useState<string | null>(null);
  const [programDetail, setProgramDetail] = useState<any>(null);
  const [sortBy, setSortBy] = useState<"roi" | "bounty" | "name">("roi");
  const [filterBounty, setFilterBounty] = useState(false);

  const load = async () => {
    setLoading(true);
    try {
      const [d, r] = await Promise.allSettled([
        getProgramsDashboard(),
        getProgramRecommendations(20),
      ]);
      if (d.status === "fulfilled") setDashboard(d.value);
      if (r.status === "fulfilled") setRecommendations(r.value);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  const handleRefresh = async () => {
    setRefreshing(true);
    try {
      await refreshPrograms(50);
      await load();
    } finally {
      setRefreshing(false);
    }
  };

  const handleExpandProgram = async (handle: string) => {
    if (expandedProgram === handle) {
      setExpandedProgram(null);
      setProgramDetail(null);
      return;
    }
    setExpandedProgram(handle);
    try {
      const detail = await getProgram(handle);
      setProgramDetail(detail);
    } catch {
      setProgramDetail(null);
    }
  };

  const programs = Array.isArray(recommendations) ? recommendations : (recommendations?.recommendations || []);

  const sortedPrograms = [...programs].sort((a: any, b: any) => {
    if (sortBy === "roi") return (b.roi_score || 0) - (a.roi_score || 0);
    if (sortBy === "bounty") return (b.avg_bounty || 0) - (a.avg_bounty || 0);
    return (a.name || a.handle || "").localeCompare(b.name || b.handle || "");
  });

  const filteredPrograms = filterBounty
    ? sortedPrograms.filter((p: any) => (p.avg_bounty || 0) > 0)
    : sortedPrograms;

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-3">
            <Bug className="w-7 h-7 text-red-400" />
            {t("programs.title")}
          </h1>
          <p className="text-gray-500 text-sm mt-1">
            {dashboard?.total_programs || 0} {t("programs.tracked")}, {dashboard?.scored || 0} {t("programs.scored")}
          </p>
        </div>
        <button
          onClick={handleRefresh}
          disabled={refreshing}
          className="flex items-center gap-2 px-4 py-2 bg-red-600 hover:bg-red-700 disabled:bg-gray-700 rounded-lg text-sm text-white transition-colors"
        >
          <RefreshCw className={`w-4 h-4 ${refreshing ? "animate-spin" : ""}`} />
          {refreshing ? t("programs.refreshing") : t("programs.refresh")}
        </button>
      </div>

      {/* Stats Cards */}
      {dashboard && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
            <p className="text-xs text-gray-500 uppercase">{t("programs.total_programs")}</p>
            <p className="text-2xl font-bold text-white font-mono mt-1">{dashboard.total_programs}</p>
          </div>
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
            <p className="text-xs text-gray-500 uppercase">{t("programs.with_bounties")}</p>
            <p className="text-2xl font-bold text-green-400 font-mono mt-1">{dashboard.with_bounties}</p>
          </div>
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
            <p className="text-xs text-gray-500 uppercase">{t("programs.avg_roi_score")}</p>
            <p className="text-2xl font-bold text-yellow-400 font-mono mt-1">{(dashboard.avg_roi_score || 0).toFixed(0)}</p>
          </div>
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
            <p className="text-xs text-gray-500 uppercase">{t("programs.scanned_by_us")}</p>
            <p className="text-2xl font-bold text-blue-400 font-mono mt-1">{dashboard.scanned || 0}</p>
          </div>
        </div>
      )}

      {/* Controls */}
      <div className="flex items-center gap-4">
        <div className="flex bg-gray-800 rounded-lg overflow-hidden text-sm">
          {(["roi", "bounty", "name"] as const).map((s) => (
            <button
              key={s}
              onClick={() => setSortBy(s)}
              className={`px-3 py-1.5 capitalize ${sortBy === s ? "bg-red-600 text-white" : "text-gray-400 hover:text-white"}`}
            >
              {s === "roi" ? t("programs.roi_score") : s === "bounty" ? t("programs.avg_bounty") : t("programs.name")}
            </button>
          ))}
        </div>
        <label className="flex items-center gap-2 text-sm text-gray-400 cursor-pointer">
          <input
            type="checkbox"
            checked={filterBounty}
            onChange={(e) => setFilterBounty(e.target.checked)}
            className="rounded bg-gray-800 border-gray-700"
          />
          {t("programs.only_with_bounty")}
        </label>
      </div>

      {/* Programs List */}
      {loading ? (
        <div className="text-center text-gray-500 py-12">{t("programs.loading")}</div>
      ) : filteredPrograms.length === 0 ? (
        <div className="text-center text-gray-500 py-12">
          {t("programs.no_programs")} {t("programs.no_programs_hint")}
        </div>
      ) : (
        <div className="space-y-2">
          {filteredPrograms.map((p: any, i: number) => (
            <div key={p.handle || i} className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
              {/* Main Row */}
              <div
                className="flex items-center justify-between p-4 cursor-pointer hover:bg-gray-800/50 transition-colors"
                onClick={() => handleExpandProgram(p.handle)}
              >
                <div className="flex items-center gap-4">
                  <div className="w-8 h-8 bg-gray-800 rounded-lg flex items-center justify-center text-xs font-bold text-gray-400">
                    #{i + 1}
                  </div>
                  <div>
                    <p className="text-white font-medium">{p.name || p.handle}</p>
                    <p className="text-xs text-gray-500">{p.handle}</p>
                  </div>
                </div>
                <div className="flex items-center gap-6">
                  <div className="text-right">
                    <p className="text-xs text-gray-500">{t("programs.roi")}</p>
                    <p className="text-sm font-mono text-yellow-400">{(p.roi_score || 0).toFixed(0)}</p>
                  </div>
                  <div className="text-right">
                    <p className="text-xs text-gray-500">{t("programs.avg_bounty")}</p>
                    <p className="text-sm font-mono text-green-400">${(p.avg_bounty || 0).toFixed(0)}</p>
                  </div>
                  <div className="text-right">
                    <p className="text-xs text-gray-500">{t("programs.difficulty")}</p>
                    <p className="text-sm font-mono text-gray-300">{((p.difficulty || p.difficulty_score || 0) * 100).toFixed(0)}%</p>
                  </div>
                  <div className="text-right">
                    <p className="text-xs text-gray-500">{t("programs.scope")}</p>
                    <p className="text-sm font-mono text-blue-400">{p.scope_size || 0}</p>
                  </div>
                  {expandedProgram === p.handle ? (
                    <ChevronUp className="w-4 h-4 text-gray-500" />
                  ) : (
                    <ChevronDown className="w-4 h-4 text-gray-500" />
                  )}
                </div>
              </div>

              {/* Expanded Detail */}
              {expandedProgram === p.handle && programDetail && (
                <div className="border-t border-gray-800 p-4 bg-gray-950/50">
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
                    <div>
                      <p className="text-xs text-gray-500">{t("programs.max_bounty")}</p>
                      <p className="text-sm font-mono text-green-400">${(programDetail.max_bounty || 0).toLocaleString()}</p>
                    </div>
                    <div>
                      <p className="text-xs text-gray-500">{t("programs.base_bounty")}</p>
                      <p className="text-sm font-mono text-gray-300">${(programDetail.base_bounty || 0).toLocaleString()}</p>
                    </div>
                    <div>
                      <p className="text-xs text-gray-500">{t("programs.our_reports")}</p>
                      <p className="text-sm font-mono text-blue-400">{programDetail.our_stats?.reports || 0}</p>
                    </div>
                    <div>
                      <p className="text-xs text-gray-500">{t("programs.our_bounty")}</p>
                      <p className="text-sm font-mono text-green-400">${(programDetail.our_stats?.bounty_earned || 0).toLocaleString()}</p>
                    </div>
                  </div>
                  {/* Scope */}
                  {programDetail.scope?.length > 0 && (
                    <div>
                      <p className="text-xs text-gray-500 mb-2 uppercase">{t("programs.scope")} ({programDetail.scope.length} assets)</p>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-1.5 max-h-40 overflow-y-auto">
                        {programDetail.scope.slice(0, 10).map((s: any, j: number) => (
                          <div key={j} className="flex items-center gap-2 text-xs bg-gray-800/50 rounded px-2 py-1.5">
                            <Globe className="w-3 h-3 text-gray-600" />
                            <span className="text-gray-300 truncate">{s.asset}</span>
                            <span className={`ml-auto text-[10px] ${s.bounty_eligible ? "text-green-500" : "text-gray-600"}`}>
                              {s.type}
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                  {/* Reasoning */}
                  {p.reasons?.length > 0 && (
                    <div className="mt-3">
                      <p className="text-xs text-gray-500 mb-1 uppercase">{t("programs.why_this")}</p>
                      <ul className="space-y-1">
                        {p.reasons.map((r: string, j: number) => (
                          <li key={j} className="text-xs text-gray-400 flex items-start gap-1.5">
                            <Star className="w-3 h-3 text-yellow-500 mt-0.5 shrink-0" />
                            {r}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

