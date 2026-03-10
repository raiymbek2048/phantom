"use client";

import { useState, useEffect } from "react";
import { useAuthStore } from "@/lib/store";
import { useT } from "@/lib/i18n";
import LoginForm from "@/components/LoginForm";
import Sidebar from "@/components/Sidebar";
import {
  getSubmissionsDashboard,
  getProgramsDashboard,
  getAutopilotStatus,
  getHackeroneStats,
} from "@/lib/api";
import {
  Trophy,
  DollarSign,
  Send,
  CheckCircle,
  Bug,
  Cpu,
  BarChart3,
  RefreshCw,
} from "lucide-react";

function utc(iso: string | null | undefined): string {
  if (!iso) return "";
  return iso.endsWith("Z") ? iso : iso + "Z";
}

export default function BountyHubPage() {
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
        <BountyHubContent />
      </main>
    </div>
  );
}

function BountyHubContent() {
  const t = useT();
  const [subDash, setSubDash] = useState<any>(null);
  const [progDash, setProgDash] = useState<any>(null);
  const [autopilot, setAutopilot] = useState<any>(null);
  const [h1Stats, setH1Stats] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  const load = async () => {
    setLoading(true);
    try {
      const [s, p, a, h] = await Promise.allSettled([
        getSubmissionsDashboard(),
        getProgramsDashboard(),
        getAutopilotStatus(),
        getHackeroneStats(),
      ]);
      if (s.status === "fulfilled") setSubDash(s.value);
      if (p.status === "fulfilled") setProgDash(p.value);
      if (a.status === "fulfilled") setAutopilot(a.value);
      if (h.status === "fulfilled") setH1Stats(h.value);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  const totalBounty = subDash?.bounties?.total || 0;
  const acceptanceRate = subDash?.rates?.acceptance_rate || 0;
  const duplicateRate = subDash?.rates?.duplicate_rate || 0;
  const totalSubmissions = subDash?.total_submissions || 0;
  const avgBounty = subDash?.bounties?.average || 0;

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-3">
            <Trophy className="w-7 h-7 text-yellow-400" />
            {t("bounty.title")}
          </h1>
          <p className="text-gray-500 text-sm mt-1">{t("bounty.subtitle")}</p>
        </div>
        <button
          onClick={load}
          className="flex items-center gap-2 px-4 py-2 bg-gray-800 hover:bg-gray-700 rounded-lg text-sm text-gray-300 transition-colors"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
          Refresh
        </button>
      </div>

      {/* Top Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard
          icon={<DollarSign className="w-5 h-5 text-green-400" />}
          label={t("bounty.total_bounties")}
          value={`$${totalBounty.toLocaleString()}`}
          color="green"
        />
        <StatCard
          icon={<CheckCircle className="w-5 h-5 text-blue-400" />}
          label={t("bounty.acceptance_rate")}
          value={`${(acceptanceRate * 100).toFixed(0)}%`}
          color="blue"
        />
        <StatCard
          icon={<Send className="w-5 h-5 text-purple-400" />}
          label={t("bounty.total_reports")}
          value={totalSubmissions}
          color="purple"
        />
        <StatCard
          icon={<DollarSign className="w-5 h-5 text-yellow-400" />}
          label={t("bounty.avg_bounty")}
          value={`$${avgBounty.toFixed(0)}`}
          color="yellow"
        />
      </div>

      {/* Main Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Programs Overview */}
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
          <h2 className="text-lg font-semibold text-white flex items-center gap-2 mb-4">
            <Bug className="w-5 h-5 text-red-400" />
            {t("bounty.programs_overview")}
          </h2>
          {progDash ? (
            <div className="space-y-3">
              <div className="flex justify-between text-sm">
                <span className="text-gray-400">Total Programs</span>
                <span className="text-white font-mono">{progDash.total_programs || 0}</span>
              </div>
              <div className="flex justify-between text-sm">
                <span className="text-gray-400">With Bounties</span>
                <span className="text-green-400 font-mono">{progDash.with_bounties || 0}</span>
              </div>
              <div className="flex justify-between text-sm">
                <span className="text-gray-400">Scored</span>
                <span className="text-blue-400 font-mono">{progDash.scored || 0}</span>
              </div>
              <div className="flex justify-between text-sm">
                <span className="text-gray-400">Avg ROI Score</span>
                <span className="text-yellow-400 font-mono">{(progDash.avg_roi_score || 0).toFixed(0)}</span>
              </div>
              {(progDash.top_recommendations || progDash.top_programs)?.slice(0, 3).map((p: any, i: number) => (
                <div key={i} className="flex justify-between items-center text-sm bg-gray-800/50 rounded-lg px-3 py-2">
                  <span className="text-gray-300">{p.name || p.handle}</span>
                  <span className="text-green-400 font-mono text-xs">${(p.avg_bounty || 0).toFixed(0)}</span>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-gray-600 text-sm">No program data yet. Collect programs first.</p>
          )}
        </div>

        {/* Submissions Status */}
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
          <h2 className="text-lg font-semibold text-white flex items-center gap-2 mb-4">
            <Send className="w-5 h-5 text-purple-400" />
            {t("bounty.submission_status")}
          </h2>
          {subDash && subDash.total_submissions > 0 ? (
            <div className="space-y-3">
              <div className="flex justify-between text-sm">
                <span className="text-gray-400">Accepted</span>
                <span className="text-green-400 font-mono">{subDash.by_status?.accepted || 0}</span>
              </div>
              <div className="flex justify-between text-sm">
                <span className="text-gray-400">Duplicates</span>
                <span className="text-yellow-400 font-mono">{subDash.by_status?.duplicate || 0}</span>
              </div>
              <div className="flex justify-between text-sm">
                <span className="text-gray-400">Informative</span>
                <span className="text-gray-400 font-mono">{subDash.by_status?.informative || 0}</span>
              </div>
              <div className="flex justify-between text-sm">
                <span className="text-gray-400">Duplicate Rate</span>
                <span className={`font-mono ${duplicateRate > 0.3 ? "text-red-400" : "text-gray-300"}`}>
                  {(duplicateRate * 100).toFixed(0)}%
                </span>
              </div>
              <div className="flex justify-between text-sm">
                <span className="text-gray-400">Avg Triage Days</span>
                <span className="text-gray-300 font-mono">{(subDash.avg_triage_days || 0).toFixed(1)}</span>
              </div>
              {/* Program breakdown */}
              {subDash.program_breakdown?.slice(0, 3).map((p: any, i: number) => (
                <div key={i} className="flex justify-between items-center text-sm bg-gray-800/50 rounded-lg px-3 py-2">
                  <span className="text-gray-300">{p.program_handle}</span>
                  <div className="flex gap-3 text-xs">
                    <span className="text-green-400">{p.accepted || 0} acc</span>
                    <span className="text-yellow-400">{p.duplicate || 0} dup</span>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-gray-600 text-sm">No submissions yet. Start scanning and submit reports.</p>
          )}
        </div>

        {/* Autopilot Status */}
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
          <h2 className="text-lg font-semibold text-white flex items-center gap-2 mb-4">
            <Cpu className="w-5 h-5 text-cyan-400" />
            {t("bounty.autopilot_status")}
          </h2>
          {autopilot ? (
            <div className="space-y-3">
              <div className="flex justify-between text-sm">
                <span className="text-gray-400">Active Scans</span>
                <span className={`font-mono ${autopilot.active_scans > 0 ? "text-green-400" : "text-gray-500"}`}>
                  {autopilot.active_scans}
                </span>
              </div>
              <div className="flex justify-between text-sm">
                <span className="text-gray-400">Available Programs</span>
                <span className="text-white font-mono">{autopilot.available_programs}</span>
              </div>
              <div className="flex justify-between text-sm">
                <span className="text-gray-400">Pending Drafts</span>
                <span className="text-yellow-400 font-mono">{autopilot.pending_drafts}</span>
              </div>
              <div className="flex justify-between text-sm">
                <span className="text-gray-400">Scans (24h)</span>
                <span className="text-blue-400 font-mono">{autopilot.scans_last_24h}</span>
              </div>
              {autopilot.next_recommended && (
                <div className="bg-gray-800/50 rounded-lg px-3 py-2 mt-2">
                  <p className="text-xs text-gray-500 mb-1">Next Recommended</p>
                  <p className="text-sm text-white">{autopilot.next_recommended.name || autopilot.next_recommended.program}</p>
                  <p className="text-xs text-green-400 font-mono">ROI: {(autopilot.next_recommended.roi_score || 0).toFixed(0)}</p>
                </div>
              )}
            </div>
          ) : (
            <p className="text-gray-600 text-sm">Autopilot status unavailable.</p>
          )}
        </div>

        {/* H1 Knowledge Base */}
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
          <h2 className="text-lg font-semibold text-white flex items-center gap-2 mb-4">
            <BarChart3 className="w-5 h-5 text-orange-400" />
            {t("bounty.knowledge_base")}
          </h2>
          {h1Stats ? (
            <div className="space-y-3">
              <div className="flex justify-between text-sm">
                <span className="text-gray-400">Total Reports</span>
                <span className="text-white font-mono">{h1Stats.total_reports || 0}</span>
              </div>
              <div className="flex justify-between text-sm">
                <span className="text-gray-400">Disclosed</span>
                <span className="text-blue-400 font-mono">{h1Stats.disclosed_reports || 0}</span>
              </div>
              <div className="flex justify-between text-sm">
                <span className="text-gray-400">Analyzed</span>
                <span className="text-purple-400 font-mono">{h1Stats.analyzed_reports || 0}</span>
              </div>
              <div className="flex justify-between text-sm">
                <span className="text-gray-400">H1 Insights</span>
                <span className="text-green-400 font-mono">{h1Stats.h1_insights || 0}</span>
              </div>
              {/* Top programs from KB */}
              {h1Stats.top_programs?.slice(0, 3).map((p: any, i: number) => (
                <div key={i} className="flex justify-between items-center text-xs bg-gray-800/50 rounded-lg px-3 py-1.5">
                  <span className="text-gray-400">{p.program}</span>
                  <span className="text-green-400 font-mono">${(p.total_bounty || 0).toLocaleString()}</span>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-gray-600 text-sm">No H1 data. Run &quot;Collect Hacktivity&quot; first.</p>
          )}
        </div>
      </div>
    </div>
  );
}

function StatCard({ icon, label, value, color }: { icon: React.ReactNode; label: string; value: any; color: string }) {
  const bgMap: Record<string, string> = {
    green: "from-green-600/10 to-green-600/5 border-green-800/30",
    blue: "from-blue-600/10 to-blue-600/5 border-blue-800/30",
    purple: "from-purple-600/10 to-purple-600/5 border-purple-800/30",
    yellow: "from-yellow-600/10 to-yellow-600/5 border-yellow-800/30",
    red: "from-red-600/10 to-red-600/5 border-red-800/30",
    cyan: "from-cyan-600/10 to-cyan-600/5 border-cyan-800/30",
  };

  return (
    <div className={`bg-gradient-to-br ${bgMap[color] || bgMap.blue} border rounded-xl p-4`}>
      <div className="flex items-center gap-2 mb-2">
        {icon}
        <span className="text-xs text-gray-500 uppercase tracking-wider">{label}</span>
      </div>
      <p className="text-2xl font-bold text-white font-mono">{value}</p>
    </div>
  );
}
