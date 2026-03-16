"use client";

import { useState, useEffect, useCallback } from "react";
import { useAuthStore } from "@/lib/store";
import { useT } from "@/lib/i18n";
import LoginForm from "@/components/LoginForm";
import Sidebar from "@/components/Sidebar";
import {
  getTargets,
  getVulnerabilities,
  createScan,
  getCampaignStatus,
  createCampaign,
} from "@/lib/api";
import { cn } from "@/lib/utils";
import {
  Crosshair,
  Loader2,
  AlertTriangle,
  Play,
  CheckCircle,
  Clock,
  Target,
  ShieldAlert,
  Trash2,
  Plus,
  Square,
  XCircle,
} from "lucide-react";

// --- Types ---
interface CampaignLocal {
  id: string;
  name: string;
  techFilter: string;
  vulnTypeFilter: string;
  targetIds: string[];
  status: "running" | "completed" | "paused";
  scanIds: string[];
  vulnsFound: number;
  createdAt: string;
  campaignId?: string; // backend campaign ID
}

const VULN_TYPES = [
  "xss", "sqli", "ssrf", "info_disclosure", "auth_bypass",
  "misconfiguration", "ssti", "lfi", "cmd_injection", "idor",
  "cors", "xxe", "rce",
];

export default function CampaignsPage() {
  const { isLoggedIn } = useAuthStore();
  const t = useT();

  const [loading, setLoading] = useState(true);
  const [targets, setTargets] = useState<any[]>([]);
  const [campaigns, setCampaigns] = useState<CampaignLocal[]>([]);
  const [error, setError] = useState("");

  // Creator state
  const [showCreator, setShowCreator] = useState(false);
  const [name, setName] = useState("");
  const [techFilter, setTechFilter] = useState("");
  const [vulnTypeFilter, setVulnTypeFilter] = useState("");
  const [selectedTargetIds, setSelectedTargetIds] = useState<Set<string>>(new Set());
  const [selectAll, setSelectAll] = useState(false);
  const [launching, setLaunching] = useState(false);

  // View campaign results
  const [viewingCampaign, setViewingCampaign] = useState<string | null>(null);
  const [campaignVulns, setCampaignVulns] = useState<any[]>([]);

  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const tgs = await getTargets();
      setTargets(Array.isArray(tgs) ? tgs : []);

      // Load campaigns from localStorage
      const stored = localStorage.getItem("phantom_campaigns");
      if (stored) {
        setCampaigns(JSON.parse(stored));
      }
    } catch (e: any) {
      setError(e.message || "Failed to load data");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  // Persist campaigns to localStorage
  const saveCampaigns = (updated: CampaignLocal[]) => {
    setCampaigns(updated);
    localStorage.setItem("phantom_campaigns", JSON.stringify(updated));
  };

  // Filter targets by tech
  const filteredTargets = targets.filter((tgt: any) => {
    if (!techFilter.trim()) return true;
    const techs: string[] = tgt.technologies || [];
    return techs.some((t) => t.toLowerCase().includes(techFilter.toLowerCase()));
  });

  const toggleTarget = (id: string) => {
    const next = new Set(selectedTargetIds);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    setSelectedTargetIds(next);
  };

  const handleSelectAll = () => {
    if (selectAll) {
      setSelectedTargetIds(new Set());
    } else {
      setSelectedTargetIds(new Set(filteredTargets.map((t: any) => t.id)));
    }
    setSelectAll(!selectAll);
  };

  const launchCampaign = async () => {
    if (!name.trim() || selectedTargetIds.size === 0) return;
    setLaunching(true);
    setError("");

    try {
      const targetIds = Array.from(selectedTargetIds);
      let campaignId: string | undefined;

      // Use backend campaign API
      try {
        const result = await createCampaign(targetIds, "full", 5);
        campaignId = result.campaign_id;
      } catch {
        // Fallback: launch individual scans
        for (const tid of targetIds) {
          try {
            await createScan(tid, "full", 5);
          } catch {
            // ignore individual failures
          }
        }
      }

      const campaign: CampaignLocal = {
        id: Date.now().toString(),
        name: name.trim(),
        techFilter,
        vulnTypeFilter,
        targetIds,
        status: "running",
        scanIds: [],
        vulnsFound: 0,
        createdAt: new Date().toISOString(),
        campaignId,
      };

      saveCampaigns([campaign, ...campaigns]);
      setShowCreator(false);
      setName("");
      setTechFilter("");
      setVulnTypeFilter("");
      setSelectedTargetIds(new Set());
      setSelectAll(false);
    } catch (e: any) {
      setError(e.message || "Failed to launch campaign");
    } finally {
      setLaunching(false);
    }
  };

  const deleteCampaign = (id: string) => {
    saveCampaigns(campaigns.filter((c) => c.id !== id));
  };

  const refreshCampaignStatus = async (campaign: CampaignLocal) => {
    if (!campaign.campaignId) return;
    try {
      const status = await getCampaignStatus(campaign.campaignId);
      const updated = campaigns.map((c) => {
        if (c.id === campaign.id) {
          return {
            ...c,
            status: status.all_completed ? "completed" as const : "running" as const,
            vulnsFound: status.total_vulns || c.vulnsFound,
          };
        }
        return c;
      });
      saveCampaigns(updated);
    } catch {
      // silent
    }
  };

  const viewResults = async (campaign: CampaignLocal) => {
    setViewingCampaign(campaign.id);
    try {
      const vulns = await getVulnerabilities();
      const arr = Array.isArray(vulns) ? vulns : [];
      // Filter vulns by campaign target IDs
      const targetIdSet = new Set(campaign.targetIds);
      const filtered = arr.filter((v: any) => targetIdSet.has(v.target_id));
      setCampaignVulns(filtered);
    } catch {
      setCampaignVulns([]);
    }
  };

  if (!isLoggedIn) return <LoginForm />;

  const statusIcon = (status: string) => {
    switch (status) {
      case "running": return <Clock className="w-3.5 h-3.5 text-yellow-400 animate-pulse" />;
      case "completed": return <CheckCircle className="w-3.5 h-3.5 text-green-400" />;
      case "paused": return <Square className="w-3.5 h-3.5 text-gray-400" />;
      default: return <Clock className="w-3.5 h-3.5 text-gray-400" />;
    }
  };

  const sevColor = (sev: string) => {
    const map: Record<string, string> = {
      critical: "text-red-400 bg-red-950",
      high: "text-orange-400 bg-orange-950",
      medium: "text-yellow-400 bg-yellow-950",
      low: "text-blue-400 bg-blue-950",
      info: "text-gray-400 bg-gray-800",
    };
    return map[sev] || map.info;
  };

  return (
    <div className="flex min-h-screen bg-[#0a0a0a]">
      <Sidebar />
      <main className="flex-1 ml-60 p-6">
        {/* Header */}
        <div className="flex items-center justify-between mb-8">
          <div>
            <h1 className="text-2xl font-bold text-white flex items-center gap-3">
              <Crosshair className="w-7 h-7 text-red-400" />
              {t("campaigns.title")}
            </h1>
            <p className="text-sm text-gray-500 mt-1">{t("campaigns.subtitle")}</p>
          </div>
          <button
            onClick={() => setShowCreator(!showCreator)}
            className={cn(
              "flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors",
              showCreator
                ? "bg-gray-800 text-gray-400"
                : "bg-red-600/20 text-red-400 border border-red-700 hover:bg-red-600/30"
            )}
          >
            {showCreator ? <XCircle className="w-4 h-4" /> : <Plus className="w-4 h-4" />}
            {showCreator ? t("common.cancel") : t("campaigns.new")}
          </button>
        </div>

        {error && (
          <div className="mb-6 p-4 bg-red-950/50 border border-red-800 rounded-lg text-red-400 text-sm flex items-center gap-2">
            <AlertTriangle className="w-4 h-4" /> {error}
          </div>
        )}

        {/* Campaign Creator */}
        {showCreator && (
          <div className="bg-gray-900/50 border border-gray-800 rounded-xl p-5 mb-8">
            <h3 className="text-sm font-semibold text-white mb-4">{t("campaigns.creator")}</h3>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
              {/* Name */}
              <div>
                <label className="text-xs text-gray-500 mb-1 block">{t("campaigns.name")}</label>
                <input
                  type="text"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder={t("campaigns.name_placeholder")}
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-200 placeholder-gray-600 focus:outline-none focus:border-red-600"
                />
              </div>

              {/* Tech Filter */}
              <div>
                <label className="text-xs text-gray-500 mb-1 block">{t("campaigns.tech_filter")}</label>
                <input
                  type="text"
                  value={techFilter}
                  onChange={(e) => setTechFilter(e.target.value)}
                  placeholder={t("campaigns.tech_placeholder")}
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-200 placeholder-gray-600 focus:outline-none focus:border-red-600"
                />
              </div>

              {/* Vuln Type Filter */}
              <div>
                <label className="text-xs text-gray-500 mb-1 block">{t("campaigns.vuln_filter")}</label>
                <select
                  value={vulnTypeFilter}
                  onChange={(e) => setVulnTypeFilter(e.target.value)}
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-300 focus:outline-none focus:border-red-600"
                >
                  <option value="">{t("vulns.filter_all")}</option>
                  {VULN_TYPES.map((vt) => (
                    <option key={vt} value={vt}>{vt}</option>
                  ))}
                </select>
              </div>
            </div>

            {/* Target Selection */}
            <div className="mb-4">
              <div className="flex items-center justify-between mb-2">
                <label className="text-xs text-gray-500">
                  {t("campaigns.select_targets")} ({selectedTargetIds.size}/{filteredTargets.length})
                </label>
                <button
                  onClick={handleSelectAll}
                  className="text-xs text-gray-500 hover:text-gray-300 transition-colors"
                >
                  {selectAll ? t("campaigns.deselect_all") : t("campaigns.select_all")}
                </button>
              </div>

              <div className="max-h-48 overflow-y-auto border border-gray-800 rounded-lg divide-y divide-gray-800">
                {filteredTargets.length === 0 ? (
                  <div className="p-3 text-xs text-gray-600">{t("campaigns.no_matching_targets")}</div>
                ) : (
                  filteredTargets.map((tgt: any) => (
                    <label
                      key={tgt.id}
                      className="flex items-center gap-3 px-3 py-2.5 hover:bg-gray-800/50 cursor-pointer transition-colors"
                    >
                      <input
                        type="checkbox"
                        checked={selectedTargetIds.has(tgt.id)}
                        onChange={() => toggleTarget(tgt.id)}
                        className="w-3.5 h-3.5 rounded border-gray-700 bg-gray-800 text-red-500 focus:ring-0 focus:ring-offset-0"
                      />
                      <Target className="w-3.5 h-3.5 text-gray-500" />
                      <span className="text-xs text-gray-300 font-mono flex-1">{tgt.domain}</span>
                      <div className="flex gap-1">
                        {(tgt.technologies || []).slice(0, 3).map((tech: string) => (
                          <span
                            key={tech}
                            className="px-1.5 py-0.5 text-[9px] bg-purple-500/10 text-purple-400 rounded font-mono"
                          >
                            {tech}
                          </span>
                        ))}
                      </div>
                    </label>
                  ))
                )}
              </div>
            </div>

            {/* Launch Button */}
            <button
              onClick={launchCampaign}
              disabled={launching || !name.trim() || selectedTargetIds.size === 0}
              className={cn(
                "flex items-center gap-2 px-5 py-2.5 rounded-lg text-sm font-medium transition-colors",
                launching || !name.trim() || selectedTargetIds.size === 0
                  ? "bg-gray-800 text-gray-600 cursor-not-allowed"
                  : "bg-red-600 text-white hover:bg-red-700"
              )}
            >
              {launching ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
              {launching ? t("campaigns.launching") : t("campaigns.launch")}
            </button>
          </div>
        )}

        {loading ? (
          <div className="flex items-center justify-center h-64 text-gray-500">
            <Loader2 className="w-8 h-8 animate-spin" />
          </div>
        ) : (
          <>
            {/* Active Campaigns Table */}
            <div className="bg-gray-900/50 border border-gray-800 rounded-xl overflow-hidden mb-8">
              <div className="px-5 py-4 border-b border-gray-800">
                <h3 className="text-sm font-semibold text-white">{t("campaigns.active_campaigns")}</h3>
              </div>

              {campaigns.length === 0 ? (
                <div className="p-8 text-center text-gray-600 text-sm">
                  {t("campaigns.no_campaigns")}
                </div>
              ) : (
                <div className="divide-y divide-gray-800">
                  {campaigns.map((campaign) => (
                    <div key={campaign.id} className="px-5 py-3 hover:bg-gray-800/30 transition-colors">
                      <div className="flex items-center gap-4">
                        {statusIcon(campaign.status)}
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2">
                            <span className="text-sm text-gray-200 font-medium">{campaign.name}</span>
                            <span className={cn(
                              "px-1.5 py-0.5 text-[10px] rounded capitalize font-mono",
                              campaign.status === "running" ? "bg-yellow-950 text-yellow-400" :
                              campaign.status === "completed" ? "bg-green-950 text-green-400" :
                              "bg-gray-800 text-gray-400"
                            )}>
                              {campaign.status}
                            </span>
                          </div>
                          <div className="flex items-center gap-3 mt-1">
                            <span className="text-[10px] text-gray-600">
                              {campaign.targetIds.length} {t("campaigns.targets_count")}
                            </span>
                            {campaign.techFilter && (
                              <span className="text-[10px] text-purple-400">tech: {campaign.techFilter}</span>
                            )}
                            {campaign.vulnTypeFilter && (
                              <span className="text-[10px] text-red-400">vuln: {campaign.vulnTypeFilter}</span>
                            )}
                            <span className="text-[10px] text-gray-600">
                              {new Date(campaign.createdAt).toLocaleDateString()}
                            </span>
                          </div>
                        </div>

                        <div className="flex items-center gap-3">
                          <div className="text-right">
                            <span className="text-sm text-white font-mono">{campaign.vulnsFound}</span>
                            <span className="text-[10px] text-gray-500 ml-1">vulns</span>
                          </div>

                          <div className="flex gap-1">
                            {campaign.campaignId && (
                              <button
                                onClick={() => refreshCampaignStatus(campaign)}
                                className="p-1.5 text-gray-500 hover:text-gray-300 transition-colors"
                                title="Refresh status"
                              >
                                <Clock className="w-3.5 h-3.5" />
                              </button>
                            )}
                            <button
                              onClick={() => viewResults(campaign)}
                              className="p-1.5 text-gray-500 hover:text-blue-400 transition-colors"
                              title="View results"
                            >
                              <ShieldAlert className="w-3.5 h-3.5" />
                            </button>
                            <button
                              onClick={() => deleteCampaign(campaign.id)}
                              className="p-1.5 text-gray-500 hover:text-red-400 transition-colors"
                              title="Delete"
                            >
                              <Trash2 className="w-3.5 h-3.5" />
                            </button>
                          </div>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Campaign Results (when viewing) */}
            {viewingCampaign && (
              <div className="bg-gray-900/50 border border-gray-800 rounded-xl p-5">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                    <ShieldAlert className="w-4 h-4 text-red-400" />
                    {t("campaigns.results")} ({campaignVulns.length})
                  </h3>
                  <button
                    onClick={() => { setViewingCampaign(null); setCampaignVulns([]); }}
                    className="text-xs text-gray-500 hover:text-gray-300"
                  >
                    {t("common.close")}
                  </button>
                </div>

                {campaignVulns.length === 0 ? (
                  <p className="text-xs text-gray-600">{t("campaigns.no_vulns")}</p>
                ) : (
                  <div className="space-y-2 max-h-96 overflow-y-auto">
                    {campaignVulns.map((vuln: any) => (
                      <div
                        key={vuln.id}
                        className="flex items-center gap-3 px-3 py-2.5 bg-gray-800/50 rounded-lg"
                      >
                        <span className={cn("px-1.5 py-0.5 text-[10px] rounded capitalize", sevColor(vuln.severity))}>
                          {vuln.severity}
                        </span>
                        <span className="text-[10px] text-gray-500 font-mono uppercase">{vuln.vuln_type}</span>
                        <span className="text-xs text-gray-300 flex-1 truncate">{vuln.title}</span>
                        {vuln.title?.includes("[CONFIRMED]") && (
                          <CheckCircle className="w-3.5 h-3.5 text-green-400" />
                        )}
                        <span className="text-[10px] text-gray-600 font-mono truncate max-w-[150px]">
                          {vuln.url}
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </>
        )}
      </main>
    </div>
  );
}
