"use client";

import { useState, useEffect, useCallback } from "react";
import { useAuthStore } from "@/lib/store";
import { useT } from "@/lib/i18n";
import LoginForm from "@/components/LoginForm";
import Sidebar from "@/components/Sidebar";
import {
  getGraphSummary,
  getGraphTechChain,
  getGraphAttackSurface,
  getGraphSimilarTargets,
  getTargets,
} from "@/lib/api";
import { cn } from "@/lib/utils";
import {
  GitBranch,
  Loader2,
  AlertTriangle,
  RefreshCw,
  ChevronDown,
  ChevronRight,
  Search,
  Zap,
  Shield,
  Globe,
  Database,
  Cpu,
  Target,
  Eye,
} from "lucide-react";

// --- Types ---
interface GraphSummary {
  total_nodes: number;
  total_edges: number;
  nodes_by_type: Record<string, number>;
  edges_by_type: Record<string, number>;
}

interface TechChain {
  technology: string;
  vulnerabilities: Array<{
    type: string;
    weight: number;
    techniques: Array<{ name: string; weight: number }>;
  }>;
}

interface AttackSurfaceResult {
  technologies: string[];
  vulnerabilities: Array<{ type: string; priority: number; description?: string }>;
  techniques: Array<{ name: string; vuln_type: string; weight: number }>;
  waf_bypasses: Array<{ pattern: string; confidence: number }>;
}

interface SimilarTarget {
  domain: string;
  shared_techs: string[];
  vuln_count: number;
}

const NODE_COLORS: Record<string, string> = {
  technology: "bg-purple-500/20 text-purple-400 border-purple-700",
  vulnerability: "bg-red-500/20 text-red-400 border-red-700",
  technique: "bg-blue-500/20 text-blue-400 border-blue-700",
  payload: "bg-green-500/20 text-green-400 border-green-700",
  target: "bg-yellow-500/20 text-yellow-400 border-yellow-700",
  waf_bypass: "bg-cyan-500/20 text-cyan-400 border-cyan-700",
};

const EDGE_COLORS: Record<string, string> = {
  vulnerable_to: "bg-red-500/20 text-red-400",
  exploited_by: "bg-orange-500/20 text-orange-400",
  bypasses: "bg-cyan-500/20 text-cyan-400",
  uses_tech: "bg-purple-500/20 text-purple-400",
  similar_to: "bg-yellow-500/20 text-yellow-400",
};

export default function KnowledgeGraphPage() {
  const { isLoggedIn } = useAuthStore();
  const t = useT();

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [summary, setSummary] = useState<GraphSummary | null>(null);
  const [targets, setTargets] = useState<any[]>([]);

  // Tech chains
  const [expandedTechs, setExpandedTechs] = useState<Set<string>>(new Set());
  const [techChains, setTechChains] = useState<Record<string, TechChain>>({});
  const [loadingChains, setLoadingChains] = useState<Set<string>>(new Set());

  // Similar targets
  const [similarTargets, setSimilarTargets] = useState<SimilarTarget[]>([]);
  const [selectedTarget, setSelectedTarget] = useState("");

  // Attack surface
  const [attackTechs, setAttackTechs] = useState("");
  const [attackResult, setAttackResult] = useState<AttackSurfaceResult | null>(null);
  const [attackLoading, setAttackLoading] = useState(false);

  const loadData = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const [s, tg] = await Promise.allSettled([getGraphSummary(), getTargets()]);
      if (s.status === "fulfilled") setSummary(s.value);
      if (tg.status === "fulfilled") setTargets(Array.isArray(tg.value) ? tg.value : []);
    } catch (e: any) {
      setError(e.message || "Failed to load graph data");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const toggleTech = async (tech: string) => {
    const next = new Set(expandedTechs);
    if (next.has(tech)) {
      next.delete(tech);
      setExpandedTechs(next);
      return;
    }
    next.add(tech);
    setExpandedTechs(next);

    if (!techChains[tech]) {
      setLoadingChains((prev) => new Set(prev).add(tech));
      try {
        const chain = await getGraphTechChain(tech);
        setTechChains((prev) => ({ ...prev, [tech]: chain }));
      } catch {
        // silently fail
      } finally {
        setLoadingChains((prev) => {
          const n = new Set(prev);
          n.delete(tech);
          return n;
        });
      }
    }
  };

  const loadSimilarTargets = async (domain: string) => {
    setSelectedTarget(domain);
    const target = targets.find((t: any) => t.domain === domain);
    if (!target) return;
    const techs = target.technologies || [];
    try {
      const result = await getGraphSimilarTargets(domain, techs);
      setSimilarTargets(Array.isArray(result) ? result : result?.targets || []);
    } catch {
      setSimilarTargets([]);
    }
  };

  const runAttackSurface = async () => {
    if (!attackTechs.trim()) return;
    setAttackLoading(true);
    try {
      const techs = attackTechs.split(",").map((t) => t.trim()).filter(Boolean);
      const result = await getGraphAttackSurface(techs);
      setAttackResult(result);
    } catch {
      setAttackResult(null);
    } finally {
      setAttackLoading(false);
    }
  };

  if (!isLoggedIn) return <LoginForm />;

  const techNodes = summary?.nodes_by_type?.technology || summary?.nodes_by_type?.tech || 0;
  const techList = Object.keys(summary?.nodes_by_type || {}).includes("technology")
    ? [] // Will get from chain lookups
    : [];

  // Extract tech names from nodes_by_type for the tree view
  const allTechNames: string[] = [];
  // We use the summary node types as categories, and allow user to explore chains

  return (
    <div className="flex min-h-screen bg-[#0a0a0a]">
      <Sidebar />
      <main className="flex-1 ml-60 p-6">
        {/* Header */}
        <div className="flex items-center justify-between mb-8">
          <div>
            <h1 className="text-2xl font-bold text-white flex items-center gap-3">
              <GitBranch className="w-7 h-7 text-cyan-400" />
              {t("kg.title")}
            </h1>
            <p className="text-sm text-gray-500 mt-1">{t("kg.subtitle")}</p>
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

        {loading && !summary ? (
          <div className="flex items-center justify-center h-64 text-gray-500">
            <Loader2 className="w-8 h-8 animate-spin" />
          </div>
        ) : (
          <>
            {/* Graph Overview */}
            <div className="bg-gray-900/50 border border-gray-800 rounded-xl p-5 mb-8">
              <h3 className="text-sm font-semibold text-white mb-4">{t("kg.overview")}</h3>

              {/* Node types */}
              <div className="mb-4">
                <p className="text-xs text-gray-500 mb-2 uppercase tracking-wider">{t("kg.nodes")}</p>
                <div className="flex flex-wrap gap-2">
                  {summary && Object.entries(summary.nodes_by_type).map(([type, count]) => (
                    <span
                      key={type}
                      className={cn(
                        "px-3 py-1.5 rounded-lg text-xs font-mono border",
                        NODE_COLORS[type] || "bg-gray-800 text-gray-400 border-gray-700"
                      )}
                    >
                      {type}: <strong>{count}</strong>
                    </span>
                  ))}
                  {summary && (
                    <span className="px-3 py-1.5 rounded-lg text-xs font-mono bg-gray-800 text-gray-300 border border-gray-700">
                      {t("kg.total_nodes")}: <strong>{summary.total_nodes}</strong>
                    </span>
                  )}
                </div>
              </div>

              {/* Edge types */}
              <div>
                <p className="text-xs text-gray-500 mb-2 uppercase tracking-wider">{t("kg.edges")}</p>
                <div className="flex flex-wrap gap-2">
                  {summary && Object.entries(summary.edges_by_type).map(([type, count]) => (
                    <span
                      key={type}
                      className={cn(
                        "px-3 py-1.5 rounded-lg text-xs font-mono",
                        EDGE_COLORS[type] || "bg-gray-800 text-gray-400"
                      )}
                    >
                      {type}: <strong>{count}</strong>
                    </span>
                  ))}
                  {summary && (
                    <span className="px-3 py-1.5 rounded-lg text-xs font-mono bg-gray-800 text-gray-300">
                      {t("kg.total_edges")}: <strong>{summary.total_edges}</strong>
                    </span>
                  )}
                </div>
              </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Main: Tech -> Vuln -> Technique Chains */}
              <div className="lg:col-span-2 space-y-6">
                {/* Tech Chain Explorer */}
                <div className="bg-gray-900/50 border border-gray-800 rounded-xl p-5">
                  <h3 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
                    <Cpu className="w-4 h-4 text-purple-400" />
                    {t("kg.tech_chains")}
                  </h3>
                  <p className="text-xs text-gray-600 mb-3">{t("kg.tech_chains_desc")}</p>

                  {/* Clickable tech nodes from summary */}
                  {summary && Object.entries(summary.nodes_by_type)
                    .filter(([type]) => type === "technology" || type === "tech")
                    .length === 0 && (
                    <div className="space-y-1">
                      {/* Show all node types as explorable */}
                      {Object.entries(summary.nodes_by_type).map(([type, count]) => (
                        <div key={type} className="text-xs text-gray-500">
                          {type}: {count} nodes
                        </div>
                      ))}
                    </div>
                  )}

                  {/* If we have tech nodes, show them as expandable tree */}
                  {targets.length > 0 && (
                    <div className="space-y-1">
                      {(() => {
                        // Collect all unique techs from targets
                        const allTechs = new Set<string>();
                        targets.forEach((tgt: any) => {
                          const techs = tgt.technologies || [];
                          techs.forEach((t: string) => allTechs.add(t));
                        });
                        return Array.from(allTechs).sort().map((tech) => (
                          <div key={tech} className="border border-gray-800 rounded-lg overflow-hidden">
                            <button
                              onClick={() => toggleTech(tech)}
                              className="w-full flex items-center gap-2 px-3 py-2.5 text-left hover:bg-gray-800/50 transition-colors"
                            >
                              {expandedTechs.has(tech) ? (
                                <ChevronDown className="w-3.5 h-3.5 text-gray-500" />
                              ) : (
                                <ChevronRight className="w-3.5 h-3.5 text-gray-500" />
                              )}
                              <Cpu className="w-3.5 h-3.5 text-purple-400" />
                              <span className="text-xs text-gray-300 font-mono">{tech}</span>
                              {loadingChains.has(tech) && (
                                <Loader2 className="w-3 h-3 text-gray-500 animate-spin ml-auto" />
                              )}
                            </button>

                            {expandedTechs.has(tech) && techChains[tech] && (
                              <div className="border-t border-gray-800 bg-gray-950/50 px-3 py-2">
                                {techChains[tech].vulnerabilities?.length === 0 ? (
                                  <p className="text-xs text-gray-600 py-1">{t("kg.no_chains")}</p>
                                ) : (
                                  <div className="space-y-2">
                                    {(techChains[tech].vulnerabilities || []).map((vuln, vi) => (
                                      <div key={vi} className="ml-4">
                                        <div className="flex items-center gap-2 mb-1">
                                          <span className="text-[10px] text-gray-600">vulnerable_to</span>
                                          <span className="text-[10px] text-gray-700">--&gt;</span>
                                          <Shield className="w-3 h-3 text-red-400" />
                                          <span className="text-xs text-red-400 font-mono">{vuln.type}</span>
                                          {vuln.weight > 0 && (
                                            <span className="text-[10px] text-gray-600 ml-auto">
                                              w: {vuln.weight.toFixed(2)}
                                            </span>
                                          )}
                                        </div>
                                        {/* Weight bar */}
                                        <div className="ml-5 mb-1">
                                          <div className="h-1.5 w-24 bg-gray-800 rounded-full overflow-hidden">
                                            <div
                                              className="h-full bg-red-500/60 rounded-full"
                                              style={{ width: `${Math.min(vuln.weight * 100, 100)}%` }}
                                            />
                                          </div>
                                        </div>
                                        {/* Techniques */}
                                        {(vuln.techniques || []).map((tech, ti) => (
                                          <div key={ti} className="ml-8 flex items-center gap-2 py-0.5">
                                            <span className="text-[10px] text-gray-600">exploited_by</span>
                                            <span className="text-[10px] text-gray-700">--&gt;</span>
                                            <Zap className="w-3 h-3 text-blue-400" />
                                            <span className="text-[10px] text-blue-400 font-mono truncate max-w-[200px]">
                                              {tech.name}
                                            </span>
                                            <span className="text-[10px] text-gray-700 ml-auto">
                                              {tech.weight.toFixed(2)}
                                            </span>
                                          </div>
                                        ))}
                                      </div>
                                    ))}
                                  </div>
                                )}
                              </div>
                            )}
                          </div>
                        ));
                      })()}
                      {(() => {
                        const allTechs = new Set<string>();
                        targets.forEach((tgt: any) => {
                          (tgt.technologies || []).forEach((t: string) => allTechs.add(t));
                        });
                        return allTechs.size === 0 ? (
                          <p className="text-xs text-gray-600">{t("kg.no_techs")}</p>
                        ) : null;
                      })()}
                    </div>
                  )}
                </div>

                {/* Attack Surface Query */}
                <div className="bg-gray-900/50 border border-gray-800 rounded-xl p-5">
                  <h3 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
                    <Search className="w-4 h-4 text-yellow-400" />
                    {t("kg.attack_surface")}
                  </h3>
                  <div className="flex gap-2 mb-4">
                    <input
                      type="text"
                      value={attackTechs}
                      onChange={(e) => setAttackTechs(e.target.value)}
                      placeholder={t("kg.attack_surface_placeholder")}
                      className="flex-1 bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-200 placeholder-gray-600 focus:outline-none focus:border-yellow-600"
                    />
                    <button
                      onClick={runAttackSurface}
                      disabled={attackLoading || !attackTechs.trim()}
                      className={cn(
                        "px-4 py-2 rounded-lg text-sm font-medium transition-colors",
                        attackLoading || !attackTechs.trim()
                          ? "bg-gray-800 text-gray-600 cursor-not-allowed"
                          : "bg-yellow-600/20 text-yellow-400 border border-yellow-700 hover:bg-yellow-600/30"
                      )}
                    >
                      {attackLoading ? (
                        <Loader2 className="w-4 h-4 animate-spin" />
                      ) : (
                        t("kg.analyze")
                      )}
                    </button>
                  </div>

                  {attackResult && (
                    <div className="space-y-4">
                      {/* Vulnerabilities */}
                      {attackResult.vulnerabilities?.length > 0 && (
                        <div>
                          <p className="text-xs text-gray-500 uppercase mb-2">{t("kg.vulns_found")}</p>
                          <div className="space-y-1">
                            {attackResult.vulnerabilities.map((v, i) => (
                              <div
                                key={i}
                                className="flex items-center justify-between px-3 py-2 bg-gray-800/50 rounded-lg"
                              >
                                <span className="text-xs text-red-400 font-mono">{v.type}</span>
                                <span className="text-[10px] text-gray-500">
                                  priority: {v.priority?.toFixed?.(2) || v.priority}
                                </span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* Techniques */}
                      {attackResult.techniques?.length > 0 && (
                        <div>
                          <p className="text-xs text-gray-500 uppercase mb-2">{t("kg.techniques")}</p>
                          <div className="space-y-1">
                            {attackResult.techniques.slice(0, 15).map((tech, i) => (
                              <div
                                key={i}
                                className="flex items-center gap-2 px-3 py-1.5 bg-gray-800/50 rounded-lg"
                              >
                                <Zap className="w-3 h-3 text-blue-400" />
                                <span className="text-[10px] text-gray-300 font-mono truncate flex-1">
                                  {tech.name}
                                </span>
                                <span className="text-[10px] text-gray-600">{tech.vuln_type}</span>
                                <span className="text-[10px] text-gray-500">{tech.weight.toFixed(2)}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* WAF Bypasses */}
                      {attackResult.waf_bypasses?.length > 0 && (
                        <div>
                          <p className="text-xs text-gray-500 uppercase mb-2">{t("kg.waf_bypasses")}</p>
                          <div className="space-y-1">
                            {attackResult.waf_bypasses.slice(0, 10).map((wb, i) => (
                              <div
                                key={i}
                                className="flex items-center gap-2 px-3 py-1.5 bg-gray-800/50 rounded-lg"
                              >
                                <Shield className="w-3 h-3 text-cyan-400" />
                                <span className="text-[10px] text-gray-300 font-mono truncate flex-1">
                                  {wb.pattern}
                                </span>
                                <span className="text-[10px] text-gray-500">{(wb.confidence * 100).toFixed(0)}%</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {!attackResult.vulnerabilities?.length &&
                        !attackResult.techniques?.length &&
                        !attackResult.waf_bypasses?.length && (
                        <p className="text-xs text-gray-600">{t("common.no_data")}</p>
                      )}
                    </div>
                  )}
                </div>
              </div>

              {/* Sidebar: Similar Targets */}
              <div className="space-y-6">
                <div className="bg-gray-900/50 border border-gray-800 rounded-xl p-5">
                  <h3 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
                    <Target className="w-4 h-4 text-yellow-400" />
                    {t("kg.similar_targets")}
                  </h3>

                  {/* Target selector */}
                  <select
                    value={selectedTarget}
                    onChange={(e) => loadSimilarTargets(e.target.value)}
                    className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-xs text-gray-300 mb-3 focus:outline-none focus:border-gray-600"
                  >
                    <option value="">{t("kg.select_target")}</option>
                    {targets.map((tgt: any) => (
                      <option key={tgt.id} value={tgt.domain}>
                        {tgt.domain}
                      </option>
                    ))}
                  </select>

                  {similarTargets.length > 0 ? (
                    <div className="space-y-2">
                      {similarTargets.map((st, i) => (
                        <div key={i} className="bg-gray-800/50 rounded-lg p-3">
                          <div className="flex items-center justify-between mb-1">
                            <span className="text-xs text-gray-300 font-mono">{st.domain}</span>
                            <span className="text-[10px] text-gray-500">{st.vuln_count} vulns</span>
                          </div>
                          <div className="flex flex-wrap gap-1">
                            {(st.shared_techs || []).map((tech) => (
                              <span
                                key={tech}
                                className="px-1.5 py-0.5 text-[10px] bg-purple-500/10 text-purple-400 rounded font-mono"
                              >
                                {tech}
                              </span>
                            ))}
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : selectedTarget ? (
                    <p className="text-xs text-gray-600">{t("kg.no_similar")}</p>
                  ) : (
                    <p className="text-xs text-gray-600">{t("kg.select_target_hint")}</p>
                  )}
                </div>

                {/* Quick Stats */}
                {summary && (
                  <div className="bg-gray-900/50 border border-gray-800 rounded-xl p-5">
                    <h3 className="text-sm font-semibold text-white mb-3">{t("kg.quick_stats")}</h3>
                    <div className="space-y-3">
                      <div className="flex items-center justify-between">
                        <span className="text-xs text-gray-500">{t("kg.density")}</span>
                        <span className="text-xs text-green-400 font-mono">
                          {summary.total_nodes > 0
                            ? (summary.total_edges / summary.total_nodes).toFixed(2)
                            : "0"}
                        </span>
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-xs text-gray-500">{t("kg.node_types")}</span>
                        <span className="text-xs text-gray-300 font-mono">
                          {Object.keys(summary.nodes_by_type).length}
                        </span>
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-xs text-gray-500">{t("kg.edge_types")}</span>
                        <span className="text-xs text-gray-300 font-mono">
                          {Object.keys(summary.edges_by_type).length}
                        </span>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </>
        )}
      </main>
    </div>
  );
}
