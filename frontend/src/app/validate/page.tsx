"use client";

import { useState, useEffect } from "react";
import { useSearchParams } from "next/navigation";
import Sidebar from "@/components/Sidebar";
import { validateScanReport, getScans } from "@/lib/api";
import {
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Minus,
  Brain,
  Target,
  ArrowRight,
  Loader2,
  TrendingDown,
  TrendingUp,
  Eye,
  EyeOff,
  Lightbulb,
  Flag,
  ThumbsUp,
  RotateCw,
  Layers,
  Zap,
  ChevronDown,
  ChevronRight,
} from "lucide-react";
import { cn } from "@/lib/utils";

interface FindingReview {
  original_title: string;
  original_severity: string;
  real_severity: string;
  is_real_vulnerability: boolean;
  is_false_positive: boolean;
  explanation: string;
  real_world_impact: string;
  remediation_priority: string;
}

interface RoundResult {
  round_number: number;
  round_name: string;
  real_risk_score: number;
  verdict: string;
  new_insights: string[];
  findings_count: number;
}

interface ValidationResult {
  real_risk_score: number;
  automated_risk_score: number;
  overall_verdict: string;
  findings_review: FindingReview[];
  missing_checks: string[];
  practical_recommendations: string[];
  red_flags: string[];
  green_flags: string[];
  scan_id: string;
  target_domain: string;
  total_findings: number;
  validated_at: string;
  rounds_completed: number;
  round_results: RoundResult[];
  accumulated_insights: string[];
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: "text-red-400 bg-red-500/10 border-red-500/20",
  high: "text-orange-400 bg-orange-500/10 border-orange-500/20",
  medium: "text-amber-400 bg-amber-500/10 border-amber-500/20",
  low: "text-blue-400 bg-blue-500/10 border-blue-500/20",
  info: "text-gray-400 bg-gray-500/10 border-gray-500/20",
  false_positive: "text-green-400 bg-green-500/10 border-green-500/20",
};

const PRIORITY_LABELS: Record<string, { label: string; color: string }> = {
  immediate: { label: "FIX NOW", color: "text-red-400 bg-red-500/10" },
  short_term: { label: "Fix Soon", color: "text-amber-400 bg-amber-500/10" },
  nice_to_have: { label: "Nice to Have", color: "text-blue-400 bg-blue-500/10" },
  ignore: { label: "Ignore", color: "text-gray-500 bg-gray-800" },
};

const ROUND_DESCRIPTIONS: Record<string, string> = {
  "General Triage": "Noise vs real vulns separation",
  "IDOR & Access Control": "Testing for broken access control, IDOR patterns",
  "Injection & RCE": "SQL/NoSQL/OS injection, template injection, XXE",
  "Business Logic & API Abuse": "Race conditions, price manipulation, auth flows",
  "Infrastructure & Exposure": "Swagger, Actuator, JWT, .env, admin panels",
  "Authentication & JWT Deep Dive": "Token security, session management, OAuth",
  "Spring/Java Specific": "JPQL, SpEL, Actuator, deserialization",
  "Synthesis & Final Assessment": "Merged assessment with attack chains",
};

function RiskGauge({ score, label, color }: { score: number; label: string; color: string }) {
  return (
    <div className="text-center">
      <div className="relative w-24 h-24 mx-auto mb-2">
        <svg viewBox="0 0 100 100" className="w-full h-full -rotate-90">
          <circle cx="50" cy="50" r="40" fill="none" stroke="#1f2937" strokeWidth="8" />
          <circle
            cx="50" cy="50" r="40" fill="none"
            stroke={score > 70 ? "#ef4444" : score > 40 ? "#f59e0b" : "#22c55e"}
            strokeWidth="8"
            strokeDasharray={`${score * 2.51} 251`}
            strokeLinecap="round"
          />
        </svg>
        <div className="absolute inset-0 flex items-center justify-center">
          <span className={cn("text-xl font-bold", color)}>{score}</span>
        </div>
      </div>
      <p className="text-xs text-gray-500">{label}</p>
    </div>
  );
}

export default function ValidatePage() {
  const searchParams = useSearchParams();
  const scanIdParam = searchParams.get("scan_id");

  const [scans, setScans] = useState<any[]>([]);
  const [selectedScan, setSelectedScan] = useState<string>(scanIdParam || "");
  const [result, setResult] = useState<ValidationResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [expandedFindings, setExpandedFindings] = useState<Set<number>>(new Set());
  const [expandedRounds, setExpandedRounds] = useState<Set<number>>(new Set());

  // Multi-round controls
  const [roundMode, setRoundMode] = useState<"single" | "multi" | "continuous">("single");
  const [roundCount, setRoundCount] = useState(3);

  useEffect(() => {
    getScans().then((data) => {
      const completed = (data || []).filter((s: any) => s.status === "COMPLETED" || s.status === "completed");
      setScans(completed);
    }).catch(() => {});
  }, []);

  useEffect(() => {
    if (scanIdParam && scanIdParam !== selectedScan) {
      setSelectedScan(scanIdParam);
    }
  }, [scanIdParam]);

  const handleValidate = async () => {
    if (!selectedScan) return;
    setLoading(true);
    setError("");
    setResult(null);
    try {
      const rounds = roundMode === "single" ? 1 : roundCount;
      const continuous = roundMode === "continuous";
      const data = await validateScanReport(selectedScan, rounds, continuous);
      setResult(data);
    } catch (e: any) {
      setError(e?.response?.data?.detail || "Validation failed. Check if Claude API is available.");
    }
    setLoading(false);
  };

  const toggleFinding = (idx: number) => {
    setExpandedFindings((prev) => {
      const next = new Set(prev);
      if (next.has(idx)) next.delete(idx);
      else next.add(idx);
      return next;
    });
  };

  const toggleRound = (idx: number) => {
    setExpandedRounds((prev) => {
      const next = new Set(prev);
      if (next.has(idx)) next.delete(idx);
      else next.add(idx);
      return next;
    });
  };

  const realVulns = result?.findings_review.filter((f) => f.is_real_vulnerability) || [];
  const falsePositives = result?.findings_review.filter((f) => f.is_false_positive) || [];
  const noiseCount = result?.findings_review.filter((f) => !f.is_real_vulnerability).length || 0;

  return (
    <div className="flex min-h-screen bg-gray-950">
      <Sidebar />
      <main className="flex-1 ml-60 p-8">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-2xl font-bold text-white flex items-center gap-3">
            <Brain className="w-7 h-7 text-cyan-400" />
            Report Validator
          </h1>
          <p className="text-sm text-gray-500 mt-1">
            AI expert critically reviews scan findings — multi-round deep analysis from different pentesting angles
          </p>
        </div>

        {/* Scan selector + round mode */}
        <div className="space-y-4 mb-8">
          <div className="flex items-center gap-4">
            <select
              value={selectedScan}
              onChange={(e) => setSelectedScan(e.target.value)}
              className="flex-1 max-w-lg bg-gray-900 border border-gray-800 rounded-lg px-4 py-2.5 text-sm text-gray-300"
            >
              <option value="">Select a completed scan...</option>
              {scans.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.target_domain || "Unknown"} — {s.vulns_found || 0} findings — {new Date(s.created_at).toLocaleDateString()}
                </option>
              ))}
            </select>
            <button
              onClick={handleValidate}
              disabled={!selectedScan || loading}
              className="flex items-center gap-2 px-6 py-2.5 bg-cyan-600/20 border border-cyan-600/30 rounded-lg text-cyan-400 hover:bg-cyan-600/30 transition disabled:opacity-50 text-sm font-medium"
            >
              {loading ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  Analyzing...
                </>
              ) : (
                <>
                  <ShieldCheck className="w-4 h-4" />
                  Validate
                </>
              )}
            </button>
          </div>

          {/* Round mode selector */}
          <div className="flex items-center gap-3">
            <span className="text-xs text-gray-500">Mode:</span>
            <button
              onClick={() => setRoundMode("single")}
              className={cn(
                "flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs transition border",
                roundMode === "single"
                  ? "bg-cyan-600/20 border-cyan-600/30 text-cyan-400"
                  : "bg-gray-900 border-gray-800 text-gray-500 hover:text-gray-300"
              )}
            >
              <Zap className="w-3 h-3" />
              Quick (1 round)
            </button>
            <button
              onClick={() => setRoundMode("multi")}
              className={cn(
                "flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs transition border",
                roundMode === "multi"
                  ? "bg-purple-600/20 border-purple-600/30 text-purple-400"
                  : "bg-gray-900 border-gray-800 text-gray-500 hover:text-gray-300"
              )}
            >
              <Layers className="w-3 h-3" />
              Multi-Round
            </button>
            <button
              onClick={() => setRoundMode("continuous")}
              className={cn(
                "flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs transition border",
                roundMode === "continuous"
                  ? "bg-red-600/20 border-red-600/30 text-red-400"
                  : "bg-gray-900 border-gray-800 text-gray-500 hover:text-gray-300"
              )}
            >
              <RotateCw className="w-3 h-3" />
              Continuous
            </button>

            {roundMode === "multi" && (
              <div className="flex items-center gap-2 ml-2">
                <span className="text-xs text-gray-500">Rounds:</span>
                <input
                  type="range"
                  min={2}
                  max={8}
                  value={roundCount}
                  onChange={(e) => setRoundCount(parseInt(e.target.value))}
                  className="w-24 accent-purple-500"
                />
                <span className="text-sm font-mono text-purple-400 w-4">{roundCount}</span>
              </div>
            )}

            {roundMode === "continuous" && (
              <span className="text-[10px] text-gray-600 ml-2">
                Keeps probing until no new insights (max 8 rounds for validation)
              </span>
            )}
          </div>
        </div>

        {loading && (
          <div className="text-center py-20">
            <Loader2 className="w-10 h-10 text-cyan-400 animate-spin mx-auto mb-4" />
            <p className="text-gray-400">
              {roundMode === "single"
                ? "AI expert is reviewing the report..."
                : roundMode === "continuous"
                  ? "AI is running continuous deep validation..."
                  : `AI is running ${roundCount}-round deep analysis...`}
            </p>
            <p className="text-xs text-gray-600 mt-1">
              {roundMode === "single" ? "~15-30 seconds" : `~${(roundMode === "multi" ? roundCount : 5) * 20} seconds`}
            </p>
          </div>
        )}

        {error && (
          <div className="bg-red-950/30 border border-red-900/30 rounded-xl p-4 mb-6">
            <p className="text-red-400 text-sm">{error}</p>
          </div>
        )}

        {result && (
          <div className="space-y-6">
            {/* Risk Score Comparison */}
            <div className="bg-gray-900/50 border border-gray-800 rounded-xl p-6">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-8">
                  <RiskGauge
                    score={result.automated_risk_score}
                    label="Automated Score"
                    color="text-gray-400"
                  />
                  <div className="flex flex-col items-center">
                    <ArrowRight className="w-6 h-6 text-gray-600" />
                    {result.real_risk_score < result.automated_risk_score ? (
                      <TrendingDown className="w-5 h-5 text-green-400 mt-1" />
                    ) : (
                      <TrendingUp className="w-5 h-5 text-red-400 mt-1" />
                    )}
                  </div>
                  <RiskGauge
                    score={result.real_risk_score}
                    label="Real Risk Score"
                    color={result.real_risk_score > 70 ? "text-red-400" : result.real_risk_score > 40 ? "text-amber-400" : "text-green-400"}
                  />
                </div>
                <div className="flex-1 ml-8">
                  <h3 className="text-white font-medium mb-2 flex items-center gap-2">
                    Expert Verdict
                    {(result.rounds_completed || 0) > 1 && (
                      <span className="text-[10px] px-2 py-0.5 rounded bg-purple-500/10 text-purple-400 font-mono">
                        {result.rounds_completed} rounds
                      </span>
                    )}
                  </h3>
                  <p className="text-sm text-gray-400 leading-relaxed">{result.overall_verdict}</p>
                </div>
              </div>
            </div>

            {/* Stats row */}
            <div className="grid grid-cols-4 gap-4">
              <div className="bg-gray-900/50 border border-gray-800 rounded-xl p-4 text-center">
                <p className="text-2xl font-bold text-white">{result.total_findings}</p>
                <p className="text-xs text-gray-500 mt-1">Total Findings</p>
              </div>
              <div className="bg-gray-900/50 border border-gray-800 rounded-xl p-4 text-center">
                <p className="text-2xl font-bold text-red-400">{realVulns.length}</p>
                <p className="text-xs text-gray-500 mt-1">Real Vulnerabilities</p>
              </div>
              <div className="bg-gray-900/50 border border-gray-800 rounded-xl p-4 text-center">
                <p className="text-2xl font-bold text-green-400">{falsePositives.length}</p>
                <p className="text-xs text-gray-500 mt-1">False Positives</p>
              </div>
              <div className="bg-gray-900/50 border border-gray-800 rounded-xl p-4 text-center">
                <p className="text-2xl font-bold text-amber-400">{noiseCount}</p>
                <p className="text-xs text-gray-500 mt-1">Noise / Informational</p>
              </div>
            </div>

            {/* Round Results Timeline */}
            {result.round_results && result.round_results.length > 1 && (
              <div className="bg-gray-900/50 border border-gray-800 rounded-xl p-5">
                <h3 className="text-white font-medium text-sm flex items-center gap-2 mb-4">
                  <Layers className="w-4 h-4 text-purple-400" />
                  Validation Rounds
                </h3>
                <div className="space-y-2">
                  {result.round_results.map((round, i) => {
                    const expanded = expandedRounds.has(i);
                    return (
                      <div key={i} className="border border-gray-800 rounded-lg overflow-hidden">
                        <button
                          onClick={() => toggleRound(i)}
                          className="w-full flex items-center gap-3 px-4 py-3 hover:bg-gray-800/30 transition text-left"
                        >
                          {expanded ? (
                            <ChevronDown className="w-3.5 h-3.5 text-gray-500" />
                          ) : (
                            <ChevronRight className="w-3.5 h-3.5 text-gray-500" />
                          )}
                          <span className="text-[10px] font-mono text-purple-400 bg-purple-500/10 px-2 py-0.5 rounded">
                            R{round.round_number}
                          </span>
                          <span className="text-sm text-gray-300 font-medium">{round.round_name}</span>
                          <span className="text-[10px] text-gray-600 flex-1">
                            {ROUND_DESCRIPTIONS[round.round_name] || ""}
                          </span>
                          <span className={cn(
                            "text-xs font-mono",
                            round.real_risk_score > 70 ? "text-red-400" : round.real_risk_score > 40 ? "text-amber-400" : "text-green-400"
                          )}>
                            {round.real_risk_score}/100
                          </span>
                          {round.new_insights && round.new_insights.length > 0 && (
                            <span className="text-[10px] px-1.5 py-0.5 rounded bg-cyan-500/10 text-cyan-400">
                              +{round.new_insights.length} insights
                            </span>
                          )}
                        </button>
                        {expanded && (
                          <div className="px-4 pb-3 pt-0 border-t border-gray-800/50">
                            <p className="text-xs text-gray-400 mt-2 mb-2">{round.verdict}</p>
                            {round.new_insights && round.new_insights.length > 0 && (
                              <div className="mt-2">
                                <p className="text-[10px] text-gray-600 uppercase tracking-wider mb-1">New Insights</p>
                                <ul className="space-y-1">
                                  {round.new_insights.map((insight, j) => (
                                    <li key={j} className="text-xs text-cyan-400/80 flex items-start gap-1.5">
                                      <Lightbulb className="w-3 h-3 mt-0.5 flex-shrink-0" />
                                      {insight}
                                    </li>
                                  ))}
                                </ul>
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            {/* Accumulated Insights */}
            {result.accumulated_insights && result.accumulated_insights.length > 0 && (
              <div className="bg-cyan-950/20 border border-cyan-900/30 rounded-xl p-5">
                <h3 className="text-cyan-400 font-medium text-sm flex items-center gap-2 mb-3">
                  <Lightbulb className="w-4 h-4" />
                  Deep Insights (from multi-round analysis)
                </h3>
                <ul className="space-y-2">
                  {result.accumulated_insights.map((insight, i) => (
                    <li key={i} className="text-xs text-cyan-300/70 flex items-start gap-2">
                      <span className="text-cyan-500 font-mono flex-shrink-0">{i + 1}.</span>
                      {insight}
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {/* Red & Green Flags */}
            {(result.red_flags.length > 0 || result.green_flags.length > 0) && (
              <div className="grid grid-cols-2 gap-4">
                {result.red_flags.length > 0 && (
                  <div className="bg-red-950/20 border border-red-900/30 rounded-xl p-4">
                    <h3 className="text-red-400 font-medium text-sm flex items-center gap-2 mb-3">
                      <Flag className="w-4 h-4" /> Red Flags
                    </h3>
                    <ul className="space-y-1.5">
                      {result.red_flags.map((f, i) => (
                        <li key={i} className="text-xs text-red-300/80 flex items-start gap-2">
                          <AlertTriangle className="w-3 h-3 mt-0.5 flex-shrink-0" />
                          {f}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
                {result.green_flags.length > 0 && (
                  <div className="bg-green-950/20 border border-green-900/30 rounded-xl p-4">
                    <h3 className="text-green-400 font-medium text-sm flex items-center gap-2 mb-3">
                      <ThumbsUp className="w-4 h-4" /> Green Flags
                    </h3>
                    <ul className="space-y-1.5">
                      {result.green_flags.map((f, i) => (
                        <li key={i} className="text-xs text-green-300/80 flex items-start gap-2">
                          <CheckCircle className="w-3 h-3 mt-0.5 flex-shrink-0" />
                          {f}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            )}

            {/* Findings Review */}
            <div>
              <h3 className="text-white font-medium mb-3 flex items-center gap-2">
                <Eye className="w-5 h-5 text-cyan-400" />
                Findings Review
              </h3>
              <div className="space-y-2">
                {result.findings_review.map((f, i) => {
                  const expanded = expandedFindings.has(i);
                  const severityChanged = f.original_severity?.toLowerCase() !== f.real_severity?.toLowerCase();
                  const priority = PRIORITY_LABELS[f.remediation_priority] || PRIORITY_LABELS.ignore;

                  return (
                    <div
                      key={i}
                      className={cn(
                        "border rounded-xl transition cursor-pointer",
                        f.is_real_vulnerability
                          ? "bg-red-950/10 border-red-900/20 hover:border-red-800/30"
                          : f.is_false_positive
                            ? "bg-green-950/10 border-green-900/20 hover:border-green-800/30"
                            : "bg-gray-900/30 border-gray-800 hover:border-gray-700"
                      )}
                      onClick={() => toggleFinding(i)}
                    >
                      <div className="flex items-center gap-3 p-4">
                        <div className="flex-shrink-0">
                          {f.is_real_vulnerability ? (
                            <ShieldAlert className="w-5 h-5 text-red-400" />
                          ) : f.is_false_positive ? (
                            <ShieldX className="w-5 h-5 text-green-400" />
                          ) : (
                            <Minus className="w-5 h-5 text-gray-500" />
                          )}
                        </div>

                        <div className="flex items-center gap-1.5 flex-shrink-0">
                          <span className={cn(
                            "text-[10px] px-1.5 py-0.5 rounded border font-mono uppercase",
                            SEVERITY_COLORS[f.original_severity?.toLowerCase()] || SEVERITY_COLORS.info
                          )}>
                            {f.original_severity}
                          </span>
                          {severityChanged && (
                            <>
                              <ArrowRight className="w-3 h-3 text-gray-600" />
                              <span className={cn(
                                "text-[10px] px-1.5 py-0.5 rounded border font-mono uppercase",
                                SEVERITY_COLORS[f.real_severity?.toLowerCase()] || SEVERITY_COLORS.info
                              )}>
                                {f.real_severity}
                              </span>
                            </>
                          )}
                        </div>

                        <span className="text-sm text-gray-300 flex-1 truncate">{f.original_title}</span>

                        <span className={cn("text-[10px] px-2 py-0.5 rounded font-medium", priority.color)}>
                          {priority.label}
                        </span>

                        {f.is_real_vulnerability && (
                          <span className="text-[10px] px-2 py-0.5 rounded bg-red-500/10 text-red-400 font-medium">
                            REAL VULN
                          </span>
                        )}
                        {f.is_false_positive && (
                          <span className="text-[10px] px-2 py-0.5 rounded bg-green-500/10 text-green-400 font-medium">
                            FALSE POSITIVE
                          </span>
                        )}
                      </div>

                      {expanded && (
                        <div className="px-4 pb-4 pt-0 border-t border-gray-800/50 mt-0">
                          <div className="grid grid-cols-2 gap-4 mt-3">
                            <div>
                              <p className="text-[10px] text-gray-600 uppercase tracking-wider mb-1">Expert Analysis</p>
                              <p className="text-xs text-gray-400 leading-relaxed">{f.explanation}</p>
                            </div>
                            <div>
                              <p className="text-[10px] text-gray-600 uppercase tracking-wider mb-1">Real-World Impact</p>
                              <p className="text-xs text-gray-400 leading-relaxed">{f.real_world_impact}</p>
                            </div>
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Missing Checks & Recommendations */}
            <div className="grid grid-cols-2 gap-4">
              {result.missing_checks.length > 0 && (
                <div className="bg-gray-900/50 border border-gray-800 rounded-xl p-5">
                  <h3 className="text-amber-400 font-medium text-sm flex items-center gap-2 mb-3">
                    <EyeOff className="w-4 h-4" /> What Scanner Missed
                  </h3>
                  <ul className="space-y-2">
                    {result.missing_checks.map((c, i) => (
                      <li key={i} className="text-xs text-gray-400 flex items-start gap-2">
                        <Target className="w-3 h-3 mt-0.5 text-amber-500 flex-shrink-0" />
                        {c}
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {result.practical_recommendations.length > 0 && (
                <div className="bg-gray-900/50 border border-gray-800 rounded-xl p-5">
                  <h3 className="text-cyan-400 font-medium text-sm flex items-center gap-2 mb-3">
                    <Lightbulb className="w-4 h-4" /> Practical Recommendations
                  </h3>
                  <ol className="space-y-2">
                    {result.practical_recommendations.map((r, i) => (
                      <li key={i} className="text-xs text-gray-400 flex items-start gap-2">
                        <span className="text-cyan-500 font-mono flex-shrink-0">{i + 1}.</span>
                        {r}
                      </li>
                    ))}
                  </ol>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Empty state */}
        {!result && !loading && !error && (
          <div className="text-center py-20">
            <ShieldCheck className="w-16 h-16 text-gray-800 mx-auto mb-4" />
            <p className="text-gray-500 mb-2">Select a completed scan and click Validate</p>
            <p className="text-xs text-gray-600 max-w-md mx-auto">
              Quick mode does a single triage pass. Multi-round runs multiple expert angles (IDOR, injection, business logic, infrastructure).
              Continuous mode keeps probing until no new insights are found.
            </p>
          </div>
        )}
      </main>
    </div>
  );
}
