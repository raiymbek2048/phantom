"use client";

import { useState, useEffect, useCallback } from "react";
import { useParams, useRouter } from "next/navigation";
import { useAuthStore } from "@/lib/store";
import LoginForm from "@/components/LoginForm";
import Sidebar from "@/components/Sidebar";
import {
  getVulnerability,
  validateVulnerability,
  calculateCVSS,
  getBountyReport,
  reverifyVulnerability,
  getVulnCompliance,
} from "@/lib/api";
import { severityColor, cn, timeAgo } from "@/lib/utils";
import {
  ArrowLeft,
  ShieldCheck,
  Calculator,
  FileText,
  RefreshCw,
  Copy,
  Check,
  ChevronDown,
  ChevronRight,
  ExternalLink,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Loader2,
} from "lucide-react";

export default function VulnerabilityDetailPage() {
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
        <VulnDetail />
      </main>
    </div>
  );
}

function VulnDetail() {
  const params = useParams();
  const router = useRouter();
  const vulnId = params.id as string;

  const [vuln, setVuln] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  // Action states
  const [validating, setValidating] = useState(false);
  const [validationResult, setValidationResult] = useState<any>(null);
  const [calculatingCvss, setCalculatingCvss] = useState(false);
  const [cvssResult, setCvssResult] = useState<any>(null);
  const [generatingReport, setGeneratingReport] = useState(false);
  const [bountyReport, setBountyReport] = useState<any>(null);
  const [reverifying, setReverifying] = useState(false);
  const [reverifyResult, setReverifyResult] = useState<any>(null);
  const [compliance, setCompliance] = useState<any>(null);
  const [copied, setCopied] = useState(false);
  const [aiAnalysisOpen, setAiAnalysisOpen] = useState(false);

  const loadVuln = useCallback(async () => {
    try {
      setLoading(true);
      const data = await getVulnerability(vulnId);
      setVuln(data);

      // Parse existing ai_analysis for cached results
      if (data.ai_analysis) {
        try {
          const analysis =
            typeof data.ai_analysis === "string"
              ? JSON.parse(data.ai_analysis)
              : data.ai_analysis;
          if (analysis.validation) setValidationResult(analysis.validation);
          if (analysis.cvss) setCvssResult(analysis.cvss);
        } catch {}
      }

      // Load compliance
      try {
        const comp = await getVulnCompliance(vulnId);
        setCompliance(comp);
      } catch {}
    } catch (e: any) {
      setError(e.response?.data?.detail || "Failed to load vulnerability");
    } finally {
      setLoading(false);
    }
  }, [vulnId]);

  useEffect(() => {
    loadVuln();
  }, [loadVuln]);

  const handleValidate = async () => {
    setValidating(true);
    try {
      const result = await validateVulnerability(vulnId);
      setValidationResult(result.validation);
      // Reload vuln to get updated status
      const updated = await getVulnerability(vulnId);
      setVuln(updated);
    } catch (e: any) {
      alert("Validation failed: " + (e.response?.data?.detail || e.message));
    } finally {
      setValidating(false);
    }
  };

  const handleCVSS = async () => {
    setCalculatingCvss(true);
    try {
      const result = await calculateCVSS(vulnId);
      setCvssResult(result.cvss);
      const updated = await getVulnerability(vulnId);
      setVuln(updated);
    } catch (e: any) {
      alert(
        "CVSS calculation failed: " + (e.response?.data?.detail || e.message)
      );
    } finally {
      setCalculatingCvss(false);
    }
  };

  const handleBountyReport = async () => {
    setGeneratingReport(true);
    try {
      const result = await getBountyReport(vulnId);
      setBountyReport(result);
    } catch (e: any) {
      alert(
        "Report generation failed: " + (e.response?.data?.detail || e.message)
      );
    } finally {
      setGeneratingReport(false);
    }
  };

  const handleReverify = async () => {
    setReverifying(true);
    try {
      const result = await reverifyVulnerability(vulnId);
      setReverifyResult(result);
      const updated = await getVulnerability(vulnId);
      setVuln(updated);
    } catch (e: any) {
      alert("Re-verify failed: " + (e.response?.data?.detail || e.message));
    } finally {
      setReverifying(false);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="w-6 h-6 text-gray-500 animate-spin" />
      </div>
    );
  }

  if (error || !vuln) {
    return (
      <div className="text-center py-20">
        <AlertTriangle className="w-12 h-12 mx-auto mb-3 text-red-500 opacity-50" />
        <p className="text-gray-400">{error || "Vulnerability not found"}</p>
        <button
          onClick={() => router.push("/vulnerabilities")}
          className="mt-4 text-sm text-red-400 hover:text-red-300"
        >
          Back to Vulnerabilities
        </button>
      </div>
    );
  }

  const confidence = (vuln.ai_confidence || 0) * 100;
  const statusLabel = (vuln.status || "new").toUpperCase().replace("_", " ");

  // Parse ai_analysis for display
  let parsedAnalysis: any = null;
  if (vuln.ai_analysis) {
    try {
      parsedAnalysis =
        typeof vuln.ai_analysis === "string"
          ? JSON.parse(vuln.ai_analysis)
          : vuln.ai_analysis;
    } catch {}
  }

  const statusBadgeColor = (status: string) => {
    const s = status.toLowerCase();
    if (s === "confirmed") return "text-green-400 bg-green-950 border-green-800";
    if (s === "false_positive") return "text-gray-400 bg-gray-800 border-gray-700";
    if (s === "fixed") return "text-blue-400 bg-blue-950 border-blue-800";
    return "text-yellow-400 bg-yellow-950 border-yellow-800"; // NEW
  };

  const cvssScoreColor = (score: number) => {
    if (score >= 9.0) return "text-red-400 border-red-500";
    if (score >= 7.0) return "text-orange-400 border-orange-500";
    if (score >= 4.0) return "text-yellow-400 border-yellow-500";
    if (score >= 0.1) return "text-blue-400 border-blue-500";
    return "text-gray-400 border-gray-500";
  };

  return (
    <div className="max-w-5xl mx-auto space-y-6">
      {/* ── Header ── */}
      <div>
        <button
          onClick={() => router.push("/vulnerabilities")}
          className="flex items-center gap-1.5 text-sm text-gray-500 hover:text-gray-300 transition mb-4"
        >
          <ArrowLeft className="w-4 h-4" />
          Back to Vulnerabilities
        </button>

        <div className="flex items-start gap-4">
          <span
            className={cn(
              "text-xs px-3 py-1.5 rounded border font-bold uppercase",
              severityColor(vuln.severity)
            )}
          >
            {vuln.severity}
          </span>
          <div className="flex-1 min-w-0">
            <h1 className="text-xl font-bold text-white leading-tight">
              {vuln.title}
            </h1>
            <div className="flex items-center gap-3 mt-2 flex-wrap">
              <span className="text-[10px] text-gray-500 font-mono bg-gray-800 px-2 py-0.5 rounded">
                {vuln.vuln_type}
              </span>
              {vuln.target_domain && (
                <span className="text-xs text-gray-500 flex items-center gap-1">
                  <ExternalLink className="w-3 h-3" />
                  {vuln.target_domain}
                </span>
              )}
              {vuln.created_at && (
                <span className="text-xs text-gray-600">
                  {timeAgo(vuln.created_at)}
                </span>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* ── Quick Actions Bar ── */}
      <div className="flex items-center gap-2 flex-wrap">
        <button
          onClick={handleValidate}
          disabled={validating}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-green-950 text-green-400 border border-green-800 hover:bg-green-900 transition disabled:opacity-50"
        >
          {validating ? (
            <Loader2 className="w-3.5 h-3.5 animate-spin" />
          ) : (
            <ShieldCheck className="w-3.5 h-3.5" />
          )}
          Validate
        </button>
        <button
          onClick={handleCVSS}
          disabled={calculatingCvss}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-cyan-950 text-cyan-400 border border-cyan-800 hover:bg-cyan-900 transition disabled:opacity-50"
        >
          {calculatingCvss ? (
            <Loader2 className="w-3.5 h-3.5 animate-spin" />
          ) : (
            <Calculator className="w-3.5 h-3.5" />
          )}
          Calculate CVSS
        </button>
        <button
          onClick={handleBountyReport}
          disabled={generatingReport}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-amber-950 text-amber-400 border border-amber-800 hover:bg-amber-900 transition disabled:opacity-50"
        >
          {generatingReport ? (
            <Loader2 className="w-3.5 h-3.5 animate-spin" />
          ) : (
            <FileText className="w-3.5 h-3.5" />
          )}
          Bug Bounty Report
        </button>
        <button
          onClick={handleReverify}
          disabled={reverifying}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-purple-950 text-purple-400 border border-purple-800 hover:bg-purple-900 transition disabled:opacity-50"
        >
          {reverifying ? (
            <Loader2 className="w-3.5 h-3.5 animate-spin" />
          ) : (
            <RefreshCw className="w-3.5 h-3.5" />
          )}
          Re-verify
        </button>
      </div>

      {/* ── Info Grid ── */}
      <div className="bg-gray-900 rounded-xl border border-gray-800 p-5">
        <h2 className="text-sm font-semibold text-white mb-4">Details</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-x-8 gap-y-4">
          <div>
            <span className="text-[11px] text-gray-500 uppercase tracking-wider">
              URL
            </span>
            <p className="text-gray-300 font-mono text-xs break-all mt-0.5">
              {vuln.url || "\u2014"}
            </p>
          </div>
          <div>
            <span className="text-[11px] text-gray-500 uppercase tracking-wider">
              Method
            </span>
            <p className="text-gray-300 text-sm mt-0.5">
              {vuln.method || "\u2014"}
            </p>
          </div>
          <div>
            <span className="text-[11px] text-gray-500 uppercase tracking-wider">
              Parameter
            </span>
            <p className="text-gray-300 font-mono text-xs mt-0.5">
              {vuln.parameter || "\u2014"}
            </p>
          </div>
          <div>
            <span className="text-[11px] text-gray-500 uppercase tracking-wider">
              Status
            </span>
            <div className="mt-1">
              <span
                className={cn(
                  "text-[10px] px-2 py-0.5 rounded border font-bold uppercase",
                  statusBadgeColor(vuln.status)
                )}
              >
                {statusLabel}
              </span>
            </div>
          </div>
          <div>
            <span className="text-[11px] text-gray-500 uppercase tracking-wider">
              AI Confidence
            </span>
            <div className="flex items-center gap-2 mt-1">
              <div className="flex-1 h-2 bg-gray-800 rounded-full max-w-[160px]">
                <div
                  className={cn(
                    "h-2 rounded-full transition-all",
                    confidence >= 80
                      ? "bg-green-500"
                      : confidence >= 50
                        ? "bg-yellow-500"
                        : "bg-red-500"
                  )}
                  style={{ width: `${confidence}%` }}
                />
              </div>
              <span className="text-sm text-gray-300 font-mono">
                {confidence.toFixed(0)}%
              </span>
            </div>
          </div>
          <div>
            <span className="text-[11px] text-gray-500 uppercase tracking-wider">
              Source
            </span>
            <p className="text-gray-300 text-sm mt-0.5">
              {vuln.source || "scanner"}
            </p>
          </div>
          {vuln.cvss_score != null && vuln.cvss_score > 0 && (
            <div>
              <span className="text-[11px] text-gray-500 uppercase tracking-wider">
                CVSS Score
              </span>
              <p className="text-gray-300 text-sm font-bold mt-0.5">
                {vuln.cvss_score}
              </p>
            </div>
          )}
        </div>
      </div>

      {/* ── Payload Section ── */}
      {(vuln.payload_used || vuln.response_data) && (
        <div className="bg-gray-900 rounded-xl border border-gray-800 p-5">
          <h2 className="text-sm font-semibold text-white mb-4">
            Payload & Response
          </h2>
          {vuln.payload_used && (
            <div className="mb-4">
              <span className="text-[11px] text-gray-500 uppercase tracking-wider">
                Payload Used
              </span>
              <pre className="bg-gray-950 rounded-lg p-3 text-xs text-red-400 font-mono mt-1 overflow-x-auto whitespace-pre-wrap break-all">
                {vuln.payload_used}
              </pre>
            </div>
          )}
          {vuln.response_data && (
            <div>
              <span className="text-[11px] text-gray-500 uppercase tracking-wider">
                Response Snippet
              </span>
              <pre className="bg-gray-950 rounded-lg p-3 text-xs text-gray-400 font-mono mt-1 overflow-x-auto max-h-64 overflow-y-auto whitespace-pre-wrap break-all">
                {typeof vuln.response_data === "string"
                  ? vuln.response_data.slice(0, 2000)
                  : JSON.stringify(vuln.response_data, null, 2).slice(0, 2000)}
              </pre>
            </div>
          )}
        </div>
      )}

      {/* ── CVSS Section ── */}
      {cvssResult && (
        <div className="bg-gray-900 rounded-xl border border-gray-800 p-5">
          <h2 className="text-sm font-semibold text-white mb-4">
            CVSS 3.1 Analysis
          </h2>
          <div className="flex items-start gap-6">
            {/* Score circle */}
            <div
              className={cn(
                "w-20 h-20 rounded-full border-4 flex items-center justify-center flex-shrink-0",
                cvssScoreColor(cvssResult.cvss_score || 0)
              )}
            >
              <span className="text-2xl font-bold">
                {cvssResult.cvss_score ?? "?"}
              </span>
            </div>
            <div className="flex-1 min-w-0">
              {/* Vector string */}
              <div className="mb-3">
                <span className="text-[11px] text-gray-500 uppercase tracking-wider">
                  Vector String
                </span>
                <p className="text-xs font-mono text-gray-300 mt-0.5 break-all">
                  {cvssResult.cvss_vector || "\u2014"}
                </p>
              </div>
              {/* Metric badges */}
              <div className="flex flex-wrap gap-1.5 mb-3">
                {[
                  { label: "AV", value: cvssResult.attack_vector },
                  { label: "AC", value: cvssResult.attack_complexity },
                  { label: "PR", value: cvssResult.privileges_required },
                  { label: "UI", value: cvssResult.user_interaction },
                  { label: "S", value: cvssResult.scope },
                  { label: "C", value: cvssResult.confidentiality },
                  { label: "I", value: cvssResult.integrity },
                  { label: "A", value: cvssResult.availability },
                ].map((m) => (
                  <span
                    key={m.label}
                    className="text-[10px] px-2 py-1 rounded bg-gray-800 text-gray-300 border border-gray-700 font-mono"
                  >
                    <span className="text-gray-500">{m.label}:</span>{" "}
                    {m.value || "?"}
                  </span>
                ))}
              </div>
              {/* Reasoning */}
              {cvssResult.reasoning && (
                <div>
                  <span className="text-[11px] text-gray-500 uppercase tracking-wider">
                    AI Reasoning
                  </span>
                  <p className="text-xs text-gray-400 mt-0.5">
                    {cvssResult.reasoning}
                  </p>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* ── Validation Section ── */}
      {validationResult && (
        <div className="bg-gray-900 rounded-xl border border-gray-800 p-5">
          <h2 className="text-sm font-semibold text-white mb-4">
            AI Validation
          </h2>
          <div className="flex items-center gap-3 mb-3">
            {validationResult.is_valid ? (
              <span className="flex items-center gap-1.5 text-xs px-2.5 py-1 rounded border font-bold text-green-400 bg-green-950 border-green-800">
                <CheckCircle2 className="w-3.5 h-3.5" />
                VALID
              </span>
            ) : (
              <span className="flex items-center gap-1.5 text-xs px-2.5 py-1 rounded border font-bold text-red-400 bg-red-950 border-red-800">
                <XCircle className="w-3.5 h-3.5" />
                FALSE POSITIVE
              </span>
            )}
            <span className="text-sm text-gray-300 font-mono">
              {((validationResult.confidence || 0) * 100).toFixed(0)}%
              confidence
            </span>
          </div>
          {validationResult.reasoning && (
            <p className="text-xs text-gray-400 leading-relaxed">
              {validationResult.reasoning}
            </p>
          )}
          {validationResult.adjusted_severity && (
            <div className="mt-2">
              <span className="text-[11px] text-gray-500">
                Adjusted Severity:{" "}
              </span>
              <span
                className={cn(
                  "text-[10px] px-2 py-0.5 rounded border font-bold uppercase",
                  severityColor(validationResult.adjusted_severity)
                )}
              >
                {validationResult.adjusted_severity}
              </span>
            </div>
          )}
        </div>
      )}

      {/* ── Re-verify Result ── */}
      {reverifyResult && (
        <div className="bg-gray-900 rounded-xl border border-gray-800 p-5">
          <h2 className="text-sm font-semibold text-white mb-4">
            Re-verification Result
          </h2>
          <div className="flex items-center gap-3 mb-3">
            {reverifyResult.still_vulnerable ? (
              <span className="flex items-center gap-1.5 text-xs px-2.5 py-1 rounded border font-bold text-red-400 bg-red-950 border-red-800">
                <AlertTriangle className="w-3.5 h-3.5" />
                STILL VULNERABLE
              </span>
            ) : reverifyResult.still_vulnerable === false ? (
              <span className="flex items-center gap-1.5 text-xs px-2.5 py-1 rounded border font-bold text-green-400 bg-green-950 border-green-800">
                <CheckCircle2 className="w-3.5 h-3.5" />
                FIXED
              </span>
            ) : (
              <span className="flex items-center gap-1.5 text-xs px-2.5 py-1 rounded border font-bold text-yellow-400 bg-yellow-950 border-yellow-800">
                <AlertTriangle className="w-3.5 h-3.5" />
                ERROR
              </span>
            )}
          </div>
          <div className="grid grid-cols-2 gap-4 text-xs">
            <div>
              <span className="text-gray-500">Response Code</span>
              <p className="text-gray-300 mt-0.5">
                {reverifyResult.response_code ?? "\u2014"}
              </p>
            </div>
            <div>
              <span className="text-gray-500">Response Length</span>
              <p className="text-gray-300 mt-0.5">
                {reverifyResult.response_length != null
                  ? `${reverifyResult.response_length} bytes`
                  : "\u2014"}
              </p>
            </div>
          </div>
          {reverifyResult.error && (
            <p className="text-xs text-red-400 mt-2">
              Error: {reverifyResult.error}
            </p>
          )}
        </div>
      )}

      {/* ── Bug Bounty Report ── */}
      {bountyReport && (
        <div className="bg-gray-900 rounded-xl border border-gray-800 p-5">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-semibold text-white">
              Bug Bounty Report
            </h2>
            <button
              onClick={() =>
                copyToClipboard(bountyReport.report || JSON.stringify(bountyReport, null, 2))
              }
              className="flex items-center gap-1.5 text-xs text-gray-500 hover:text-gray-300 transition"
            >
              {copied ? (
                <Check className="w-3.5 h-3.5 text-green-400" />
              ) : (
                <Copy className="w-3.5 h-3.5" />
              )}
              {copied ? "Copied" : "Copy"}
            </button>
          </div>
          {bountyReport.suggested_program && (
            <div className="flex items-center gap-4 mb-3 text-xs">
              <div>
                <span className="text-gray-500">Program: </span>
                <span className="text-gray-300">
                  {bountyReport.suggested_program}
                </span>
              </div>
              {bountyReport.suggested_severity && (
                <div>
                  <span className="text-gray-500">Severity: </span>
                  <span
                    className={cn(
                      "px-1.5 py-0.5 rounded border font-bold uppercase text-[10px]",
                      severityColor(bountyReport.suggested_severity)
                    )}
                  >
                    {bountyReport.suggested_severity}
                  </span>
                </div>
              )}
              {bountyReport.estimated_bounty && (
                <div>
                  <span className="text-gray-500">Est. Bounty: </span>
                  <span className="text-green-400 font-mono">
                    {bountyReport.estimated_bounty}
                  </span>
                </div>
              )}
            </div>
          )}
          <pre className="bg-gray-950 rounded-lg p-4 text-xs text-gray-300 font-mono overflow-x-auto max-h-96 overflow-y-auto whitespace-pre-wrap">
            {bountyReport.report || JSON.stringify(bountyReport, null, 2)}
          </pre>
        </div>
      )}

      {/* ── Remediation ── */}
      {(vuln.description || vuln.remediation) && (
        <div className="bg-gray-900 rounded-xl border border-gray-800 p-5">
          <h2 className="text-sm font-semibold text-white mb-4">
            Remediation
          </h2>
          {vuln.description && (
            <div className="mb-4">
              <span className="text-[11px] text-gray-500 uppercase tracking-wider">
                Description
              </span>
              <p className="text-xs text-gray-400 mt-1 leading-relaxed">
                {vuln.description}
              </p>
            </div>
          )}
          {vuln.remediation && (
            <div>
              <span className="text-[11px] text-gray-500 uppercase tracking-wider">
                Recommended Fix
              </span>
              <p className="text-xs text-gray-400 mt-1 leading-relaxed">
                {vuln.remediation}
              </p>
            </div>
          )}
        </div>
      )}

      {/* ── Compliance ── */}
      {compliance?.compliance && (
        <div className="bg-gray-900 rounded-xl border border-gray-800 p-5">
          <h2 className="text-sm font-semibold text-white mb-4">
            Compliance Mapping
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {(compliance.compliance.cwe) && (
              <div>
                <span className="text-[11px] text-gray-500 uppercase tracking-wider">
                  CWE
                </span>
                <div className="mt-1 space-y-1">
                  {(Array.isArray(compliance.compliance.cwe)
                    ? compliance.compliance.cwe
                    : [compliance.compliance.cwe]
                  ).map((cwe: any, i: number) => (
                    <span
                      key={i}
                      className="inline-block text-xs px-2 py-0.5 rounded bg-gray-800 text-gray-300 border border-gray-700 mr-1.5 font-mono"
                    >
                      {typeof cwe === "string" ? cwe : cwe.id ? `${cwe.id}${cwe.name ? ` — ${cwe.name}` : ""}` : JSON.stringify(cwe)}
                    </span>
                  ))}
                </div>
              </div>
            )}
            {(compliance.compliance.owasp || compliance.compliance.owasp_top_10) && (
              <div>
                <span className="text-[11px] text-gray-500 uppercase tracking-wider">
                  OWASP Top 10
                </span>
                <div className="mt-1 space-y-1">
                  {(Array.isArray(compliance.compliance.owasp_top_10 || compliance.compliance.owasp)
                    ? (compliance.compliance.owasp_top_10 || compliance.compliance.owasp)
                    : [compliance.compliance.owasp_top_10 || compliance.compliance.owasp]
                  ).map((item: any, i: number) => (
                    <span
                      key={i}
                      className="inline-block text-xs px-2 py-0.5 rounded bg-red-950 text-red-400 border border-red-800 mr-1.5"
                    >
                      {typeof item === "string" ? item : item.id ? `${item.id}${item.name ? ` — ${item.name}` : ""}` : JSON.stringify(item)}
                    </span>
                  ))}
                </div>
              </div>
            )}
            {compliance.compliance.pci_dss && (
              <div>
                <span className="text-[11px] text-gray-500 uppercase tracking-wider">
                  PCI DSS
                </span>
                <div className="mt-1 space-y-1">
                  {(Array.isArray(compliance.compliance.pci_dss)
                    ? compliance.compliance.pci_dss
                    : [compliance.compliance.pci_dss]
                  ).map((item: any, i: number) => (
                    <span
                      key={i}
                      className="inline-block text-xs px-2 py-0.5 rounded bg-blue-950 text-blue-400 border border-blue-800 mr-1.5"
                    >
                      {typeof item === "string" ? item : item.requirement ? `${item.requirement}${item.description ? ` — ${item.description}` : ""}` : item.id || JSON.stringify(item)}
                    </span>
                  ))}
                </div>
              </div>
            )}
            {(compliance.compliance.nist || compliance.compliance.nist_800_53) && (
              <div>
                <span className="text-[11px] text-gray-500 uppercase tracking-wider">
                  NIST 800-53
                </span>
                <div className="mt-1 space-y-1">
                  {(Array.isArray(compliance.compliance.nist_800_53 || compliance.compliance.nist)
                    ? (compliance.compliance.nist_800_53 || compliance.compliance.nist)
                    : [compliance.compliance.nist_800_53 || compliance.compliance.nist]
                  ).map((item: any, i: number) => (
                    <span
                      key={i}
                      className="inline-block text-xs px-2 py-0.5 rounded bg-purple-950 text-purple-400 border border-purple-800 mr-1.5"
                    >
                      {typeof item === "string" ? item : item.control || item.id || JSON.stringify(item)}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── AI Analysis (Collapsible) ── */}
      {parsedAnalysis && (
        <div className="bg-gray-900 rounded-xl border border-gray-800">
          <button
            onClick={() => setAiAnalysisOpen(!aiAnalysisOpen)}
            className="flex items-center gap-2 w-full p-5 text-left hover:bg-gray-800/50 transition rounded-xl"
          >
            {aiAnalysisOpen ? (
              <ChevronDown className="w-4 h-4 text-gray-500" />
            ) : (
              <ChevronRight className="w-4 h-4 text-gray-500" />
            )}
            <h2 className="text-sm font-semibold text-white">
              Raw AI Analysis
            </h2>
            <span className="text-[10px] text-gray-600 ml-auto">
              {Object.keys(parsedAnalysis).length} keys
            </span>
          </button>
          {aiAnalysisOpen && (
            <div className="px-5 pb-5">
              <pre className="bg-gray-950 rounded-lg p-4 text-xs text-gray-400 font-mono overflow-x-auto max-h-96 overflow-y-auto whitespace-pre-wrap">
                {JSON.stringify(parsedAnalysis, null, 2)}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
