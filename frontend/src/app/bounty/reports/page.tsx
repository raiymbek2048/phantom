"use client";

import { useState, useEffect } from "react";
import { useAuthStore } from "@/lib/store";
import { useT } from "@/lib/i18n";
import LoginForm from "@/components/LoginForm";
import Sidebar from "@/components/Sidebar";
import {
  getSubmissions,
  getSubmission,
  updateSubmissionStatus,
  learnFromAll,
  getRejectionAnalysis,
  getBountyReport,
} from "@/lib/api";
import {
  Send,
  RefreshCw,
  ChevronDown,
  ChevronUp,
  CheckCircle,
  XCircle,
  Clock,
  Copy,
  AlertTriangle,
  Eye,
  Brain,
} from "lucide-react";

function utc(iso: string | null | undefined): string {
  if (!iso) return "";
  return iso.endsWith("Z") ? iso : iso + "Z";
}

const STATUS_COLORS: Record<string, string> = {
  draft: "text-gray-400 bg-gray-700/20",
  submitted: "text-blue-400 bg-blue-700/20",
  new: "text-blue-300 bg-blue-700/20",
  triaged: "text-purple-400 bg-purple-700/20",
  needs_more_info: "text-yellow-400 bg-yellow-700/20",
  accepted: "text-green-400 bg-green-700/20",
  duplicate: "text-yellow-400 bg-yellow-700/20",
  informative: "text-gray-400 bg-gray-700/20",
  not_applicable: "text-red-400 bg-red-700/20",
  spam: "text-red-600 bg-red-700/20",
  resolved: "text-green-400 bg-green-700/20",
  bounty_paid: "text-green-300 bg-green-700/30",
};

const ALL_STATUSES = [
  "draft", "submitted", "new", "triaged", "needs_more_info",
  "accepted", "duplicate", "informative", "not_applicable",
  "spam", "resolved", "bounty_paid",
];

export default function ReportsPage() {
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
        <ReportsContent />
      </main>
    </div>
  );
}

function ReportsContent() {
  const t = useT();
  const [submissions, setSubmissions] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [filterStatus, setFilterStatus] = useState<string>("all");
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<any>(null);
  const [reportMarkdown, setReportMarkdown] = useState<string | null>(null);
  const [statusUpdate, setStatusUpdate] = useState<{ id: string; status: string; response: string; bounty: string } | null>(null);
  const [learning, setLearning] = useState(false);
  const [rejections, setRejections] = useState<any>(null);
  const [showRejections, setShowRejections] = useState(false);

  const load = async () => {
    setLoading(true);
    try {
      const params: Record<string, string> = {};
      if (filterStatus !== "all") params.status = filterStatus;
      const data = await getSubmissions(params);
      setSubmissions(data.submissions || data || []);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, [filterStatus]);

  const handleExpand = async (id: string) => {
    if (expandedId === id) {
      setExpandedId(null);
      setDetail(null);
      setReportMarkdown(null);
      return;
    }
    setExpandedId(id);
    try {
      const d = await getSubmission(id);
      setDetail(d);
      if (d.vulnerability_id) {
        try {
          const report = await getBountyReport(d.vulnerability_id);
          setReportMarkdown(report.report_markdown || report.report?.markdown || null);
        } catch { setReportMarkdown(null); }
      }
    } catch {
      setDetail(null);
    }
  };

  const handleStatusUpdate = async () => {
    if (!statusUpdate) return;
    try {
      await updateSubmissionStatus(
        statusUpdate.id,
        statusUpdate.status,
        statusUpdate.response || undefined,
        statusUpdate.bounty ? parseFloat(statusUpdate.bounty) : undefined,
      );
      setStatusUpdate(null);
      load();
    } catch (e: any) {
      alert(`Error: ${e.response?.data?.detail || e.message}`);
    }
  };

  const handleLearn = async () => {
    setLearning(true);
    try {
      await learnFromAll();
    } finally {
      setLearning(false);
    }
  };

  const handleShowRejections = async () => {
    if (showRejections) {
      setShowRejections(false);
      return;
    }
    try {
      const data = await getRejectionAnalysis();
      setRejections(data);
      setShowRejections(true);
    } catch {
      setRejections(null);
    }
  };

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-3">
            <Send className="w-7 h-7 text-purple-400" />
            {t("reports.title")}
          </h1>
          <p className="text-gray-500 text-sm mt-1">{t("reports.subtitle")}</p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={handleShowRejections}
            className="flex items-center gap-2 px-3 py-2 bg-gray-800 hover:bg-gray-700 rounded-lg text-sm text-gray-300 transition-colors"
          >
            <AlertTriangle className="w-4 h-4 text-yellow-400" />
            {t("reports.rejection_analysis")}
          </button>
          <button
            onClick={handleLearn}
            disabled={learning}
            className="flex items-center gap-2 px-3 py-2 bg-gray-800 hover:bg-gray-700 rounded-lg text-sm text-gray-300 transition-colors"
          >
            <Brain className={`w-4 h-4 text-purple-400 ${learning ? "animate-pulse" : ""}`} />
            {learning ? "Learning..." : t("reports.learn_all")}
          </button>
          <button
            onClick={load}
            className="flex items-center gap-2 px-3 py-2 bg-gray-800 hover:bg-gray-700 rounded-lg text-sm text-gray-300 transition-colors"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
          </button>
        </div>
      </div>

      {/* Rejection Analysis Panel */}
      {showRejections && rejections && (
        <div className="bg-yellow-900/10 border border-yellow-800/30 rounded-xl p-5">
          <h3 className="text-sm font-semibold text-yellow-400 mb-3">{t("reports.rejection_analysis")}</h3>
          {rejections.patterns?.length > 0 ? (
            <div className="space-y-2">
              {rejections.patterns.map((p: any, i: number) => (
                <div key={i} className="text-sm text-gray-300 bg-gray-800/50 rounded-lg px-3 py-2">
                  <span className="text-yellow-400">{p.vuln_type || p.type}:</span> {p.reason || p.description}
                </div>
              ))}
            </div>
          ) : (
            <p className="text-gray-500 text-sm">No rejection patterns found.</p>
          )}
          {rejections.recommendations?.length > 0 && (
            <div className="mt-3">
              <p className="text-xs text-gray-500 uppercase mb-1">Recommendations</p>
              <ul className="space-y-1">
                {rejections.recommendations.map((r: string, i: number) => (
                  <li key={i} className="text-sm text-gray-400">• {r}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {/* Status Filter */}
      <div className="flex flex-wrap gap-2">
        <button
          onClick={() => setFilterStatus("all")}
          className={`px-3 py-1.5 rounded-lg text-xs transition-colors ${
            filterStatus === "all" ? "bg-red-600 text-white" : "bg-gray-800 text-gray-400 hover:text-white"
          }`}
        >
          All
        </button>
        {ALL_STATUSES.map((s) => (
          <button
            key={s}
            onClick={() => setFilterStatus(s)}
            className={`px-3 py-1.5 rounded-lg text-xs capitalize transition-colors ${
              filterStatus === s ? "bg-red-600 text-white" : "bg-gray-800 text-gray-400 hover:text-white"
            }`}
          >
            {s.replace(/_/g, " ")}
          </button>
        ))}
      </div>

      {/* Submissions List */}
      {loading ? (
        <div className="text-center text-gray-500 py-12">Loading submissions...</div>
      ) : submissions.length === 0 ? (
        <div className="text-center text-gray-500 py-12">
          {t("reports.no_reports")}
        </div>
      ) : (
        <div className="space-y-2">
          {submissions.map((sub: any) => (
            <div key={sub.id} className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
              {/* Row */}
              <div
                className="flex items-center justify-between p-4 cursor-pointer hover:bg-gray-800/50 transition-colors"
                onClick={() => handleExpand(sub.id)}
              >
                <div className="flex items-center gap-4 flex-1 min-w-0">
                  <StatusIcon status={sub.h1_status} />
                  <div className="min-w-0">
                    <p className="text-white font-medium truncate">{sub.report_title || "Untitled"}</p>
                    <div className="flex items-center gap-3 text-xs text-gray-500 mt-0.5">
                      <span>{sub.program_handle}</span>
                      <span className="capitalize">{sub.report_severity || "—"}</span>
                      {sub.quality_grade && <span className="font-mono">Grade: {sub.quality_grade}</span>}
                    </div>
                  </div>
                </div>
                <div className="flex items-center gap-4">
                  {sub.bounty_amount > 0 && (
                    <span className="text-green-400 font-mono text-sm">${sub.bounty_amount}</span>
                  )}
                  {sub.duplicate_risk > 50 && (
                    <span className="text-yellow-400 text-xs flex items-center gap-1">
                      <Copy className="w-3 h-3" /> {sub.duplicate_risk}%
                    </span>
                  )}
                  <span className={`text-xs font-mono px-2 py-1 rounded capitalize ${STATUS_COLORS[sub.h1_status] || "text-gray-400"}`}>
                    {(sub.h1_status || "").replace(/_/g, " ")}
                  </span>
                  {expandedId === sub.id ? <ChevronUp className="w-4 h-4 text-gray-500" /> : <ChevronDown className="w-4 h-4 text-gray-500" />}
                </div>
              </div>

              {/* Expanded */}
              {expandedId === sub.id && detail && (
                <div className="border-t border-gray-800 p-4 bg-gray-950/50 space-y-4">
                  {/* Status Timeline */}
                  {detail.status_history?.length > 0 && (
                    <div>
                      <p className="text-xs text-gray-500 uppercase mb-2">{t("reports.status")}</p>
                      <div className="space-y-1">
                        {detail.status_history.map((h: any, i: number) => (
                          <div key={i} className="flex items-center gap-3 text-xs">
                            <span className="text-gray-600 font-mono w-36">
                              {h.at ? new Date(utc(h.at)).toLocaleString() : "—"}
                            </span>
                            <span className={`capitalize ${STATUS_COLORS[h.status] || "text-gray-400"} px-1.5 py-0.5 rounded`}>
                              {h.status?.replace(/_/g, " ")}
                            </span>
                            {h.note && <span className="text-gray-500">{h.note}</span>}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Report Preview */}
                  {(detail.report_markdown || reportMarkdown) && (
                    <div>
                      <p className="text-xs text-gray-500 uppercase mb-2">Report Preview</p>
                      <div className="bg-gray-800/50 rounded-lg p-3 max-h-60 overflow-y-auto">
                        <pre className="text-xs text-gray-300 whitespace-pre-wrap font-mono">
                          {detail.report_markdown || reportMarkdown}
                        </pre>
                      </div>
                    </div>
                  )}

                  {/* H1 Response */}
                  {detail.h1_response && (
                    <div>
                      <p className="text-xs text-gray-500 uppercase mb-1">H1 Response</p>
                      <p className="text-sm text-gray-300 bg-gray-800/50 rounded-lg px-3 py-2">{detail.h1_response}</p>
                    </div>
                  )}

                  {/* Update Status */}
                  <div className="border-t border-gray-800 pt-3">
                    <p className="text-xs text-gray-500 uppercase mb-2">Update Status</p>
                    {statusUpdate?.id === sub.id ? (
                      <div className="flex flex-wrap items-end gap-3">
                        <div>
                          <label className="text-xs text-gray-500 block mb-1">New Status</label>
                          <select
                            value={statusUpdate.status}
                            onChange={(e) => setStatusUpdate({ ...statusUpdate, status: e.target.value })}
                            className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-1.5 text-sm text-white"
                          >
                            {ALL_STATUSES.map((s) => (
                              <option key={s} value={s}>{s.replace(/_/g, " ")}</option>
                            ))}
                          </select>
                        </div>
                        <div>
                          <label className="text-xs text-gray-500 block mb-1">H1 Response</label>
                          <input
                            type="text"
                            value={statusUpdate.response}
                            onChange={(e) => setStatusUpdate({ ...statusUpdate, response: e.target.value })}
                            className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-1.5 text-sm text-white w-48"
                            placeholder="Optional response"
                          />
                        </div>
                        <div>
                          <label className="text-xs text-gray-500 block mb-1">Bounty ($)</label>
                          <input
                            type="number"
                            value={statusUpdate.bounty}
                            onChange={(e) => setStatusUpdate({ ...statusUpdate, bounty: e.target.value })}
                            className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-1.5 text-sm text-white w-24"
                            placeholder="0"
                          />
                        </div>
                        <button
                          onClick={handleStatusUpdate}
                          className="px-4 py-1.5 bg-green-600 hover:bg-green-700 rounded-lg text-sm text-white"
                        >
                          Save
                        </button>
                        <button
                          onClick={() => setStatusUpdate(null)}
                          className="px-4 py-1.5 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm text-gray-300"
                        >
                          Cancel
                        </button>
                      </div>
                    ) : (
                      <button
                        onClick={() => setStatusUpdate({ id: sub.id, status: sub.h1_status, response: "", bounty: "" })}
                        className="px-3 py-1.5 bg-gray-800 hover:bg-gray-700 rounded-lg text-sm text-gray-300"
                      >
                        Change Status
                      </button>
                    )}
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function StatusIcon({ status }: { status: string }) {
  switch (status) {
    case "accepted":
    case "bounty_paid":
    case "resolved":
      return <CheckCircle className="w-5 h-5 text-green-400 shrink-0" />;
    case "duplicate":
      return <Copy className="w-5 h-5 text-yellow-400 shrink-0" />;
    case "not_applicable":
    case "spam":
      return <XCircle className="w-5 h-5 text-red-400 shrink-0" />;
    case "triaged":
      return <Eye className="w-5 h-5 text-purple-400 shrink-0" />;
    case "submitted":
    case "new":
      return <Send className="w-5 h-5 text-blue-400 shrink-0" />;
    default:
      return <Clock className="w-5 h-5 text-gray-500 shrink-0" />;
  }
}
