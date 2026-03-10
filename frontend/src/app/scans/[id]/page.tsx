"use client";

import { useState, useEffect, useCallback, useRef, useMemo } from "react";
import { useParams } from "next/navigation";
import { useAuthStore } from "@/lib/store";
import LoginForm from "@/components/LoginForm";
import Sidebar from "@/components/Sidebar";
import ScanProgress from "@/components/ScanProgress";
import { getScan, getScanLogs, getTarget, getVulnerabilities, stopScan, getScanReportHtml, getScanReportPdf, reverifyVulnerability, exportVulnerabilities, getBountyReport, getTargetChanges, calculateCVSS } from "@/lib/api";
import { timeAgo, cn, parseUTC, severityColor } from "@/lib/utils";
import { ArrowLeft, StopCircle, Clock, Server, Globe, Bug, FileCode, Download, FileDown, Network, Cpu, Shield, ScrollText, Search, RefreshCw, CheckCircle, XCircle, Copy, X, FileText, ArrowLeftRight, Plus, Minus, ShieldCheck, AlertTriangle } from "lucide-react";
import Link from "next/link";

export default function ScanDetailPage() {
  const { isLoggedIn, init } = useAuthStore();
  const [loaded, setLoaded] = useState(false);

  useEffect(() => { init(); setLoaded(true); }, [init]);
  if (!loaded) return null;
  if (!isLoggedIn) return <LoginForm />;

  return (
    <div className="flex">
      <Sidebar />
      <main className="ml-60 flex-1 min-h-screen p-6">
        <ScanDetail />
      </main>
    </div>
  );
}

function ScanDetail() {
  const { id } = useParams();
  const [scan, setScan] = useState<any>(null);
  const [logs, setLogs] = useState<any[]>([]);
  const [target, setTarget] = useState<any>(null);
  const [vulns, setVulns] = useState<any[]>([]);
  const [wsConnected, setWsConnected] = useState(false);
  const [activeTab, setActiveTab] = useState("overview");
  const logsEndRef = useRef<HTMLDivElement>(null);
  const wsRef = useRef<WebSocket | null>(null);

  const load = useCallback(async () => {
    try {
      const s = await getScan(id as string);
      setScan(s);
      const l = await getScanLogs(id as string);
      setLogs(l);
      const t = await getTarget(s.target_id);
      setTarget(t);
      // Get vulns for this target (vulns may be linked to first scan that found them)
      const scanVulns = await getVulnerabilities({ target_id: t.id });
      setVulns(scanVulns);
    } catch {}
  }, [id]);

  useEffect(() => { load(); }, [load]);

  // WebSocket for live updates
  useEffect(() => {
    if (!id) return;
    const wsProtocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsHost = window.location.hostname;
    const port = window.location.port;
    const wsPort = !port || port === "80" || port === "443" ? "" : ":8000";
    const wsUrl = `${wsProtocol}//${wsHost}${wsPort}/ws/scans/${id}/live`;

    let ws: WebSocket;
    let reconnectTimer: NodeJS.Timeout;

    function connect() {
      ws = new WebSocket(wsUrl);
      wsRef.current = ws;
      ws.onopen = () => setWsConnected(true);
      ws.onclose = () => {
        setWsConnected(false);
        reconnectTimer = setTimeout(connect, 3000);
      };
      ws.onerror = () => ws.close();
      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (data.type === "progress") {
            setScan((prev: any) => prev ? {
              ...prev,
              current_phase: data.phase,
              progress_percent: data.progress,
              vulns_found: data.vulns_found ?? prev.vulns_found,
              endpoints_found: data.endpoints_found ?? prev.endpoints_found,
              subdomains_found: data.subdomains_found ?? prev.subdomains_found,
            } : prev);
          }
          if (data.type === "log") {
            setLogs((prev) => [...prev, {
              phase: data.phase, level: data.level,
              message: data.message, created_at: new Date().toISOString(),
            }]);
          }
          if (data.type === "complete") {
            setScan((prev: any) => prev ? { ...prev, status: "completed" } : prev);
            load();
          }
        } catch {}
      };
    }
    connect();
    return () => { clearTimeout(reconnectTimer); if (wsRef.current) wsRef.current.close(); };
  }, [id, load]);

  // Fallback polling
  useEffect(() => {
    if (wsConnected) return;
    const interval = setInterval(load, 5000);
    return () => clearInterval(interval);
  }, [wsConnected, load]);

  // Auto-scroll logs
  useEffect(() => {
    if (activeTab === "logs") logsEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [logs, activeTab]);

  // Live duration counter
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    if (scan?.status !== "running") return;
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, [scan?.status]);

  if (!scan) return <div className="text-gray-500">Loading...</div>;

  const isActive = scan.status === "running";
  const isComplete = scan.status === "completed";
  const duration = scan.started_at && scan.completed_at
    ? Math.round((parseUTC(scan.completed_at).getTime() - parseUTC(scan.started_at).getTime()) / 1000)
    : scan.started_at
    ? Math.round((now - parseUTC(scan.started_at).getTime()) / 1000)
    : 0;

  const tabs = [
    { id: "overview", label: "Overview", icon: Search },
    { id: "recon", label: "Recon", icon: Globe },
    { id: "endpoints", label: "Endpoints", icon: Network },
    { id: "vulns", label: `Vulns (${scan.vulns_found})`, icon: Bug },
    { id: "logs", label: `Logs (${logs.length})`, icon: ScrollText },
    { id: "changes", label: "Changes", icon: ArrowLeftRight },
  ];

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Link href="/scans" className="text-gray-500 hover:text-white transition">
            <ArrowLeft className="w-5 h-5" />
          </Link>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-xl font-bold text-white">{target?.domain || "Scan"}</h1>
              {scan.scan_type && (
                <span className={cn("text-[10px] px-2 py-0.5 rounded border font-medium uppercase",
                  scan.scan_type === "quick" ? "bg-green-950/50 text-green-400 border-green-900/50" :
                  scan.scan_type === "stealth" ? "bg-yellow-950/50 text-yellow-400 border-yellow-900/50" :
                  scan.scan_type === "recon" ? "bg-blue-950/50 text-blue-400 border-blue-900/50" :
                  "bg-purple-950/50 text-purple-400 border-purple-900/50"
                )}>
                  {scan.scan_type}
                </span>
              )}
              {wsConnected && (
                <span className="text-[9px] px-1.5 py-0.5 rounded bg-green-950/50 text-green-400 border border-green-900/50">LIVE</span>
              )}
            </div>
            <p className="text-xs text-gray-500 font-mono">{scan.id}</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {isComplete && (
            <>
              <button
                onClick={async () => {
                  try {
                    const html = await getScanReportHtml(scan.id);
                    const blob = new Blob([html], { type: "text/html" });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement("a"); a.href = url;
                    a.download = `phantom-report-${scan.id.slice(0, 8)}.html`;
                    a.click(); URL.revokeObjectURL(url);
                  } catch {}
                }}
                className="bg-purple-600/20 text-purple-400 hover:bg-purple-600/30 px-4 py-2 rounded-lg text-sm flex items-center gap-2 transition"
              >
                <Download className="w-4 h-4" /> HTML
              </button>
              <button
                onClick={async () => {
                  try {
                    const blob = await getScanReportPdf(scan.id);
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement("a"); a.href = url;
                    a.download = `phantom-report-${scan.id.slice(0, 8)}.pdf`;
                    a.click(); URL.revokeObjectURL(url);
                  } catch {}
                }}
                className="bg-blue-600/20 text-blue-400 hover:bg-blue-600/30 px-4 py-2 rounded-lg text-sm flex items-center gap-2 transition"
              >
                <FileDown className="w-4 h-4" /> PDF
              </button>
              <button
                onClick={async () => {
                  try {
                    const csv = await exportVulnerabilities("csv", { target_id: scan.target_id });
                    const blob = new Blob([csv], { type: "text/csv" });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement("a"); a.href = url;
                    a.download = `vulns-${scan.id.slice(0, 8)}.csv`;
                    a.click(); URL.revokeObjectURL(url);
                  } catch {}
                }}
                className="bg-gray-600/20 text-gray-400 hover:bg-gray-600/30 px-4 py-2 rounded-lg text-sm flex items-center gap-2 transition"
              >
                <FileCode className="w-4 h-4" /> CSV
              </button>
              <button
                onClick={() => window.location.href = `/validate?scan_id=${scan.id}`}
                className="bg-cyan-600/20 text-cyan-400 hover:bg-cyan-600/30 px-4 py-2 rounded-lg text-sm flex items-center gap-2 transition"
              >
                <ShieldCheck className="w-4 h-4" /> Validate
              </button>
            </>
          )}
          {isActive && (
            <button
              onClick={async () => { await stopScan(scan.id); load(); }}
              className="bg-red-600/20 text-red-400 hover:bg-red-600/30 px-4 py-2 rounded-lg text-sm flex items-center gap-2 transition"
            >
              <StopCircle className="w-4 h-4" /> Stop
            </button>
          )}
        </div>
      </div>

      {/* Progress */}
      <div className="bg-gray-900 rounded-xl border border-gray-800 p-5">
        <ScanProgress currentPhase={scan.current_phase || "recon"} progress={scan.progress_percent} status={scan.status} />
      </div>

      {/* Stats Row */}
      <div className="grid grid-cols-5 gap-3">
        <MiniStat icon={Clock} label="Duration" value={`${Math.floor(duration / 60)}m ${duration % 60}s`} />
        <MiniStat icon={Globe} label="Subdomains" value={scan.subdomains_found} />
        <MiniStat icon={Server} label="Endpoints" value={scan.endpoints_found} />
        <MiniStat icon={Bug} label="Vulns" value={scan.vulns_found} highlight={scan.vulns_found > 0} />
        <MiniStat icon={FileCode} label="Phase" value={scan.current_phase || "—"} />
      </div>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-gray-800 pb-0">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={cn(
              "flex items-center gap-1.5 px-4 py-2.5 text-xs font-medium rounded-t-lg transition",
              activeTab === tab.id
                ? "bg-gray-900 text-white border border-gray-800 border-b-gray-900 -mb-px"
                : "text-gray-500 hover:text-gray-300"
            )}
          >
            <tab.icon className="w-3.5 h-3.5" />
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      <div className="bg-gray-900 rounded-xl rounded-tl-none border border-gray-800 p-5">
        {activeTab === "overview" && <OverviewTab target={target} scan={scan} vulns={vulns} />}
        {activeTab === "recon" && <ReconTab target={target} />}
        {activeTab === "endpoints" && <EndpointsTab target={target} />}
        {activeTab === "vulns" && <VulnsTab vulns={vulns} />}
        {activeTab === "logs" && <LogsTab logs={logs} logsEndRef={logsEndRef} />}
        {activeTab === "changes" && target && <ChangesTab targetId={target.id} />}
      </div>
    </div>
  );
}

/* ========== TAB COMPONENTS ========== */

function OverviewTab({ target, scan, vulns }: { target: any; scan: any; vulns: any[] }) {
  const recon = target?.recon_data || {};
  const tech = target?.technologies?.summary || {};
  const ports = target?.ports || {};
  const subs = target?.subdomains || [];
  const dns = recon?.dns_records || [];

  return (
    <div className="space-y-6">
      {/* Summary Cards */}
      <div className="grid grid-cols-4 gap-4">
        <InfoCard title="DNS Records" value={dns.length} items={dns.map((d: any) => `${d.type}: ${d.value}`)} />
        <InfoCard title="Subdomains" value={subs.length} items={subs.slice(0, 5)} />
        <InfoCard title="Technologies" value={Object.keys(tech).length} items={Object.keys(tech).slice(0, 5)} />
        <InfoCard title="Open Ports" value={Object.values(ports).flat().length}
          items={Object.entries(ports).flatMap(([host, ps]: [string, any]) =>
            ps.map((p: any) => `${host}:${p.port} (${p.service})`)
          ).slice(0, 5)} />
      </div>

      {/* Robots.txt / Key Findings */}
      {recon?.robots_sitemap?.robots_txt && (
        <div>
          <h3 className="text-xs text-gray-500 uppercase font-medium mb-2">robots.txt</h3>
          <pre className="bg-gray-950 rounded-lg p-3 text-xs text-gray-400 font-mono overflow-x-auto max-h-40 overflow-y-auto">
            {recon.robots_sitemap.robots_txt}
          </pre>
        </div>
      )}

      {/* WHOIS */}
      {recon?.whois?.raw && (
        <div>
          <h3 className="text-xs text-gray-500 uppercase font-medium mb-2">WHOIS</h3>
          <pre className="bg-gray-950 rounded-lg p-3 text-xs text-gray-400 font-mono overflow-x-auto max-h-40 overflow-y-auto">
            {recon.whois.raw.slice(0, 1000)}
          </pre>
        </div>
      )}

      {/* Vulns Summary */}
      {vulns.length > 0 && (
        <div>
          <h3 className="text-xs text-gray-500 uppercase font-medium mb-2">Vulnerabilities Found</h3>
          <div className="space-y-1">
            {vulns.map((v: any) => (
              <div key={v.id} className="flex items-center gap-3 py-1.5 px-2 rounded hover:bg-gray-800/30">
                <span className={cn("text-[10px] px-2 py-0.5 rounded border font-bold uppercase w-[70px] text-center", severityColor(v.severity))}>{v.severity}</span>
                <span className="text-sm text-white flex-1 truncate">{v.title}</span>
                <span className="text-[10px] text-gray-700 font-mono bg-gray-800 px-1.5 py-0.5 rounded">{v.vuln_type}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {vulns.length === 0 && scan.status === "completed" && (
        <div className="text-center py-8 text-gray-600">
          <Shield className="w-10 h-10 mx-auto mb-2 opacity-30" />
          <p className="text-sm">No vulnerabilities detected</p>
          <p className="text-xs text-gray-700 mt-1">The target may be well-secured, or more advanced scanning techniques are needed.</p>
        </div>
      )}
    </div>
  );
}

function ReconTab({ target }: { target: any }) {
  const recon = target?.recon_data || {};
  const ports = target?.ports || {};
  const subs = target?.subdomains || [];
  const tech = target?.technologies || {};

  return (
    <div className="space-y-6">
      {/* DNS */}
      <Section title="DNS Records">
        {(recon.dns_records || []).length > 0 ? (
          <table className="w-full text-xs">
            <thead><tr className="text-gray-600 border-b border-gray-800">
              <th className="text-left py-1.5 font-medium w-20">Type</th>
              <th className="text-left py-1.5 font-medium">Value</th>
            </tr></thead>
            <tbody>
              {(recon.dns_records || []).map((r: any, i: number) => (
                <tr key={i} className="border-b border-gray-800/50">
                  <td className="py-1.5 text-blue-400 font-mono">{r.type}</td>
                  <td className="py-1.5 text-gray-300 font-mono break-all">{r.value}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : <Empty text="No DNS records collected" />}
      </Section>

      {/* Subdomains */}
      <Section title={`Subdomains (${subs.length})`}>
        {subs.length > 0 ? (
          <div className="flex flex-wrap gap-2">
            {subs.map((s: string, i: number) => (
              <span key={i} className="bg-gray-800 text-gray-300 text-xs font-mono px-2.5 py-1 rounded">{s}</span>
            ))}
          </div>
        ) : <Empty text="No subdomains discovered" />}
      </Section>

      {/* Open Ports */}
      <Section title="Open Ports">
        {Object.keys(ports).length > 0 ? (
          <table className="w-full text-xs">
            <thead><tr className="text-gray-600 border-b border-gray-800">
              <th className="text-left py-1.5 font-medium">Host</th>
              <th className="text-left py-1.5 font-medium w-16">Port</th>
              <th className="text-left py-1.5 font-medium w-20">Service</th>
              <th className="text-left py-1.5 font-medium">Version</th>
            </tr></thead>
            <tbody>
              {Object.entries(ports).flatMap(([host, ps]: [string, any]) =>
                ps.map((p: any, i: number) => (
                  <tr key={`${host}-${i}`} className="border-b border-gray-800/50">
                    <td className="py-1.5 text-gray-300 font-mono">{host}</td>
                    <td className="py-1.5 text-green-400 font-mono">{p.port}</td>
                    <td className="py-1.5 text-yellow-400">{p.service}</td>
                    <td className="py-1.5 text-gray-500 font-mono">{p.version || "—"}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        ) : <Empty text="No port scan data" />}
      </Section>

      {/* Technologies */}
      <Section title="Technologies">
        {Object.keys(tech.summary || {}).length > 0 ? (
          <div className="flex flex-wrap gap-2">
            {Object.keys(tech.summary || {}).map((t: string, i: number) => (
              <span key={i} className="bg-purple-950/50 text-purple-400 border border-purple-900/50 text-xs px-2.5 py-1 rounded">{t}</span>
            ))}
          </div>
        ) : <Empty text="No technologies detected" />}
      </Section>

      {/* Headers */}
      {recon.headers && Object.keys(recon.headers).length > 0 && (
        <Section title="HTTP Headers">
          <table className="w-full text-xs">
            <tbody>
              {Object.entries(recon.headers).map(([k, v]: [string, any], i: number) => (
                <tr key={i} className="border-b border-gray-800/50">
                  <td className="py-1 text-gray-500 font-mono w-48">{k}</td>
                  <td className="py-1 text-gray-300 font-mono break-all">{String(v)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Section>
      )}
    </div>
  );
}

function EndpointsTab({ target }: { target: any }) {
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState("all");

  // Endpoints are not stored on target — we need to get them from recon_data or show a note
  // For now, show what we have from robots.txt disallowed paths
  const recon = target?.recon_data || {};
  const robots = recon?.robots_sitemap?.robots_txt || "";

  // Extract disallowed paths from robots.txt
  const disallowed = robots
    .split("\n")
    .filter((l: string) => l.toLowerCase().startsWith("disallow:"))
    .map((l: string) => l.split(":").slice(1).join(":").trim())
    .filter(Boolean);

  const wayback = recon?.wayback_urls || [];

  return (
    <div className="space-y-6">
      <div className="text-xs text-gray-500 bg-gray-800/50 rounded-lg p-3">
        Endpoint data is collected during scanning but not persisted to the target. Below are paths found during reconnaissance.
      </div>

      {disallowed.length > 0 && (
        <Section title={`Disallowed Paths (robots.txt) — ${disallowed.length}`}>
          <div className="grid grid-cols-3 gap-1">
            {disallowed.map((p: string, i: number) => (
              <span key={i} className="text-xs font-mono text-orange-400 bg-gray-800 px-2 py-1 rounded truncate">{p}</span>
            ))}
          </div>
        </Section>
      )}

      {wayback.length > 0 && (
        <Section title={`Wayback URLs — ${wayback.length}`}>
          <div className="space-y-0.5 max-h-60 overflow-y-auto">
            {wayback.slice(0, 50).map((u: string, i: number) => (
              <div key={i} className="text-xs font-mono text-gray-400 truncate">{u}</div>
            ))}
            {wayback.length > 50 && <div className="text-xs text-gray-600">... and {wayback.length - 50} more</div>}
          </div>
        </Section>
      )}

      {disallowed.length === 0 && wayback.length === 0 && (
        <Empty text="No endpoint data available for display" />
      )}
    </div>
  );
}

function VulnsTab({ vulns }: { vulns: any[] }) {
  const [selected, setSelected] = useState<any>(null);
  const [verifying, setVerifying] = useState<string | null>(null);
  const [verifyResults, setVerifyResults] = useState<Record<string, any>>({});
  const [bountyReport, setBountyReport] = useState<any>(null);
  const [bountyLoading, setBountyLoading] = useState<string | null>(null);
  const [bountyVulnId, setBountyVulnId] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [cvssLoading, setCvssLoading] = useState<string | null>(null);
  const [cvssResults, setCvssResults] = useState<Record<string, any>>({});

  const handleReverify = async (e: React.MouseEvent, vulnId: string) => {
    e.stopPropagation();
    setVerifying(vulnId);
    try {
      const result = await reverifyVulnerability(vulnId);
      setVerifyResults(prev => ({ ...prev, [vulnId]: result }));
    } catch {
      setVerifyResults(prev => ({ ...prev, [vulnId]: { status: "error" } }));
    }
    setVerifying(null);
  };

  const handleBountyReport = async (e: React.MouseEvent, vulnId: string) => {
    e.stopPropagation();
    setBountyLoading(vulnId);
    try {
      const report = await getBountyReport(vulnId);
      setBountyReport(report);
      setBountyVulnId(vulnId);
    } catch {
      setBountyReport(null);
      setBountyVulnId(null);
    }
    setBountyLoading(null);
  };

  const handleCalculateCVSS = async (e: React.MouseEvent, vulnId: string) => {
    e.stopPropagation();
    setCvssLoading(vulnId);
    try {
      const result = await calculateCVSS(vulnId);
      setCvssResults(prev => ({ ...prev, [vulnId]: result.cvss }));
    } catch {
      setCvssResults(prev => ({ ...prev, [vulnId]: { error: true } }));
    }
    setCvssLoading(null);
  };

  const handleCopyReport = async () => {
    if (!bountyReport?.markdown) return;
    try {
      await navigator.clipboard.writeText(bountyReport.markdown);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Fallback for non-secure contexts
      const ta = document.createElement("textarea");
      ta.value = bountyReport.markdown;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand("copy");
      document.body.removeChild(ta);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const closeBountyModal = (e?: React.MouseEvent) => {
    if (e) e.stopPropagation();
    setBountyReport(null);
    setBountyVulnId(null);
    setCopied(false);
  };

  // Try to load existing CVSS data from ai_analysis for a vuln
  const getCvssData = (v: any) => {
    if (cvssResults[v.id]) return cvssResults[v.id];
    if (v.ai_analysis) {
      try {
        const parsed = typeof v.ai_analysis === "string" ? JSON.parse(v.ai_analysis) : v.ai_analysis;
        if (parsed?.cvss) return parsed.cvss;
      } catch {}
    }
    return null;
  };

  if (vulns.length === 0) {
    return (
      <div className="text-center py-12 text-gray-600">
        <Shield className="w-10 h-10 mx-auto mb-2 opacity-30" />
        <p>No vulnerabilities found in this scan.</p>
      </div>
    );
  }

  const sevOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const sorted = [...vulns].sort((a, b) => (sevOrder[a.severity] ?? 5) - (sevOrder[b.severity] ?? 5));

  return (
    <div className="space-y-2">
      {sorted.map((v: any) => {
        const cvss = getCvssData(v);
        return (
        <div
          key={v.id}
          onClick={() => setSelected(selected?.id === v.id ? null : v)}
          className="rounded-lg border border-gray-800 p-3 hover:border-gray-700 cursor-pointer transition"
        >
          <div className="flex items-center gap-3">
            <span className={cn("text-[10px] px-2 py-0.5 rounded border font-bold uppercase w-[70px] text-center", severityColor(v.severity))}>{v.severity}</span>
            <span className="text-white font-medium flex-1 truncate text-sm">{v.title}</span>
            {cvss && !cvss.error && (
              <span className={cn("text-[10px] font-bold px-1.5 py-0.5 rounded border",
                cvss.cvss_score >= 9.0 ? "bg-red-950/60 text-red-400 border-red-800/50" :
                cvss.cvss_score >= 7.0 ? "bg-orange-950/60 text-orange-400 border-orange-800/50" :
                cvss.cvss_score >= 4.0 ? "bg-yellow-950/60 text-yellow-400 border-yellow-800/50" :
                cvss.cvss_score >= 0.1 ? "bg-blue-950/60 text-blue-400 border-blue-800/50" :
                "bg-gray-800 text-gray-500 border-gray-700"
              )}>
                CVSS {cvss.cvss_score}
              </span>
            )}
            <span className="text-[10px] text-gray-700 font-mono bg-gray-800 px-1.5 py-0.5 rounded">{v.vuln_type}</span>
          </div>
          {selected?.id === v.id && (
            <div className="mt-3 pt-3 border-t border-gray-800 space-y-3 text-sm">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <span className="text-gray-500 text-xs">URL</span>
                  <p className="text-gray-300 font-mono text-xs break-all">{v.url}</p>
                </div>
                <div>
                  <span className="text-gray-500 text-xs">Parameter</span>
                  <p className="text-gray-300 font-mono text-xs">{v.parameter || "—"}</p>
                </div>
                <div>
                  <span className="text-gray-500 text-xs">Method</span>
                  <p className="text-gray-300">{v.method}</p>
                </div>
                <div>
                  <span className="text-gray-500 text-xs">AI Confidence</span>
                  <p className="text-gray-300">{((v.ai_confidence || 0) * 100).toFixed(0)}%</p>
                </div>
              </div>
              {v.description && (
                <div>
                  <span className="text-gray-500 text-xs">Description</span>
                  <p className="text-gray-400 text-xs mt-1">{v.description}</p>
                </div>
              )}
              {v.payload_used && (
                <div>
                  <span className="text-gray-500 text-xs">Payload</span>
                  <pre className="bg-gray-950 rounded-lg p-2 text-xs text-red-400 font-mono mt-1 overflow-x-auto">{v.payload_used}</pre>
                </div>
              )}
              {v.remediation && (
                <div>
                  <span className="text-gray-500 text-xs">Remediation</span>
                  <p className="text-gray-400 text-xs mt-1">{v.remediation}</p>
                </div>
              )}
              <div className="flex items-center gap-3 pt-2">
                <button
                  onClick={(e) => handleReverify(e, v.id)}
                  disabled={verifying === v.id}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-gray-800 hover:bg-gray-700 text-xs text-gray-300 disabled:opacity-50 transition"
                >
                  <RefreshCw className={cn("w-3 h-3", verifying === v.id && "animate-spin")} />
                  {verifying === v.id ? "Verifying..." : "Re-verify"}
                </button>
                <button
                  onClick={(e) => handleBountyReport(e, v.id)}
                  disabled={bountyLoading === v.id}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-amber-900/40 hover:bg-amber-800/50 border border-amber-700/50 text-xs text-amber-300 disabled:opacity-50 transition"
                >
                  <Bug className={cn("w-3 h-3", bountyLoading === v.id && "animate-pulse")} />
                  {bountyLoading === v.id ? "Generating..." : "Bug Bounty Report"}
                </button>
                <button
                  onClick={(e) => handleCalculateCVSS(e, v.id)}
                  disabled={cvssLoading === v.id}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-cyan-900/40 hover:bg-cyan-800/50 border border-cyan-700/50 text-xs text-cyan-300 disabled:opacity-50 transition"
                >
                  <ShieldCheck className={cn("w-3 h-3", cvssLoading === v.id && "animate-pulse")} />
                  {cvssLoading === v.id ? "Calculating..." : "Calculate CVSS"}
                </button>
                {verifyResults[v.id] && (
                  <span className={cn("text-xs flex items-center gap-1", verifyResults[v.id].status === "confirmed" ? "text-red-400" : verifyResults[v.id].status === "fixed" ? "text-green-400" : "text-yellow-400")}>
                    {verifyResults[v.id].status === "confirmed" ? <><XCircle className="w-3 h-3" /> Still vulnerable</> :
                     verifyResults[v.id].status === "fixed" ? <><CheckCircle className="w-3 h-3" /> Fixed</> :
                     "Error"}
                  </span>
                )}
                <span className={cn("text-[10px] px-2 py-0.5 rounded ml-auto",
                  v.status === "new" ? "bg-blue-900/30 text-blue-400" :
                  v.status === "confirmed" ? "bg-red-900/30 text-red-400" :
                  v.status === "fixed" ? "bg-green-900/30 text-green-400" :
                  "bg-gray-800 text-gray-500"
                )}>
                  {v.status}
                </span>
              </div>
              {/* CVSS Score Display */}
              {cvss && !cvss.error && (
                <div onClick={(e) => e.stopPropagation()} className="mt-3 rounded-lg border border-cyan-700/50 bg-cyan-950/20 overflow-hidden">
                  <div className="flex items-center justify-between px-4 py-2.5 bg-cyan-900/30 border-b border-cyan-700/50">
                    <div className="flex items-center gap-3">
                      <ShieldCheck className="w-4 h-4 text-cyan-400" />
                      <span className="text-sm font-medium text-cyan-300">CVSS 3.1 Score</span>
                    </div>
                    <div className="flex items-center gap-2">
                      {/* Score circle */}
                      <div className={cn(
                        "w-10 h-10 rounded-full flex items-center justify-center text-sm font-bold border-2",
                        cvss.cvss_score >= 9.0 ? "border-red-500 text-red-400 bg-red-950/50" :
                        cvss.cvss_score >= 7.0 ? "border-orange-500 text-orange-400 bg-orange-950/50" :
                        cvss.cvss_score >= 4.0 ? "border-yellow-500 text-yellow-400 bg-yellow-950/50" :
                        cvss.cvss_score >= 0.1 ? "border-blue-500 text-blue-400 bg-blue-950/50" :
                        "border-gray-500 text-gray-400 bg-gray-950/50"
                      )}>
                        {cvss.cvss_score}
                      </div>
                      <span className={cn("text-xs font-bold uppercase px-2 py-0.5 rounded",
                        cvss.severity === "critical" ? "bg-red-900/50 text-red-400" :
                        cvss.severity === "high" ? "bg-orange-900/50 text-orange-400" :
                        cvss.severity === "medium" ? "bg-yellow-900/50 text-yellow-400" :
                        cvss.severity === "low" ? "bg-blue-900/50 text-blue-400" :
                        "bg-gray-800 text-gray-500"
                      )}>
                        {cvss.severity}
                      </span>
                    </div>
                  </div>
                  <div className="p-4 space-y-3">
                    {/* Vector string */}
                    <div>
                      <span className="text-gray-500 text-xs">Vector String</span>
                      <p className="text-cyan-300 font-mono text-xs mt-0.5 bg-gray-950 rounded px-2 py-1.5 select-all">{cvss.cvss_vector}</p>
                    </div>
                    {/* Metric badges */}
                    <div>
                      <span className="text-gray-500 text-xs">Base Metrics</span>
                      <div className="flex flex-wrap gap-2 mt-1.5">
                        <CvssMetricBadge label="AV" value={cvss.attack_vector} />
                        <CvssMetricBadge label="AC" value={cvss.attack_complexity} />
                        <CvssMetricBadge label="PR" value={cvss.privileges_required} />
                        <CvssMetricBadge label="UI" value={cvss.user_interaction} />
                        <CvssMetricBadge label="S" value={cvss.scope} />
                        <CvssMetricBadge label="C" value={cvss.confidentiality} />
                        <CvssMetricBadge label="I" value={cvss.integrity} />
                        <CvssMetricBadge label="A" value={cvss.availability} />
                      </div>
                    </div>
                    {/* Reasoning */}
                    {cvss.reasoning && (
                      <div>
                        <span className="text-gray-500 text-xs">AI Reasoning</span>
                        <p className="text-gray-400 text-xs mt-1 leading-relaxed">{cvss.reasoning}</p>
                      </div>
                    )}
                  </div>
                </div>
              )}
              {cvss?.error && (
                <div onClick={(e) => e.stopPropagation()} className="mt-3 rounded-lg border border-red-700/50 bg-red-950/20 p-3">
                  <span className="text-red-400 text-xs flex items-center gap-1.5">
                    <AlertTriangle className="w-3 h-3" /> CVSS calculation failed. Try again.
                  </span>
                </div>
              )}
              {/* Bounty Report Expandable Section */}
              {bountyVulnId === v.id && bountyReport && (
                <div onClick={(e) => e.stopPropagation()} className="mt-3 rounded-lg border border-amber-700/50 bg-amber-950/20 overflow-hidden">
                  <div className="flex items-center justify-between px-4 py-2.5 bg-amber-900/30 border-b border-amber-700/50">
                    <div className="flex items-center gap-2">
                      <FileText className="w-4 h-4 text-amber-400" />
                      <span className="text-sm font-medium text-amber-300">HackerOne Bug Bounty Report</span>
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-amber-800/50 text-amber-400 border border-amber-700/40">
                        {bountyReport.cvss_rating} &middot; {bountyReport.vuln_type_cwe}
                      </span>
                    </div>
                    <div className="flex items-center gap-2">
                      <button
                        onClick={handleCopyReport}
                        className={cn(
                          "flex items-center gap-1.5 px-3 py-1 rounded text-xs transition",
                          copied
                            ? "bg-green-800/50 text-green-300 border border-green-600/50"
                            : "bg-amber-800/40 hover:bg-amber-700/50 text-amber-300 border border-amber-600/40"
                        )}
                      >
                        {copied ? (
                          <><CheckCircle className="w-3 h-3" /> Copied!</>
                        ) : (
                          <><Copy className="w-3 h-3" /> Copy to Clipboard</>
                        )}
                      </button>
                      <button
                        onClick={closeBountyModal}
                        className="p-1 rounded hover:bg-amber-800/40 text-amber-500 hover:text-amber-300 transition"
                      >
                        <X className="w-4 h-4" />
                      </button>
                    </div>
                  </div>
                  <div className="p-4 max-h-[500px] overflow-y-auto">
                    <pre className="whitespace-pre-wrap text-xs text-gray-300 font-mono leading-relaxed">{bountyReport.markdown}</pre>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
        );
      })}
    </div>
  );
}

function CvssMetricBadge({ label, value }: { label: string; value: string }) {
  // Color based on metric impact level
  const isHighImpact = ["High", "Network", "None", "Changed"].includes(value);
  const isMediumImpact = ["Low", "Adjacent", "Required"].includes(value);
  const colorClass = isHighImpact
    ? "bg-red-900/40 text-red-400 border-red-800/50"
    : isMediumImpact
    ? "bg-yellow-900/40 text-yellow-400 border-yellow-800/50"
    : "bg-green-900/40 text-green-400 border-green-800/50";

  return (
    <span className={cn("text-[10px] px-2 py-1 rounded border font-mono", colorClass)}>
      <span className="font-bold">{label}</span>: {value}
    </span>
  );
}

function LogsTab({ logs, logsEndRef }: { logs: any[]; logsEndRef: any }) {
  return (
    <div className="space-y-1 max-h-[600px] overflow-y-auto font-mono text-xs">
      {logs.map((log: any, i: number) => (
        <div key={i} className="flex gap-3 py-1 hover:bg-gray-800/30 px-2 rounded">
          <span className="text-gray-700 w-20 flex-shrink-0">{log.phase}</span>
          <span className={cn(
            "w-14 flex-shrink-0",
            log.level === "error" ? "text-red-400" :
            log.level === "warning" ? "text-yellow-400" :
            log.level === "success" ? "text-green-400" :
            "text-gray-500"
          )}>{log.level}</span>
          <span className="text-gray-300">{log.message}</span>
        </div>
      ))}
      {logs.length === 0 && <p className="text-gray-600 text-center py-4">Waiting for logs...</p>}
      <div ref={logsEndRef} />
    </div>
  );
}

function ChangesTab({ targetId }: { targetId: string }) {
  const [changes, setChanges] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function fetchChanges() {
      setLoading(true);
      setError(null);
      try {
        const data = await getTargetChanges(targetId);
        setChanges(data);
      } catch (e: any) {
        setError(e?.response?.data?.detail || "Failed to load changes");
      }
      setLoading(false);
    }
    fetchChanges();
  }, [targetId]);

  if (loading) {
    return (
      <div className="text-center py-12 text-gray-500">
        <RefreshCw className="w-6 h-6 mx-auto mb-2 animate-spin opacity-40" />
        <p className="text-sm">Loading scan diff...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="text-center py-12 text-red-400">
        <AlertTriangle className="w-6 h-6 mx-auto mb-2 opacity-50" />
        <p className="text-sm">{error}</p>
      </div>
    );
  }

  if (!changes?.has_changes) {
    return (
      <div className="text-center py-12 text-gray-600">
        <ArrowLeftRight className="w-10 h-10 mx-auto mb-2 opacity-20" />
        <p className="text-sm">{changes?.message || "No changes detected"}</p>
        {changes?.scans_available !== undefined && changes.scans_available < 2 && (
          <p className="text-xs text-gray-700 mt-1">
            Run at least 2 completed scans on this target to see a diff.
          </p>
        )}
      </div>
    );
  }

  const { summary, new_vulns, fixed_vulns, new_endpoints, removed_endpoints, latest_scan, previous_scan } = changes;

  return (
    <div className="space-y-6">
      {/* Summary Banner */}
      <div className="bg-gray-950 rounded-lg border border-gray-800 p-4">
        <div className="flex items-center gap-3 mb-3">
          <ArrowLeftRight className="w-4 h-4 text-purple-400" />
          <span className="text-sm font-medium text-white">Scan Diff Summary</span>
        </div>
        <div className="grid grid-cols-4 gap-3">
          <div className="text-center">
            <p className={cn("text-lg font-bold", summary.new_vulns_count > 0 ? "text-red-400" : "text-gray-500")}>
              {summary.new_vulns_count}
            </p>
            <p className="text-[10px] text-gray-600 uppercase">New Vulns</p>
          </div>
          <div className="text-center">
            <p className={cn("text-lg font-bold", summary.fixed_vulns_count > 0 ? "text-green-400" : "text-gray-500")}>
              {summary.fixed_vulns_count}
            </p>
            <p className="text-[10px] text-gray-600 uppercase">Fixed</p>
          </div>
          <div className="text-center">
            <p className={cn("text-lg font-bold", summary.new_endpoints_count > 0 ? "text-blue-400" : "text-gray-500")}>
              {summary.new_endpoints_count}
            </p>
            <p className="text-[10px] text-gray-600 uppercase">New Endpoints</p>
          </div>
          <div className="text-center">
            <p className={cn("text-lg font-bold", summary.removed_endpoints_count > 0 ? "text-yellow-400" : "text-gray-500")}>
              {summary.removed_endpoints_count}
            </p>
            <p className="text-[10px] text-gray-600 uppercase">Removed Endpoints</p>
          </div>
        </div>
        <div className="flex items-center justify-between mt-3 pt-3 border-t border-gray-800 text-[10px] text-gray-600">
          <span>Previous: {previous_scan.completed_at?.slice(0, 19)} ({previous_scan.vulns_count} vulns)</span>
          <span>Latest: {latest_scan.completed_at?.slice(0, 19)} ({latest_scan.vulns_count} vulns)</span>
        </div>
      </div>

      {/* New Vulnerabilities */}
      {new_vulns.length > 0 && (
        <div>
          <h3 className="text-xs text-gray-500 uppercase font-medium mb-2 flex items-center gap-2">
            <AlertTriangle className="w-3.5 h-3.5 text-red-400" />
            New Vulnerabilities ({new_vulns.length})
          </h3>
          <div className="space-y-1.5">
            {new_vulns.map((v: any, i: number) => (
              <div
                key={i}
                className="flex items-center gap-3 py-2 px-3 rounded-lg bg-gray-950 border-l-4 border-l-red-500 border border-gray-800"
              >
                <span className="text-[9px] px-1.5 py-0.5 rounded bg-red-950 text-red-400 border border-red-800 font-bold uppercase">
                  NEW
                </span>
                <span className={cn("text-[10px] px-2 py-0.5 rounded border font-bold uppercase w-[70px] text-center", severityColor(v.severity))}>
                  {v.severity}
                </span>
                <span className="text-sm text-white flex-1 truncate">{v.title}</span>
                <span className="text-[10px] text-gray-700 font-mono bg-gray-800 px-1.5 py-0.5 rounded">{v.type}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Fixed Vulnerabilities */}
      {fixed_vulns.length > 0 && (
        <div>
          <h3 className="text-xs text-gray-500 uppercase font-medium mb-2 flex items-center gap-2">
            <ShieldCheck className="w-3.5 h-3.5 text-green-400" />
            Fixed Vulnerabilities ({fixed_vulns.length})
          </h3>
          <div className="space-y-1.5">
            {fixed_vulns.map((v: any, i: number) => (
              <div
                key={i}
                className="flex items-center gap-3 py-2 px-3 rounded-lg bg-gray-950 border-l-4 border-l-green-500 border border-gray-800"
              >
                <span className="text-[9px] px-1.5 py-0.5 rounded bg-green-950 text-green-400 border border-green-800 font-bold uppercase">
                  FIXED
                </span>
                <span className={cn("text-[10px] px-2 py-0.5 rounded border font-bold uppercase w-[70px] text-center opacity-50", severityColor(v.severity))}>
                  {v.severity}
                </span>
                <span className="text-sm text-gray-500 flex-1 truncate line-through">{v.title}</span>
                <span className="text-[10px] text-gray-700 font-mono bg-gray-800 px-1.5 py-0.5 rounded">{v.type}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* New Endpoints */}
      {new_endpoints.length > 0 && (
        <div>
          <h3 className="text-xs text-gray-500 uppercase font-medium mb-2 flex items-center gap-2">
            <Plus className="w-3.5 h-3.5 text-green-400" />
            New Endpoints ({new_endpoints.length})
          </h3>
          <div className="space-y-1 max-h-60 overflow-y-auto">
            {new_endpoints.map((ep: string, i: number) => (
              <div key={i} className="flex items-center gap-2 py-1.5 px-3 rounded bg-gray-950 border border-gray-800">
                <span className="text-green-400 font-bold text-xs">+</span>
                <span className="text-xs font-mono text-green-300 truncate">{ep}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Removed Endpoints */}
      {removed_endpoints.length > 0 && (
        <div>
          <h3 className="text-xs text-gray-500 uppercase font-medium mb-2 flex items-center gap-2">
            <Minus className="w-3.5 h-3.5 text-red-400" />
            Removed Endpoints ({removed_endpoints.length})
          </h3>
          <div className="space-y-1 max-h-60 overflow-y-auto">
            {removed_endpoints.map((ep: string, i: number) => (
              <div key={i} className="flex items-center gap-2 py-1.5 px-3 rounded bg-gray-950 border border-gray-800">
                <span className="text-red-400 font-bold text-xs">-</span>
                <span className="text-xs font-mono text-red-300 truncate line-through">{ep}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

/* ========== SHARED COMPONENTS ========== */

function MiniStat({ icon: Icon, label, value, highlight }: {
  icon: any; label: string; value: any; highlight?: boolean;
}) {
  return (
    <div className="bg-gray-900 rounded-lg border border-gray-800 p-3 text-center">
      <Icon className={cn("w-4 h-4 mx-auto mb-1", highlight ? "text-red-400" : "text-gray-600")} />
      <p className={cn("text-lg font-bold", highlight ? "text-red-400" : "text-white")}>{value}</p>
      <p className="text-[10px] text-gray-600">{label}</p>
    </div>
  );
}

function InfoCard({ title, value, items }: { title: string; value: number; items: string[] }) {
  return (
    <div className="bg-gray-950 rounded-lg border border-gray-800 p-3">
      <div className="flex items-center justify-between mb-2">
        <span className="text-xs text-gray-500">{title}</span>
        <span className="text-sm font-bold text-white">{value}</span>
      </div>
      <div className="space-y-0.5">
        {items.map((item, i) => (
          <div key={i} className="text-[11px] text-gray-400 font-mono truncate">{item}</div>
        ))}
        {items.length === 0 && <div className="text-[11px] text-gray-700">No data</div>}
      </div>
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <h3 className="text-xs text-gray-500 uppercase font-medium mb-2">{title}</h3>
      {children}
    </div>
  );
}

function Empty({ text }: { text: string }) {
  return <p className="text-xs text-gray-600 py-4 text-center">{text}</p>;
}
