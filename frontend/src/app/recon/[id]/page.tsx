"use client";

import { useState, useEffect, useCallback, useMemo } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { useAuthStore } from "@/lib/store";
import LoginForm from "@/components/LoginForm";
import Sidebar from "@/components/Sidebar";
import { getTargetRecon } from "@/lib/api";
import { cn, severityColor, timeAgo } from "@/lib/utils";
import {
  ArrowLeft,
  Radar,
  Globe,
  Shield,
  Network,
  Search,
  Copy,
  Check,
  Server,
  Code,
  Layers,
  Activity,
  AlertTriangle,
  ChevronRight,
  ExternalLink,
  Eye,
  Clock,
  Bug,
  Crosshair,
  MonitorSmartphone,
  Wifi,
} from "lucide-react";

// Port classification
function portClass(port: string): string {
  const p = parseInt(port);
  const dangerous = [21, 22, 23, 25, 135, 139, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 9200, 27017];
  const interesting = [53, 110, 143, 389, 443, 587, 636, 993, 995, 2082, 2083, 8443, 8888, 9090];
  if (dangerous.includes(p)) return "dangerous";
  if (interesting.includes(p)) return "interesting";
  return "common";
}

function portColor(classification: string): string {
  const map: Record<string, string> = {
    dangerous: "text-red-400 bg-red-950 border-red-800",
    interesting: "text-yellow-400 bg-yellow-950 border-yellow-800",
    common: "text-green-400 bg-green-950 border-green-800",
  };
  return map[classification] || map.common;
}

// Interesting endpoint patterns
const INTERESTING_PATTERNS = [
  "admin", "config", "debug", "backup", "test", "staging", "dev",
  "internal", "private", "secret", "token", "auth", "login",
  "upload", "console", "dashboard", "phpmyadmin", "wp-admin",
  ".env", ".git", ".bak", "swagger", "graphql", "api-docs",
];

function isInterestingEndpoint(endpoint: string): boolean {
  const lower = endpoint.toLowerCase();
  return INTERESTING_PATTERNS.some((p) => lower.includes(p));
}

// Tech category icons
function techCategoryLabel(key: string): string {
  const map: Record<string, string> = {
    web_server: "Web Server",
    framework: "Framework",
    language: "Language",
    cdn: "CDN",
    cms: "CMS",
    database: "Database",
    os: "Operating System",
    js_framework: "JS Framework",
    analytics: "Analytics",
    cache: "Cache",
    waf: "WAF",
    proxy: "Reverse Proxy",
    ssl: "SSL/TLS",
    security: "Security",
  };
  return map[key] || key.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

export default function ReconDetailPage() {
  const { isLoggedIn, init } = useAuthStore();
  const [loaded, setLoaded] = useState(false);

  useEffect(() => { init(); setLoaded(true); }, [init]);
  if (!loaded) return null;
  if (!isLoggedIn) return <LoginForm />;

  return (
    <div className="flex">
      <Sidebar />
      <main className="ml-60 flex-1 min-h-screen p-6">
        <ReconDetailContent />
      </main>
    </div>
  );
}

function ReconDetailContent() {
  const params = useParams();
  const targetId = params.id as string;
  const [recon, setRecon] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [subSearch, setSubSearch] = useState("");
  const [endpointSearch, setEndpointSearch] = useState("");
  const [copiedItem, setCopiedItem] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const data = await getTargetRecon(targetId);
      setRecon(data);
    } catch (e: any) {
      setError(e?.response?.data?.detail || "Failed to load recon data");
    }
    setLoading(false);
  }, [targetId]);

  useEffect(() => { load(); }, [load]);

  function copyToClipboard(text: string) {
    navigator.clipboard.writeText(text);
    setCopiedItem(text);
    setTimeout(() => setCopiedItem(null), 2000);
  }

  // Group endpoints by prefix
  const endpointGroups = useMemo(() => {
    if (!recon?.endpoints) return {};
    const groups: Record<string, string[]> = {};
    const endpoints = recon.endpoints.filter((ep: string) =>
      ep.toLowerCase().includes(endpointSearch.toLowerCase())
    );
    endpoints.forEach((ep: string) => {
      try {
        const url = new URL(ep);
        const parts = url.pathname.split("/").filter(Boolean);
        const prefix = parts.length > 1 ? `/${parts[0]}/${parts[1]}` : parts.length === 1 ? `/${parts[0]}` : "/";
        if (!groups[prefix]) groups[prefix] = [];
        groups[prefix].push(ep);
      } catch {
        const prefix = "/other";
        if (!groups[prefix]) groups[prefix] = [];
        groups[prefix].push(ep);
      }
    });
    return groups;
  }, [recon?.endpoints, endpointSearch]);

  // Filtered subdomains
  const filteredSubdomains = useMemo(() => {
    if (!recon?.subdomains) return [];
    return recon.subdomains.filter((s: string) =>
      s.toLowerCase().includes(subSearch.toLowerCase())
    );
  }, [recon?.subdomains, subSearch]);

  // Severity bar chart data
  const severityData = useMemo(() => {
    if (!recon?.severity_distribution) return [];
    const order = ["critical", "high", "medium", "low", "info"];
    const colors: Record<string, string> = {
      critical: "bg-red-500",
      high: "bg-orange-500",
      medium: "bg-yellow-500",
      low: "bg-blue-500",
      info: "bg-gray-500",
    };
    const maxVal = Math.max(1, ...Object.values(recon.severity_distribution as Record<string, number>));
    return order
      .filter((s) => (recon.severity_distribution[s] || 0) > 0)
      .map((s) => ({
        label: s,
        count: recon.severity_distribution[s] || 0,
        pct: ((recon.severity_distribution[s] || 0) / maxVal) * 100,
        color: colors[s],
      }));
  }, [recon?.severity_distribution]);

  if (loading) {
    return (
      <div className="text-center py-20 text-gray-600">
        <Radar className="w-12 h-12 mx-auto mb-3 opacity-30 animate-spin" />
        <p>Loading recon data...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="text-center py-20">
        <AlertTriangle className="w-12 h-12 mx-auto mb-3 text-red-400 opacity-60" />
        <p className="text-red-400">{error}</p>
        <Link href="/recon" className="text-sm text-gray-500 hover:text-white mt-3 inline-block">
          Back to targets
        </Link>
      </div>
    );
  }

  if (!recon) return null;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Link
            href="/recon"
            className="text-gray-500 hover:text-white transition p-2 rounded-lg hover:bg-gray-900"
          >
            <ArrowLeft className="w-5 h-5" />
          </Link>
          <div>
            <h1 className="text-2xl font-bold text-white flex items-center gap-3">
              <Globe className="w-6 h-6 text-red-400" />
              {recon.domain}
            </h1>
            <p className="text-sm text-gray-500 mt-0.5">Target Reconnaissance Overview</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {recon.monitoring?.enabled && (
            <span className="text-[10px] px-3 py-1 rounded-full uppercase font-medium text-blue-400 bg-blue-950 border border-blue-800 flex items-center gap-1.5">
              <Activity className="w-3 h-3" />
              Monitoring {recon.monitoring.interval}
            </span>
          )}
          <span className="text-[10px] px-3 py-1 rounded-full uppercase font-medium text-green-400 bg-green-950 border border-green-800">
            Active
          </span>
        </div>
      </div>

      {/* Stats Row */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        {[
          { label: "Total Scans", value: recon.total_scans || 0, icon: Crosshair, color: "text-blue-400" },
          { label: "Vulnerabilities", value: recon.total_vulns || 0, icon: Bug, color: "text-red-400" },
          { label: "Endpoints", value: recon.total_endpoints || 0, icon: Network, color: "text-green-400" },
          { label: "Subdomains", value: recon.subdomain_count || 0, icon: Layers, color: "text-purple-400" },
          { label: "Technologies", value: Object.keys(recon.technologies || {}).length, icon: MonitorSmartphone, color: "text-yellow-400" },
        ].map((stat) => (
          <div
            key={stat.label}
            className="bg-gray-900 rounded-xl border border-gray-800 p-4"
          >
            <div className="flex items-center justify-between mb-2">
              <stat.icon className={cn("w-5 h-5", stat.color)} />
              <span className="text-2xl font-bold text-white">{stat.value}</span>
            </div>
            <p className="text-xs text-gray-500">{stat.label}</p>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Subdomains Section */}
        <div className="bg-gray-900 rounded-xl border border-gray-800 p-5">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-semibold text-white flex items-center gap-2">
              <Layers className="w-4 h-4 text-purple-400" />
              Subdomains
              <span className="text-[10px] px-2 py-0.5 rounded-full bg-purple-950 text-purple-400 border border-purple-800 font-medium">
                {recon.subdomain_count || 0}
              </span>
            </h2>
            <div className="relative">
              <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-gray-600" />
              <input
                type="text"
                value={subSearch}
                onChange={(e) => setSubSearch(e.target.value)}
                placeholder="Filter..."
                className="bg-gray-800 border border-gray-700 rounded-lg pl-8 pr-3 py-1.5 text-xs text-white focus:outline-none focus:border-red-500 w-40"
              />
            </div>
          </div>
          <div className="max-h-64 overflow-y-auto space-y-1.5 pr-1 custom-scrollbar">
            {filteredSubdomains.length === 0 ? (
              <p className="text-xs text-gray-600 text-center py-6">
                {subSearch ? "No subdomains match filter" : "No subdomains discovered"}
              </p>
            ) : (
              <div className="flex flex-wrap gap-2">
                {filteredSubdomains.map((sub: string) => (
                  <button
                    key={sub}
                    onClick={() => copyToClipboard(sub)}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-gray-800 border border-gray-700 text-xs text-gray-300 hover:border-purple-600 hover:text-purple-300 transition group"
                    title="Click to copy"
                  >
                    {sub}
                    {copiedItem === sub ? (
                      <Check className="w-3 h-3 text-green-400" />
                    ) : (
                      <Copy className="w-3 h-3 opacity-0 group-hover:opacity-100 transition" />
                    )}
                  </button>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Technology Stack */}
        <div className="bg-gray-900 rounded-xl border border-gray-800 p-5">
          <h2 className="text-sm font-semibold text-white flex items-center gap-2 mb-4">
            <Code className="w-4 h-4 text-yellow-400" />
            Technology Stack
          </h2>
          {Object.keys(recon.technologies || {}).length === 0 ? (
            <p className="text-xs text-gray-600 text-center py-6">No technologies detected</p>
          ) : (
            <div className="space-y-3 max-h-64 overflow-y-auto pr-1">
              {Object.entries(recon.technologies || {}).map(([category, value]) => (
                <div key={category} className="flex items-center justify-between">
                  <span className="text-xs text-gray-500">{techCategoryLabel(category)}</span>
                  <span className="text-xs font-medium px-3 py-1 rounded-lg bg-gray-800 border border-gray-700 text-yellow-300">
                    {typeof value === "string" ? value : JSON.stringify(value)}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Ports & Services */}
      <div className="bg-gray-900 rounded-xl border border-gray-800 p-5">
        <h2 className="text-sm font-semibold text-white flex items-center gap-2 mb-4">
          <Wifi className="w-4 h-4 text-green-400" />
          Ports & Services
          <span className="text-[10px] px-2 py-0.5 rounded-full bg-green-950 text-green-400 border border-green-800 font-medium">
            {Object.keys(recon.ports || {}).length} open
          </span>
        </h2>
        {Object.keys(recon.ports || {}).length === 0 ? (
          <p className="text-xs text-gray-600 text-center py-6">No open ports detected</p>
        ) : (
          <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-6 gap-3">
            {Object.entries(recon.ports || {}).sort(([a], [b]) => parseInt(a) - parseInt(b)).map(([port, service]) => {
              const cls = portClass(port);
              return (
                <div
                  key={port}
                  className={cn(
                    "rounded-lg border px-3 py-2 text-center",
                    portColor(cls)
                  )}
                >
                  <p className="text-lg font-bold">{port}</p>
                  <p className="text-[10px] uppercase opacity-80">{typeof service === "string" ? service : "unknown"}</p>
                </div>
              );
            })}
          </div>
        )}
        <div className="flex items-center gap-4 mt-3 pt-3 border-t border-gray-800">
          <div className="flex items-center gap-1.5 text-[10px] text-gray-600">
            <span className="w-2 h-2 rounded-full bg-green-500" /> Common
          </div>
          <div className="flex items-center gap-1.5 text-[10px] text-gray-600">
            <span className="w-2 h-2 rounded-full bg-yellow-500" /> Interesting
          </div>
          <div className="flex items-center gap-1.5 text-[10px] text-gray-600">
            <span className="w-2 h-2 rounded-full bg-red-500" /> Dangerous
          </div>
        </div>
      </div>

      {/* Endpoints Explorer */}
      <div className="bg-gray-900 rounded-xl border border-gray-800 p-5">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-sm font-semibold text-white flex items-center gap-2">
            <Network className="w-4 h-4 text-green-400" />
            Endpoints Explorer
            <span className="text-[10px] px-2 py-0.5 rounded-full bg-green-950 text-green-400 border border-green-800 font-medium">
              {recon.total_endpoints || 0} total
            </span>
          </h2>
          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-gray-600" />
            <input
              type="text"
              value={endpointSearch}
              onChange={(e) => setEndpointSearch(e.target.value)}
              placeholder="Search endpoints..."
              className="bg-gray-800 border border-gray-700 rounded-lg pl-8 pr-3 py-1.5 text-xs text-white focus:outline-none focus:border-red-500 w-56"
            />
          </div>
        </div>
        <div className="max-h-96 overflow-y-auto space-y-3 pr-1">
          {Object.keys(endpointGroups).length === 0 ? (
            <p className="text-xs text-gray-600 text-center py-6">
              {endpointSearch ? "No endpoints match search" : "No endpoints discovered"}
            </p>
          ) : (
            Object.entries(endpointGroups)
              .sort(([a], [b]) => a.localeCompare(b))
              .map(([prefix, endpoints]) => (
                <EndpointGroup key={prefix} prefix={prefix} endpoints={endpoints as string[]} />
              ))
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Vulnerability Summary */}
        <div className="bg-gray-900 rounded-xl border border-gray-800 p-5">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-semibold text-white flex items-center gap-2">
              <Shield className="w-4 h-4 text-red-400" />
              Vulnerability Summary
            </h2>
            <Link
              href={`/vulnerabilities?target_id=${targetId}`}
              className="text-[10px] text-red-400 hover:text-red-300 flex items-center gap-1 transition"
            >
              View All <ChevronRight className="w-3 h-3" />
            </Link>
          </div>

          {/* Severity bars */}
          {severityData.length === 0 ? (
            <p className="text-xs text-gray-600 text-center py-6">No vulnerabilities found</p>
          ) : (
            <div className="space-y-3 mb-5">
              {severityData.map((s) => (
                <div key={s.label} className="space-y-1">
                  <div className="flex items-center justify-between text-xs">
                    <span className="capitalize text-gray-400">{s.label}</span>
                    <span className="text-white font-medium">{s.count}</span>
                  </div>
                  <div className="h-2 bg-gray-800 rounded-full overflow-hidden">
                    <div
                      className={cn("h-full rounded-full transition-all duration-500", s.color)}
                      style={{ width: `${s.pct}%` }}
                    />
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* By type breakdown */}
          {Object.keys(recon.vuln_summary || {}).length > 0 && (
            <div className="border-t border-gray-800 pt-4">
              <p className="text-[10px] text-gray-600 uppercase tracking-wider mb-3">By Type</p>
              <div className="space-y-2 max-h-48 overflow-y-auto pr-1">
                {Object.entries(recon.vuln_summary || {})
                  .sort(([, a]: any, [, b]: any) => b.count - a.count)
                  .map(([type, info]: [string, any]) => (
                    <div
                      key={type}
                      className="flex items-center justify-between text-xs py-1.5 px-2 rounded-lg hover:bg-gray-800 transition"
                    >
                      <span className="text-gray-400">{type.replace(/_/g, " ")}</span>
                      <div className="flex items-center gap-2">
                        {info.severities && Object.entries(info.severities).map(([sev, cnt]: [string, any]) => (
                          <span
                            key={sev}
                            className={cn("text-[10px] px-1.5 py-0.5 rounded border", severityColor(sev))}
                          >
                            {cnt}
                          </span>
                        ))}
                        <span className="text-white font-medium ml-1">{info.count}</span>
                      </div>
                    </div>
                  ))}
              </div>
            </div>
          )}
        </div>

        {/* Scan History Timeline */}
        <div className="bg-gray-900 rounded-xl border border-gray-800 p-5">
          <h2 className="text-sm font-semibold text-white flex items-center gap-2 mb-4">
            <Clock className="w-4 h-4 text-blue-400" />
            Scan History
            <span className="text-[10px] px-2 py-0.5 rounded-full bg-blue-950 text-blue-400 border border-blue-800 font-medium">
              {recon.scan_history?.length || 0} scans
            </span>
          </h2>
          {(!recon.scan_history || recon.scan_history.length === 0) ? (
            <p className="text-xs text-gray-600 text-center py-6">No scan history</p>
          ) : (
            <div className="space-y-1 max-h-80 overflow-y-auto pr-1">
              {recon.scan_history.map((scan: any, i: number) => (
                <Link
                  key={scan.id || i}
                  href={`/scans/${scan.id}`}
                  className="flex items-center gap-3 px-3 py-2.5 rounded-lg hover:bg-gray-800 transition group"
                >
                  {/* Timeline dot + line */}
                  <div className="flex flex-col items-center">
                    <div className={cn(
                      "w-2.5 h-2.5 rounded-full",
                      scan.status === "completed" ? "bg-blue-500" :
                      scan.status === "running" ? "bg-green-500 animate-pulse" :
                      scan.status === "failed" ? "bg-red-500" :
                      "bg-gray-600"
                    )} />
                    {i < recon.scan_history.length - 1 && (
                      <div className="w-px h-6 bg-gray-800 mt-1" />
                    )}
                  </div>

                  <div className="flex-1 min-w-0">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="text-xs text-white font-medium capitalize">
                          {scan.scan_type || "full"}
                        </span>
                        <span className={cn(
                          "text-[10px] px-1.5 py-0.5 rounded",
                          scan.status === "completed" ? "text-blue-400 bg-blue-950" :
                          scan.status === "running" ? "text-green-400 bg-green-950" :
                          scan.status === "failed" ? "text-red-400 bg-red-950" :
                          "text-gray-500 bg-gray-800"
                        )}>
                          {scan.status}
                        </span>
                      </div>
                      <ExternalLink className="w-3 h-3 text-gray-700 group-hover:text-gray-400 transition" />
                    </div>
                    <div className="flex items-center gap-3 mt-1 text-[10px] text-gray-600">
                      {scan.created_at && <span>{timeAgo(scan.created_at)}</span>}
                      {scan.vulns_found !== undefined && (
                        <span className="flex items-center gap-1">
                          <Bug className="w-2.5 h-2.5" /> {scan.vulns_found} vulns
                        </span>
                      )}
                      {scan.endpoints_found !== undefined && (
                        <span className="flex items-center gap-1">
                          <Network className="w-2.5 h-2.5" /> {scan.endpoints_found} endpoints
                        </span>
                      )}
                    </div>
                  </div>
                </Link>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// Collapsible endpoint group component
function EndpointGroup({ prefix, endpoints }: { prefix: string; endpoints: string[] }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="rounded-lg border border-gray-800 overflow-hidden">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center justify-between px-3 py-2 hover:bg-gray-800/50 transition text-left"
      >
        <div className="flex items-center gap-2">
          <ChevronRight className={cn(
            "w-3.5 h-3.5 text-gray-600 transition-transform",
            expanded && "rotate-90"
          )} />
          <span className="text-xs font-medium text-gray-300">{prefix}</span>
        </div>
        <span className="text-[10px] text-gray-600">{endpoints.length} endpoint{endpoints.length !== 1 ? "s" : ""}</span>
      </button>
      {expanded && (
        <div className="border-t border-gray-800 px-3 py-2 space-y-1 bg-gray-950/50">
          {endpoints.map((ep) => (
            <div
              key={ep}
              className={cn(
                "flex items-center gap-2 py-1 px-2 rounded text-xs",
                isInterestingEndpoint(ep)
                  ? "text-yellow-300 bg-yellow-950/30"
                  : "text-gray-400"
              )}
            >
              {isInterestingEndpoint(ep) && (
                <Eye className="w-3 h-3 text-yellow-500 flex-shrink-0" />
              )}
              <span className="truncate flex-1 font-mono text-[11px]">{ep}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
