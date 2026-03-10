"use client";

import { useState, useEffect, useCallback } from "react";
import { useAuthStore } from "@/lib/store";
import LoginForm from "@/components/LoginForm";
import Sidebar from "@/components/Sidebar";
import ScanProgress from "@/components/ScanProgress";
import { getScans, getTargets, stopScan, deleteScan } from "@/lib/api";
import { timeAgo, statusColor, cn, parseUTC } from "@/lib/utils";
import { StopCircle, ExternalLink, Trash2 } from "lucide-react";
import Link from "next/link";

export default function ScansPage() {
  const { isLoggedIn, init } = useAuthStore();
  const [loaded, setLoaded] = useState(false);

  useEffect(() => { init(); setLoaded(true); }, [init]);
  if (!loaded) return null;
  if (!isLoggedIn) return <LoginForm />;

  return (
    <div className="flex">
      <Sidebar />
      <main className="ml-60 flex-1 min-h-screen p-6">
        <ScansContent />
      </main>
    </div>
  );
}

const TYPE_COLORS: Record<string, string> = {
  full: "bg-purple-950/50 text-purple-400 border-purple-900/50",
  quick: "bg-green-950/50 text-green-400 border-green-900/50",
  stealth: "bg-yellow-950/50 text-yellow-400 border-yellow-900/50",
  recon: "bg-blue-950/50 text-blue-400 border-blue-900/50",
};

function formatDuration(scan: any): string {
  if (!scan.started_at) return "—";
  const start = parseUTC(scan.started_at).getTime();
  const end = scan.completed_at ? parseUTC(scan.completed_at).getTime() : Date.now();
  const seconds = Math.round((end - start) / 1000);
  if (seconds < 60) return `${seconds}s`;
  return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
}

function ScansContent() {
  const [scans, setScans] = useState<any[]>([]);
  const [targets, setTargets] = useState<any[]>([]);
  const [statusFilter, setStatusFilter] = useState("all");

  const load = useCallback(async () => {
    try {
      const [s, t] = await Promise.all([getScans(), getTargets()]);
      setScans(s);
      setTargets(t);
    } catch {}
  }, []);

  useEffect(() => {
    load();
    const interval = setInterval(load, 3000);
    return () => clearInterval(interval);
  }, [load]);

  async function handleStop(id: string) {
    try {
      await stopScan(id);
      load();
    } catch {}
  }

  async function handleDelete(id: string) {
    if (!confirm("Delete this scan and its logs?")) return;
    try {
      await deleteScan(id);
      load();
    } catch {}
  }

  const getTarget = (id: string) => targets.find((t: any) => t.id === id);

  const filtered = statusFilter === "all"
    ? scans
    : scans.filter((s: any) => s.status === statusFilter);

  const runningCount = scans.filter((s: any) => s.status === "running").length;
  const completedCount = scans.filter((s: any) => s.status === "completed").length;

  return (
    <div>
      <div className="mb-6">
        <h1 className="text-xl font-bold text-white">Scans</h1>
        <p className="text-sm text-gray-500">
          {runningCount} running, {completedCount} completed, {scans.length} total
        </p>
      </div>

      {/* Status Filter */}
      <div className="flex gap-2 mb-4">
        {["all", "running", "completed", "queued", "failed", "stopped"].map((s) => (
          <button
            key={s}
            onClick={() => setStatusFilter(s)}
            className={cn(
              "px-3 py-1.5 rounded-lg text-xs font-medium transition capitalize",
              statusFilter === s ? "bg-red-600 text-white" : "bg-gray-800 text-gray-400 hover:bg-gray-700"
            )}
          >
            {s}
          </button>
        ))}
      </div>

      <div className="space-y-3">
        {filtered.map((scan: any) => {
          const target = getTarget(scan.target_id);
          const isActive = scan.status === "running";
          const scanType = scan.scan_type || "full";

          return (
            <div
              key={scan.id}
              className={cn(
                "bg-gray-900 rounded-xl border p-5 transition",
                isActive ? "border-red-900/40" : "border-gray-800"
              )}
            >
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-3">
                  <Link href={`/scans/${scan.id}`} className="text-white font-medium hover:text-red-400 transition">
                    {target?.domain || "Unknown"}
                  </Link>
                  <span className={cn("text-[10px] px-2 py-0.5 rounded border font-medium uppercase",
                    TYPE_COLORS[scanType] || TYPE_COLORS.full
                  )}>
                    {scanType}
                  </span>
                  <span className={cn("text-xs capitalize font-medium", statusColor(scan.status))}>
                    {scan.status}
                  </span>
                </div>
                <div className="flex items-center gap-3">
                  <span className="text-xs text-gray-600 font-mono">{formatDuration(scan)}</span>
                  {isActive && (
                    <button
                      onClick={() => handleStop(scan.id)}
                      className="text-red-400 hover:text-red-300 transition p-1"
                      title="Stop Scan"
                    >
                      <StopCircle className="w-4 h-4" />
                    </button>
                  )}
                  {!isActive && (
                    <button
                      onClick={(e) => { e.stopPropagation(); handleDelete(scan.id); }}
                      className="text-gray-700 hover:text-red-400 transition p-1"
                      title="Delete Scan"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  )}
                  <Link href={`/scans/${scan.id}`} className="text-gray-600 hover:text-gray-400">
                    <ExternalLink className="w-4 h-4" />
                  </Link>
                </div>
              </div>

              <ScanProgress
                currentPhase={scan.current_phase || "recon"}
                progress={scan.progress_percent}
                status={scan.status}
              />

              <div className="flex gap-6 mt-3 text-xs text-gray-500">
                <span>Subdomains: <span className="text-gray-300">{scan.subdomains_found}</span></span>
                <span>Endpoints: <span className="text-gray-300">{scan.endpoints_found}</span></span>
                <span>Vulns: <span className={scan.vulns_found > 0 ? "text-red-400 font-medium" : "text-gray-300"}>{scan.vulns_found}</span></span>
                <span className="ml-auto">{timeAgo(scan.created_at)}</span>
              </div>
            </div>
          );
        })}

        {filtered.length === 0 && (
          <div className="text-center py-20 text-gray-600">
            {scans.length === 0
              ? "No scans yet. Go to the dashboard or targets page to start one."
              : "No scans match this filter."}
          </div>
        )}
      </div>
    </div>
  );
}
