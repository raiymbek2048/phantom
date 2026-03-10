"use client";

import { useState, useEffect, useRef } from "react";
import { getDashboardStats } from "@/lib/api";
import { cn } from "@/lib/utils";
import { Activity, Zap, ArrowRight } from "lucide-react";
import Link from "next/link";

interface ActiveScan {
  id: string;
  target_domain: string;
  current_phase: string;
  progress_percent: number;
  vulns_found: number;
}

export default function LiveScanBar() {
  const [scans, setScans] = useState<ActiveScan[]>([]);
  const [visible, setVisible] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);
  const prevVulnCount = useRef(0);
  const [flash, setFlash] = useState(false);

  // Poll for active scans
  useEffect(() => {
    let mounted = true;

    async function check() {
      try {
        const stats = await getDashboardStats();
        if (!mounted) return;
        if (stats.active_scans > 0 && stats.recent_scans) {
          const active = stats.recent_scans
            .filter((s: any) => s.status === "running")
            .map((s: any) => ({
              id: s.id,
              target_domain: s.target_domain || "Unknown",
              current_phase: s.current_phase || "scanning",
              progress_percent: s.progress_percent || 0,
              vulns_found: s.vulns_found || 0,
            }));
          setScans(active);
          setVisible(active.length > 0);

          // Flash on new vuln
          const totalVulns = active.reduce((sum: number, s: ActiveScan) => sum + s.vulns_found, 0);
          if (totalVulns > prevVulnCount.current && prevVulnCount.current > 0) {
            setFlash(true);
            setTimeout(() => setFlash(false), 1500);
          }
          prevVulnCount.current = totalVulns;
        } else {
          setScans([]);
          setVisible(false);
        }
      } catch {}
    }

    check();
    const interval = setInterval(check, 5000);
    return () => { mounted = false; clearInterval(interval); };
  }, []);

  // Also try WebSocket for live updates
  useEffect(() => {
    if (scans.length === 0) return;

    const scanId = scans[0]?.id;
    if (!scanId) return;

    const wsProtocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsHost = window.location.hostname;
    const port = window.location.port;
    const wsPort = !port || port === "80" || port === "443" ? "" : ":8000";
    const wsUrl = `${wsProtocol}//${wsHost}${wsPort}/ws/scans/${scanId}/live`;

    try {
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (data.type === "progress") {
            setScans((prev) =>
              prev.map((s) =>
                s.id === scanId
                  ? {
                      ...s,
                      current_phase: data.phase || s.current_phase,
                      progress_percent: data.progress ?? s.progress_percent,
                      vulns_found: data.vulns_found ?? s.vulns_found,
                    }
                  : s
              )
            );
          }
          if (data.type === "complete") {
            setScans((prev) => prev.filter((s) => s.id !== scanId));
          }
        } catch {}
      };

      ws.onerror = () => ws.close();
      ws.onclose = () => { wsRef.current = null; };

      return () => {
        ws.close();
        wsRef.current = null;
      };
    } catch {
      return;
    }
  }, [scans.length > 0 ? scans[0]?.id : null]);

  if (!visible || scans.length === 0) return null;

  return (
    <div
      className={cn(
        "fixed top-0 left-60 right-0 z-50 transition-all duration-300",
        flash ? "bg-red-900/40" : "bg-gray-950/95 backdrop-blur-sm"
      )}
      style={{ borderBottom: "1px solid rgba(34,197,94,0.2)" }}
    >
      <div className="flex items-center gap-4 px-6 py-2">
        <div className="flex items-center gap-2 text-green-400">
          <Activity className="w-4 h-4 animate-pulse" />
          <span className="text-xs font-medium">{scans.length} active</span>
        </div>

        <div className="flex-1 flex items-center gap-3 overflow-x-auto">
          {scans.slice(0, 3).map((scan) => (
            <Link
              key={scan.id}
              href={`/scans/${scan.id}`}
              className="flex items-center gap-3 bg-gray-900/50 border border-gray-800 rounded-lg px-3 py-1.5 hover:border-green-900/50 transition min-w-0 group"
            >
              <span className="text-xs text-white font-medium truncate max-w-[140px]">
                {scan.target_domain}
              </span>
              <span className="text-[10px] text-gray-500 font-mono whitespace-nowrap">
                {scan.current_phase}
              </span>
              <div className="w-20 h-1.5 bg-gray-800 rounded-full overflow-hidden flex-shrink-0">
                <div
                  className="h-full bg-green-500 rounded-full transition-all duration-500"
                  style={{ width: `${scan.progress_percent}%` }}
                />
              </div>
              <span className="text-[10px] text-gray-400 font-mono">
                {scan.progress_percent}%
              </span>
              {scan.vulns_found > 0 && (
                <span className="flex items-center gap-0.5 text-[10px] text-red-400 font-medium">
                  <Zap className="w-3 h-3" />
                  {scan.vulns_found}
                </span>
              )}
              <ArrowRight className="w-3 h-3 text-gray-700 group-hover:text-green-400 transition flex-shrink-0" />
            </Link>
          ))}
        </div>
      </div>
    </div>
  );
}
