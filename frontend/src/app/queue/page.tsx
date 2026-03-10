"use client";

import { useState, useEffect, useCallback } from "react";
import { useAuthStore } from "@/lib/store";
import LoginForm from "@/components/LoginForm";
import Sidebar from "@/components/Sidebar";
import { getScanQueue, updateScanPriority, stopScan } from "@/lib/api";
import { cn } from "@/lib/utils";
import {
  ListOrdered,
  ChevronUp,
  ChevronDown,
  StopCircle,
  Loader2,
  Clock,
  Activity,
  RefreshCw,
  Zap,
  AlertTriangle,
} from "lucide-react";

export default function QueuePage() {
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
      <main className="ml-60 flex-1 min-h-screen p-6 bg-gray-950 text-white">
        <QueueContent />
      </main>
    </div>
  );
}

interface QueueScan {
  id: string;
  target_id: string;
  domain: string;
  status: string;
  scan_type: string;
  priority: number;
  progress_percent: number;
  current_phase: string;
  created_at: string;
  started_at: string | null;
}

interface QueueData {
  total: number;
  running: number;
  queued: number;
  scans: QueueScan[];
}

const TYPE_COLORS: Record<string, string> = {
  full: "bg-purple-950/50 text-purple-400 border-purple-900/50",
  quick: "bg-green-950/50 text-green-400 border-green-900/50",
  stealth: "bg-yellow-950/50 text-yellow-400 border-yellow-900/50",
  recon: "bg-blue-950/50 text-blue-400 border-blue-900/50",
};

function priorityColor(p: number): string {
  if (p <= 3) return "bg-red-500";
  if (p <= 6) return "bg-yellow-500";
  return "bg-green-500";
}

function priorityTextColor(p: number): string {
  if (p <= 3) return "text-red-400";
  if (p <= 6) return "text-yellow-400";
  return "text-green-400";
}

function priorityLabel(p: number): string {
  if (p <= 3) return "High";
  if (p <= 6) return "Medium";
  return "Low";
}

function timeInQueue(createdAt: string): string {
  const created = new Date(createdAt.endsWith("Z") ? createdAt : createdAt + "Z");
  const now = Date.now();
  const seconds = Math.round((now - created.getTime()) / 1000);
  if (seconds < 0) return "just now";
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ${seconds % 60}s`;
  const hours = Math.floor(minutes / 60);
  return `${hours}h ${minutes % 60}m`;
}

function QueueContent() {
  const [data, setData] = useState<QueueData | null>(null);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState<Record<string, boolean>>({});
  const [lastRefresh, setLastRefresh] = useState<Date>(new Date());
  const [manualRefreshing, setManualRefreshing] = useState(false);

  const load = useCallback(async () => {
    try {
      const result = await getScanQueue();
      setData(result);
      setLastRefresh(new Date());
    } catch (e) {
      console.error("Failed to load queue:", e);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
    const interval = setInterval(load, 5000);
    return () => clearInterval(interval);
  }, [load]);

  const handleManualRefresh = async () => {
    setManualRefreshing(true);
    await load();
    setManualRefreshing(false);
  };

  const handleStop = async (scanId: string) => {
    setActionLoading((prev) => ({ ...prev, [scanId]: true }));
    try {
      await stopScan(scanId);
      await load();
    } catch (e) {
      console.error("Failed to stop scan:", e);
    } finally {
      setActionLoading((prev) => ({ ...prev, [scanId]: false }));
    }
  };

  const handlePriorityChange = async (scanId: string, newPriority: number) => {
    if (newPriority < 1 || newPriority > 10) return;
    setActionLoading((prev) => ({ ...prev, [scanId]: true }));
    try {
      await updateScanPriority(scanId, newPriority);
      await load();
    } catch (e) {
      console.error("Failed to update priority:", e);
    } finally {
      setActionLoading((prev) => ({ ...prev, [scanId]: false }));
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-96">
        <Loader2 className="w-8 h-8 animate-spin text-red-500" />
      </div>
    );
  }

  const runningScans = (data?.scans ?? [])
    .filter((s) => s.status === "running")
    .sort((a, b) => a.priority - b.priority);

  const queuedScans = (data?.scans ?? [])
    .filter((s) => s.status === "queued" || s.status === "pending")
    .sort((a, b) => a.priority - b.priority);

  return (
    <div className="max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <ListOrdered className="w-7 h-7 text-red-500" />
          <h1 className="text-2xl font-bold">Scan Queue</h1>
        </div>
        <div className="flex items-center gap-4">
          <span className="text-sm text-gray-500">
            Last updated: {lastRefresh.toLocaleTimeString()}
          </span>
          <button
            onClick={handleManualRefresh}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-gray-800 hover:bg-gray-700 border border-gray-700 text-sm transition-colors"
          >
            <RefreshCw
              className={cn("w-4 h-4", manualRefreshing && "animate-spin")}
            />
            Refresh
          </button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-3 gap-4">
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
          <div className="flex items-center gap-2 text-gray-400 text-sm mb-1">
            <Activity className="w-4 h-4" />
            Total
          </div>
          <div className="text-2xl font-bold">{data?.total ?? 0}</div>
        </div>
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
          <div className="flex items-center gap-2 text-green-400 text-sm mb-1">
            <Zap className="w-4 h-4" />
            Running
          </div>
          <div className="text-2xl font-bold text-green-400">
            {data?.running ?? 0}
          </div>
        </div>
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
          <div className="flex items-center gap-2 text-yellow-400 text-sm mb-1">
            <Clock className="w-4 h-4" />
            Queued
          </div>
          <div className="text-2xl font-bold text-yellow-400">
            {data?.queued ?? 0}
          </div>
        </div>
      </div>

      {/* Running Scans */}
      <section>
        <h2 className="text-lg font-semibold mb-3 flex items-center gap-2">
          <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
          Running Scans
        </h2>
        {runningScans.length === 0 ? (
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-8 text-center text-gray-500">
            No scans currently running
          </div>
        ) : (
          <div className="space-y-3">
            {runningScans.map((scan) => (
              <div
                key={scan.id}
                className="bg-gray-900 border border-gray-800 rounded-xl p-4"
              >
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-3">
                    {/* Priority indicator bar */}
                    <div
                      className={cn(
                        "w-1 h-12 rounded-full",
                        priorityColor(scan.priority)
                      )}
                    />
                    <div>
                      <div className="font-semibold text-lg">{scan.domain}</div>
                      <div className="flex items-center gap-2 mt-0.5">
                        <span
                          className={cn(
                            "px-2 py-0.5 text-xs rounded-full border",
                            TYPE_COLORS[scan.scan_type] ??
                              "bg-gray-800 text-gray-400 border-gray-700"
                          )}
                        >
                          {scan.scan_type}
                        </span>
                        <span
                          className={cn(
                            "text-xs font-medium",
                            priorityTextColor(scan.priority)
                          )}
                        >
                          P{scan.priority} ({priorityLabel(scan.priority)})
                        </span>
                        <span className="text-xs text-gray-500">
                          Phase: {scan.current_phase || "initializing"}
                        </span>
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-sm text-gray-400 mr-2">
                      {timeInQueue(scan.started_at ?? scan.created_at)} elapsed
                    </span>
                    <button
                      onClick={() => handleStop(scan.id)}
                      disabled={!!actionLoading[scan.id]}
                      className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-red-950/50 hover:bg-red-900/50 border border-red-900/50 text-red-400 text-sm transition-colors disabled:opacity-50"
                    >
                      {actionLoading[scan.id] ? (
                        <Loader2 className="w-4 h-4 animate-spin" />
                      ) : (
                        <StopCircle className="w-4 h-4" />
                      )}
                      Stop
                    </button>
                  </div>
                </div>
                {/* Progress bar */}
                <div className="w-full bg-gray-800 rounded-full h-2.5 overflow-hidden">
                  <div
                    className="h-full rounded-full bg-gradient-to-r from-red-600 to-red-400 transition-all duration-500"
                    style={{ width: `${scan.progress_percent ?? 0}%` }}
                  />
                </div>
                <div className="text-xs text-gray-500 mt-1 text-right">
                  {scan.progress_percent ?? 0}%
                </div>
              </div>
            ))}
          </div>
        )}
      </section>

      {/* Queued Scans */}
      <section>
        <h2 className="text-lg font-semibold mb-3 flex items-center gap-2">
          <Clock className="w-5 h-5 text-yellow-500" />
          Queued Scans
        </h2>
        {queuedScans.length === 0 ? (
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-8 text-center text-gray-500">
            No scans in queue
          </div>
        ) : (
          <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
            <table className="w-full">
              <thead>
                <tr className="border-b border-gray-800 text-gray-400 text-sm">
                  <th className="text-left py-3 px-4 font-medium">Priority</th>
                  <th className="text-left py-3 px-4 font-medium">Domain</th>
                  <th className="text-left py-3 px-4 font-medium">Type</th>
                  <th className="text-left py-3 px-4 font-medium">Status</th>
                  <th className="text-left py-3 px-4 font-medium">
                    Time in Queue
                  </th>
                  <th className="text-right py-3 px-4 font-medium">Actions</th>
                </tr>
              </thead>
              <tbody>
                {queuedScans.map((scan, idx) => (
                  <tr
                    key={scan.id}
                    className="border-b border-gray-800/50 hover:bg-gray-800/30 transition-colors"
                  >
                    {/* Priority */}
                    <td className="py-3 px-4">
                      <div className="flex items-center gap-2">
                        <div
                          className={cn(
                            "w-1.5 h-8 rounded-full",
                            priorityColor(scan.priority)
                          )}
                        />
                        <select
                          value={scan.priority}
                          onChange={(e) =>
                            handlePriorityChange(
                              scan.id,
                              parseInt(e.target.value)
                            )
                          }
                          disabled={!!actionLoading[scan.id]}
                          className={cn(
                            "bg-gray-800 border border-gray-700 rounded-lg px-2 py-1 text-sm font-mono focus:outline-none focus:ring-1 focus:ring-red-500 disabled:opacity-50",
                            priorityTextColor(scan.priority)
                          )}
                        >
                          {[1, 2, 3, 4, 5, 6, 7, 8, 9, 10].map((p) => (
                            <option key={p} value={p} className="text-white">
                              P{p}
                            </option>
                          ))}
                        </select>
                      </div>
                    </td>
                    {/* Domain */}
                    <td className="py-3 px-4">
                      <span className="font-medium">{scan.domain}</span>
                    </td>
                    {/* Type */}
                    <td className="py-3 px-4">
                      <span
                        className={cn(
                          "px-2 py-0.5 text-xs rounded-full border",
                          TYPE_COLORS[scan.scan_type] ??
                            "bg-gray-800 text-gray-400 border-gray-700"
                        )}
                      >
                        {scan.scan_type}
                      </span>
                    </td>
                    {/* Status */}
                    <td className="py-3 px-4">
                      <span className="flex items-center gap-1.5 text-sm text-yellow-400">
                        <Clock className="w-3.5 h-3.5" />
                        {scan.status}
                      </span>
                    </td>
                    {/* Time in Queue */}
                    <td className="py-3 px-4 text-sm text-gray-400">
                      {timeInQueue(scan.created_at)}
                    </td>
                    {/* Actions */}
                    <td className="py-3 px-4">
                      <div className="flex items-center justify-end gap-1">
                        <button
                          onClick={() =>
                            handlePriorityChange(scan.id, scan.priority - 1)
                          }
                          disabled={
                            scan.priority <= 1 || !!actionLoading[scan.id]
                          }
                          title="Increase priority"
                          className="p-1.5 rounded-lg hover:bg-gray-700 text-gray-400 hover:text-white transition-colors disabled:opacity-30 disabled:hover:bg-transparent disabled:hover:text-gray-400"
                        >
                          <ChevronUp className="w-4 h-4" />
                        </button>
                        <button
                          onClick={() =>
                            handlePriorityChange(scan.id, scan.priority + 1)
                          }
                          disabled={
                            scan.priority >= 10 || !!actionLoading[scan.id]
                          }
                          title="Decrease priority"
                          className="p-1.5 rounded-lg hover:bg-gray-700 text-gray-400 hover:text-white transition-colors disabled:opacity-30 disabled:hover:bg-transparent disabled:hover:text-gray-400"
                        >
                          <ChevronDown className="w-4 h-4" />
                        </button>
                        <button
                          onClick={() => handleStop(scan.id)}
                          disabled={!!actionLoading[scan.id]}
                          title="Remove from queue"
                          className="p-1.5 rounded-lg hover:bg-red-950/50 text-gray-400 hover:text-red-400 transition-colors disabled:opacity-50 ml-1"
                        >
                          {actionLoading[scan.id] ? (
                            <Loader2 className="w-4 h-4 animate-spin" />
                          ) : (
                            <StopCircle className="w-4 h-4" />
                          )}
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* Empty state */}
      {(data?.total ?? 0) === 0 && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-12 text-center">
          <AlertTriangle className="w-12 h-12 text-gray-600 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-gray-400 mb-1">
            Queue is empty
          </h3>
          <p className="text-sm text-gray-500">
            Start a scan from the Targets page to see it here.
          </p>
        </div>
      )}

      {/* Auto-refresh indicator */}
      <div className="flex items-center justify-center gap-2 text-xs text-gray-600 pb-4">
        <div className="w-1.5 h-1.5 rounded-full bg-green-600 animate-pulse" />
        Auto-refreshing every 5 seconds
      </div>
    </div>
  );
}
