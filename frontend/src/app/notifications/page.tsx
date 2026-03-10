"use client";

import { useState, useEffect, useCallback } from "react";
import Sidebar from "@/components/Sidebar";
import { getNotificationHistory, testNotification } from "@/lib/api";
import {
  Bell,
  BellOff,
  CheckCircle,
  XCircle,
  Webhook,
  Mail,
  Send,
  RefreshCw,
  AlertTriangle,
  Shield,
  Scan,
  Zap,
  Filter,
} from "lucide-react";
import { cn } from "@/lib/utils";

interface NotificationEntry {
  channel: string;
  event_type: string;
  summary: string;
  success: boolean;
  error: string | null;
  timestamp: string;
}

const CHANNEL_ICONS: Record<string, React.ReactNode> = {
  webhook: <Webhook className="w-4 h-4" />,
  email: <Mail className="w-4 h-4" />,
  telegram: <Send className="w-4 h-4" />,
};

const CHANNEL_COLORS: Record<string, string> = {
  webhook: "text-blue-400 bg-blue-500/10 border-blue-500/20",
  email: "text-amber-400 bg-amber-500/10 border-amber-500/20",
  telegram: "text-sky-400 bg-sky-500/10 border-sky-500/20",
};

const EVENT_ICONS: Record<string, React.ReactNode> = {
  critical_vuln: <AlertTriangle className="w-4 h-4 text-red-400" />,
  new_finding: <Shield className="w-4 h-4 text-amber-400" />,
  scan_complete: <Scan className="w-4 h-4 text-green-400" />,
  test: <Zap className="w-4 h-4 text-purple-400" />,
};

const EVENT_LABELS: Record<string, string> = {
  critical_vuln: "Critical Vulnerability",
  new_finding: "New Finding",
  scan_complete: "Scan Complete",
  test: "Test Notification",
};

export default function NotificationsPage() {
  const [history, setHistory] = useState<NotificationEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [sending, setSending] = useState(false);
  const [filterChannel, setFilterChannel] = useState<string>("all");
  const [filterStatus, setFilterStatus] = useState<string>("all");
  const [filterEvent, setFilterEvent] = useState<string>("all");

  const loadHistory = useCallback(async () => {
    try {
      const data = await getNotificationHistory();
      setHistory(Array.isArray(data) ? data : []);
    } catch {
      setHistory([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadHistory();
  }, [loadHistory]);

  const handleTest = async () => {
    setSending(true);
    try {
      await testNotification();
      setTimeout(loadHistory, 1500);
    } catch {}
    setSending(false);
  };

  // Stats
  const totalSent = history.length;
  const totalSuccess = history.filter((n) => n.success).length;
  const totalFailed = history.filter((n) => !n.success).length;
  const channels = [...new Set(history.map((n) => n.channel))];
  const eventTypes = [...new Set(history.map((n) => n.event_type))];

  // Filtered
  const filtered = history.filter((n) => {
    if (filterChannel !== "all" && n.channel !== filterChannel) return false;
    if (filterStatus === "success" && !n.success) return false;
    if (filterStatus === "failed" && n.success) return false;
    if (filterEvent !== "all" && n.event_type !== filterEvent) return false;
    return true;
  });

  const formatTime = (ts: string) => {
    try {
      const d = new Date(ts);
      const now = new Date();
      const diff = now.getTime() - d.getTime();
      if (diff < 60000) return "just now";
      if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
      if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
      return d.toLocaleDateString("en-US", {
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
      });
    } catch {
      return ts;
    }
  };

  return (
    <div className="flex min-h-screen bg-gray-950">
      <Sidebar />
      <main className="flex-1 ml-60 p-8">
        {/* Header */}
        <div className="flex items-center justify-between mb-8">
          <div>
            <h1 className="text-2xl font-bold text-white flex items-center gap-3">
              <Bell className="w-7 h-7 text-amber-400" />
              Notification History
            </h1>
            <p className="text-sm text-gray-500 mt-1">
              All notifications sent via webhook, email, and Telegram
            </p>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={loadHistory}
              className="flex items-center gap-2 px-4 py-2 text-sm bg-gray-900 border border-gray-800 rounded-lg text-gray-400 hover:text-white hover:border-gray-700 transition"
            >
              <RefreshCw className="w-4 h-4" />
              Refresh
            </button>
            <button
              onClick={handleTest}
              disabled={sending}
              className="flex items-center gap-2 px-4 py-2 text-sm bg-amber-600/20 border border-amber-600/30 rounded-lg text-amber-400 hover:bg-amber-600/30 transition disabled:opacity-50"
            >
              <Zap className="w-4 h-4" />
              {sending ? "Sending..." : "Send Test"}
            </button>
          </div>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-4 gap-4 mb-6">
          <div className="bg-gray-900/50 border border-gray-800 rounded-xl p-4">
            <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">Total Sent</p>
            <p className="text-2xl font-bold text-white">{totalSent}</p>
          </div>
          <div className="bg-gray-900/50 border border-gray-800 rounded-xl p-4">
            <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">Delivered</p>
            <p className="text-2xl font-bold text-green-400">{totalSuccess}</p>
          </div>
          <div className="bg-gray-900/50 border border-gray-800 rounded-xl p-4">
            <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">Failed</p>
            <p className="text-2xl font-bold text-red-400">{totalFailed}</p>
          </div>
          <div className="bg-gray-900/50 border border-gray-800 rounded-xl p-4">
            <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">Channels</p>
            <div className="flex items-center gap-2 mt-1">
              {channels.length > 0 ? (
                channels.map((ch) => (
                  <span
                    key={ch}
                    className={cn(
                      "text-xs px-2 py-0.5 rounded-full border",
                      CHANNEL_COLORS[ch] || "text-gray-400 bg-gray-800 border-gray-700"
                    )}
                  >
                    {ch}
                  </span>
                ))
              ) : (
                <span className="text-sm text-gray-600">None</span>
              )}
            </div>
          </div>
        </div>

        {/* Filters */}
        <div className="flex items-center gap-4 mb-4">
          <div className="flex items-center gap-2 text-gray-500">
            <Filter className="w-4 h-4" />
            <span className="text-xs uppercase tracking-wider">Filters</span>
          </div>

          <select
            value={filterChannel}
            onChange={(e) => setFilterChannel(e.target.value)}
            className="text-xs bg-gray-900 border border-gray-800 rounded-lg px-3 py-1.5 text-gray-300"
          >
            <option value="all">All Channels</option>
            {channels.map((ch) => (
              <option key={ch} value={ch}>{ch}</option>
            ))}
          </select>

          <select
            value={filterStatus}
            onChange={(e) => setFilterStatus(e.target.value)}
            className="text-xs bg-gray-900 border border-gray-800 rounded-lg px-3 py-1.5 text-gray-300"
          >
            <option value="all">All Status</option>
            <option value="success">Delivered</option>
            <option value="failed">Failed</option>
          </select>

          <select
            value={filterEvent}
            onChange={(e) => setFilterEvent(e.target.value)}
            className="text-xs bg-gray-900 border border-gray-800 rounded-lg px-3 py-1.5 text-gray-300"
          >
            <option value="all">All Events</option>
            {eventTypes.map((et) => (
              <option key={et} value={et}>{EVENT_LABELS[et] || et}</option>
            ))}
          </select>

          {(filterChannel !== "all" || filterStatus !== "all" || filterEvent !== "all") && (
            <button
              onClick={() => {
                setFilterChannel("all");
                setFilterStatus("all");
                setFilterEvent("all");
              }}
              className="text-xs text-gray-500 hover:text-gray-300 transition"
            >
              Clear filters
            </button>
          )}
        </div>

        {/* History List */}
        {loading ? (
          <div className="text-center py-20 text-gray-600">Loading notifications...</div>
        ) : filtered.length === 0 ? (
          <div className="text-center py-20">
            <BellOff className="w-12 h-12 text-gray-700 mx-auto mb-4" />
            <p className="text-gray-500">
              {history.length === 0
                ? "No notifications sent yet. Configure channels in Settings and run a scan."
                : "No notifications match your filters."}
            </p>
          </div>
        ) : (
          <div className="space-y-2">
            {filtered.map((entry, i) => (
              <div
                key={i}
                className={cn(
                  "flex items-center gap-4 p-4 rounded-xl border transition",
                  entry.success
                    ? "bg-gray-900/30 border-gray-800 hover:border-gray-700"
                    : "bg-red-950/20 border-red-900/30 hover:border-red-800/40"
                )}
              >
                {/* Status */}
                <div className="flex-shrink-0">
                  {entry.success ? (
                    <CheckCircle className="w-5 h-5 text-green-500" />
                  ) : (
                    <XCircle className="w-5 h-5 text-red-500" />
                  )}
                </div>

                {/* Channel badge */}
                <div
                  className={cn(
                    "flex items-center gap-1.5 px-2.5 py-1 rounded-lg border text-xs font-medium flex-shrink-0",
                    CHANNEL_COLORS[entry.channel] || "text-gray-400 bg-gray-800 border-gray-700"
                  )}
                >
                  {CHANNEL_ICONS[entry.channel] || <Bell className="w-3.5 h-3.5" />}
                  {entry.channel}
                </div>

                {/* Event type */}
                <div className="flex items-center gap-1.5 flex-shrink-0">
                  {EVENT_ICONS[entry.event_type] || <Bell className="w-4 h-4 text-gray-500" />}
                  <span className="text-xs text-gray-400">
                    {EVENT_LABELS[entry.event_type] || entry.event_type}
                  </span>
                </div>

                {/* Summary */}
                <div className="flex-1 min-w-0">
                  <p className="text-sm text-gray-300 truncate">{entry.summary}</p>
                  {entry.error && (
                    <p className="text-xs text-red-400 mt-0.5 truncate">
                      Error: {entry.error}
                    </p>
                  )}
                </div>

                {/* Timestamp */}
                <span className="text-xs text-gray-600 flex-shrink-0 whitespace-nowrap">
                  {formatTime(entry.timestamp)}
                </span>
              </div>
            ))}
          </div>
        )}
      </main>
    </div>
  );
}
