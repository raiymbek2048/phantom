"use client";

import { useState, useEffect, useCallback, useRef } from "react";
import { useAuthStore } from "@/lib/store";
import LoginForm from "@/components/LoginForm";
import Sidebar from "@/components/Sidebar";
import { getAuditLogs, getAuditActions } from "@/lib/api";
import {
  ScrollText,
  RefreshCw,
  ChevronDown,
  Filter,
  Clock,
  User,
  Globe,
  Search,
  Loader2,
} from "lucide-react";

interface AuditLog {
  id: string;
  username: string;
  action: string;
  resource_type: string;
  resource_id: string;
  details: string | Record<string, unknown> | null;
  ip_address: string;
  created_at: string;
}

interface AuditResponse {
  total: number;
  offset: number;
  limit: number;
  logs: AuditLog[];
}

const ACTION_COLORS: Record<string, string> = {
  create: "bg-green-500/20 text-green-400 border-green-500/30",
  delete: "bg-red-500/20 text-red-400 border-red-500/30",
  update: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
};

function getActionColor(action: string): string {
  const lower = action.toLowerCase();
  for (const key of Object.keys(ACTION_COLORS)) {
    if (lower.includes(key)) return ACTION_COLORS[key];
  }
  return "bg-blue-500/20 text-blue-400 border-blue-500/30";
}

function formatTimestamp(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleString("en-US", {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
}

function formatDetails(details: string | Record<string, unknown> | null): string {
  if (!details) return "-";
  if (typeof details === "string") return details;
  try {
    return JSON.stringify(details, null, 0);
  } catch {
    return String(details);
  }
}

export default function AuditPage() {
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
        <AuditLogView />
      </main>
    </div>
  );
}

function AuditLogView() {
  const PAGE_SIZE = 25;

  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(false);
  const [initialLoad, setInitialLoad] = useState(true);

  const [actions, setActions] = useState<string[]>([]);
  const [filterAction, setFilterAction] = useState("");
  const [filterResource, setFilterResource] = useState("");
  const [filterUser, setFilterUser] = useState("");

  const [autoRefresh, setAutoRefresh] = useState(false);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Derive unique resource types from loaded logs for the dropdown
  const resourceTypes = Array.from(new Set(logs.map((l) => l.resource_type).filter(Boolean)));

  const fetchActions = useCallback(async () => {
    try {
      const data = await getAuditActions();
      setActions(Array.isArray(data) ? data : []);
    } catch {
      // Silently handle errors
    }
  }, []);

  const fetchLogs = useCallback(
    async (newOffset = 0, append = false) => {
      setLoading(true);
      try {
        const params: Record<string, string | number> = {
          offset: newOffset,
          limit: PAGE_SIZE,
        };
        if (filterAction) params.action = filterAction;
        if (filterResource) params.resource_type = filterResource;
        if (filterUser) params.username = filterUser;

        const data: AuditResponse = await getAuditLogs(params);
        if (append) {
          setLogs((prev) => [...prev, ...data.logs]);
        } else {
          setLogs(data.logs);
        }
        setTotal(data.total);
        setOffset(newOffset);
      } catch {
        // Silently handle errors
      } finally {
        setLoading(false);
        setInitialLoad(false);
      }
    },
    [filterAction, filterResource, filterUser]
  );

  useEffect(() => {
    fetchActions();
  }, [fetchActions]);

  useEffect(() => {
    setOffset(0);
    fetchLogs(0);
  }, [fetchLogs]);

  // Auto-refresh
  useEffect(() => {
    if (autoRefresh) {
      intervalRef.current = setInterval(() => {
        fetchLogs(0);
      }, 10000);
    } else {
      if (intervalRef.current) clearInterval(intervalRef.current);
    }
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, [autoRefresh, fetchLogs]);

  const handleLoadMore = () => {
    const next = offset + PAGE_SIZE;
    fetchLogs(next, true);
  };

  const hasMore = logs.length < total;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white flex items-center gap-2">
            <ScrollText className="w-5 h-5 text-red-500" />
            Audit Log
          </h1>
          <p className="text-sm text-gray-500">
            {total} total entries
          </p>
        </div>
        <div className="flex items-center gap-3">
          {/* Auto-refresh toggle */}
          <button
            onClick={() => setAutoRefresh(!autoRefresh)}
            className={`flex items-center gap-2 px-3 py-1.5 rounded text-sm border transition ${
              autoRefresh
                ? "bg-red-500/20 border-red-500/50 text-red-400"
                : "bg-gray-800 border-gray-700 text-gray-400 hover:text-white"
            }`}
          >
            <RefreshCw className={`w-3.5 h-3.5 ${autoRefresh ? "animate-spin" : ""}`} />
            Auto-refresh {autoRefresh ? "ON" : "OFF"}
          </button>
          {/* Manual refresh */}
          <button
            onClick={() => fetchLogs(0)}
            disabled={loading}
            className="flex items-center gap-2 px-3 py-1.5 rounded text-sm bg-gray-800 border border-gray-700 text-gray-400 hover:text-white transition disabled:opacity-50"
          >
            {loading ? (
              <Loader2 className="w-3.5 h-3.5 animate-spin" />
            ) : (
              <RefreshCw className="w-3.5 h-3.5" />
            )}
            Refresh
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3 bg-gray-900/50 border border-gray-800 rounded-lg p-4">
        <Filter className="w-4 h-4 text-gray-500" />

        {/* Action filter */}
        <div className="relative">
          <select
            value={filterAction}
            onChange={(e) => setFilterAction(e.target.value)}
            className="appearance-none bg-gray-800 border border-gray-700 text-sm text-gray-300 rounded px-3 py-1.5 pr-8 focus:outline-none focus:border-red-500 transition"
          >
            <option value="">All Actions</option>
            {actions.map((a) => (
              <option key={a} value={a}>
                {a}
              </option>
            ))}
          </select>
          <ChevronDown className="w-3.5 h-3.5 text-gray-500 absolute right-2 top-1/2 -translate-y-1/2 pointer-events-none" />
        </div>

        {/* Resource type filter */}
        <div className="relative">
          <select
            value={filterResource}
            onChange={(e) => setFilterResource(e.target.value)}
            className="appearance-none bg-gray-800 border border-gray-700 text-sm text-gray-300 rounded px-3 py-1.5 pr-8 focus:outline-none focus:border-red-500 transition"
          >
            <option value="">All Resources</option>
            {resourceTypes.map((r) => (
              <option key={r} value={r}>
                {r}
              </option>
            ))}
          </select>
          <ChevronDown className="w-3.5 h-3.5 text-gray-500 absolute right-2 top-1/2 -translate-y-1/2 pointer-events-none" />
        </div>

        {/* User filter */}
        <div className="relative">
          <Search className="w-3.5 h-3.5 text-gray-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Filter by user..."
            value={filterUser}
            onChange={(e) => setFilterUser(e.target.value)}
            className="bg-gray-800 border border-gray-700 text-sm text-gray-300 rounded pl-8 pr-3 py-1.5 focus:outline-none focus:border-red-500 transition w-44"
          />
        </div>

        {(filterAction || filterResource || filterUser) && (
          <button
            onClick={() => {
              setFilterAction("");
              setFilterResource("");
              setFilterUser("");
            }}
            className="text-xs text-gray-500 hover:text-red-400 transition"
          >
            Clear filters
          </button>
        )}
      </div>

      {/* Table */}
      <div className="bg-gray-900/50 border border-gray-800 rounded-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800 text-gray-500 text-left">
                <th className="px-4 py-3 font-medium">
                  <span className="flex items-center gap-1.5">
                    <Clock className="w-3.5 h-3.5" />
                    Time
                  </span>
                </th>
                <th className="px-4 py-3 font-medium">
                  <span className="flex items-center gap-1.5">
                    <User className="w-3.5 h-3.5" />
                    User
                  </span>
                </th>
                <th className="px-4 py-3 font-medium">Action</th>
                <th className="px-4 py-3 font-medium">Resource Type</th>
                <th className="px-4 py-3 font-medium">Resource ID</th>
                <th className="px-4 py-3 font-medium">
                  <span className="flex items-center gap-1.5">
                    <Globe className="w-3.5 h-3.5" />
                    IP Address
                  </span>
                </th>
                <th className="px-4 py-3 font-medium">Details</th>
              </tr>
            </thead>
            <tbody>
              {initialLoad && loading ? (
                <tr>
                  <td colSpan={7} className="px-4 py-12 text-center text-gray-500">
                    <Loader2 className="w-5 h-5 animate-spin mx-auto mb-2" />
                    Loading audit logs...
                  </td>
                </tr>
              ) : logs.length === 0 ? (
                <tr>
                  <td colSpan={7} className="px-4 py-12 text-center text-gray-500">
                    <ScrollText className="w-5 h-5 mx-auto mb-2 opacity-50" />
                    No audit log entries found
                  </td>
                </tr>
              ) : (
                logs.map((log) => (
                  <tr
                    key={log.id}
                    className="border-b border-gray-800/50 hover:bg-gray-800/30 transition"
                  >
                    <td className="px-4 py-2.5 text-gray-400 whitespace-nowrap font-mono text-xs">
                      {formatTimestamp(log.created_at)}
                    </td>
                    <td className="px-4 py-2.5 text-white font-medium">
                      {log.username || "-"}
                    </td>
                    <td className="px-4 py-2.5">
                      <span
                        className={`inline-block px-2 py-0.5 rounded border text-xs font-medium ${getActionColor(
                          log.action
                        )}`}
                      >
                        {log.action}
                      </span>
                    </td>
                    <td className="px-4 py-2.5 text-gray-300">
                      {log.resource_type || "-"}
                    </td>
                    <td className="px-4 py-2.5 text-gray-400 font-mono text-xs">
                      {log.resource_id
                        ? log.resource_id.length > 12
                          ? log.resource_id.slice(0, 12) + "..."
                          : log.resource_id
                        : "-"}
                    </td>
                    <td className="px-4 py-2.5 text-gray-400 font-mono text-xs">
                      {log.ip_address || "-"}
                    </td>
                    <td className="px-4 py-2.5 text-gray-500 text-xs max-w-xs truncate">
                      {formatDetails(log.details)}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Load More */}
        {hasMore && !initialLoad && (
          <div className="border-t border-gray-800 px-4 py-3 flex items-center justify-between">
            <span className="text-xs text-gray-500">
              Showing {logs.length} of {total} entries
            </span>
            <button
              onClick={handleLoadMore}
              disabled={loading}
              className="flex items-center gap-2 px-4 py-1.5 rounded text-sm bg-gray-800 border border-gray-700 text-gray-300 hover:text-white hover:border-red-500/50 transition disabled:opacity-50"
            >
              {loading ? (
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
              ) : (
                <ChevronDown className="w-3.5 h-3.5" />
              )}
              Load More
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
