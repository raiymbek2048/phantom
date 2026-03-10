"use client";

import { useState, useEffect, useCallback } from "react";
import { useAuthStore } from "@/lib/store";
import LoginForm from "@/components/LoginForm";
import Sidebar from "@/components/Sidebar";
import { useT, useI18nStore, Locale } from "@/lib/i18n";
import {
  getMe,
  getHealth,
  getUsers,
  updateUserRole,
  generateApiToken,
  revokeApiToken,
  getClaudeKeyStatus,
  setClaudeKey,
  deleteClaudeKey,
  exportVulnerabilities,
  resetKnowledge,
  getNotificationSettings,
  updateNotificationSettings,
  testNotification,
} from "@/lib/api";
import {
  Settings,
  User,
  Key,
  Shield,
  Server,
  Database,
  Users,
  Eye,
  EyeOff,
  Trash2,
  Download,
  AlertTriangle,
  CheckCircle,
  Copy,
  RefreshCw,
  Bell,
  Send,
} from "lucide-react";

export default function SettingsPage() {
  const { isLoggedIn, init } = useAuthStore();
  const [loaded, setLoaded] = useState(false);
  const t = useT();
  const { locale, setLocale } = useI18nStore();

  useEffect(() => {
    init();
    setLoaded(true);
  }, [init]);

  if (!loaded) return null;
  if (!isLoggedIn) return <LoginForm />;

  return (
    <div className="flex min-h-screen bg-gray-950 text-gray-100">
      <Sidebar />
      <main className="flex-1 ml-60 p-8">
        <div className="max-w-4xl mx-auto space-y-8">
          <div className="flex items-center gap-3 mb-2">
            <Settings className="w-7 h-7 text-red-400" />
            <div>
              <h1 className="text-2xl font-bold">{t("settings.title")}</h1>
              <p className="text-sm text-gray-500">{t("settings.subtitle")}</p>
            </div>
          </div>

          {/* Language */}
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
            <h2 className="text-lg font-semibold text-white mb-4">{t("settings.language")}</h2>
            <div className="flex gap-3">
              <button
                onClick={() => setLocale("en")}
                className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                  locale === "en"
                    ? "bg-red-600 text-white"
                    : "bg-gray-800 text-gray-400 hover:bg-gray-700"
                }`}
              >
                🇬🇧 {t("settings.english")}
              </button>
              <button
                onClick={() => setLocale("ru")}
                className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                  locale === "ru"
                    ? "bg-red-600 text-white"
                    : "bg-gray-800 text-gray-400 hover:bg-gray-700"
                }`}
              >
                🇷🇺 {t("settings.russian")}
              </button>
            </div>
          </div>

          <ProfileSection />
          <NotificationSection />
          <ClaudeKeySection />
          <ApiTokenSection />
          <SystemInfoSection />
          <DataManagementSection />
          <UserManagementSection />
        </div>
      </main>
    </div>
  );
}

/* ── Profile ── */
function ProfileSection() {
  const t = useT();
  const [user, setUser] = useState<any>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    getMe()
      .then(setUser)
      .catch(() => setError(t("settings.failed_load_profile")));
  }, []);

  const roleBadge = (role: string) => {
    const colors: Record<string, string> = {
      ADMIN: "bg-red-600/20 text-red-400 border-red-600/30",
      OPERATOR: "bg-blue-600/20 text-blue-400 border-blue-600/30",
      VIEWER: "bg-gray-600/20 text-gray-400 border-gray-600/30",
    };
    return colors[role] || colors.VIEWER;
  };

  return (
    <section className="bg-gray-900 border border-gray-800 rounded-xl p-6">
      <div className="flex items-center gap-2 mb-4">
        <User className="w-5 h-5 text-gray-400" />
        <h2 className="text-lg font-semibold">{t("settings.profile")}</h2>
      </div>
      {error && <p className="text-red-400 text-sm">{error}</p>}
      {user ? (
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          <div>
            <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">{t("settings.username")}</p>
            <p className="text-sm font-medium">{user.username}</p>
          </div>
          <div>
            <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">{t("settings.email")}</p>
            <p className="text-sm font-medium">{user.email || t("settings.not_set")}</p>
          </div>
          <div>
            <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">{t("settings.role")}</p>
            <span
              className={`inline-block px-2 py-0.5 text-xs font-medium rounded border ${roleBadge(user.role)}`}
            >
              {user.role}
            </span>
          </div>
        </div>
      ) : !error ? (
        <p className="text-sm text-gray-500">{t("common.loading")}</p>
      ) : null}
    </section>
  );
}

/* ── Claude API Key ── */
function ClaudeKeySection() {
  const t = useT();
  const [status, setStatus] = useState<any>(null);
  const [newKey, setNewKey] = useState("");
  const [showKey, setShowKey] = useState(false);
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useState("");

  const loadStatus = useCallback(() => {
    getClaudeKeyStatus()
      .then(setStatus)
      .catch(() => setStatus(null));
  }, []);

  useEffect(() => {
    loadStatus();
  }, [loadStatus]);

  const handleSet = async () => {
    if (!newKey.trim()) return;
    setSaving(true);
    setMsg("");
    try {
      await setClaudeKey(newKey.trim());
      setMsg(t("settings.key_saved"));
      setNewKey("");
      loadStatus();
    } catch {
      setMsg(t("settings.key_save_failed"));
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async () => {
    if (!confirm(t("settings.remove_claude_key"))) return;
    try {
      await deleteClaudeKey();
      setMsg(t("settings.key_removed"));
      loadStatus();
    } catch {
      setMsg(t("settings.key_remove_failed"));
    }
  };

  const sourceBadge = (source: string) => {
    const colors: Record<string, string> = {
      redis: "bg-green-600/20 text-green-400 border-green-600/30",
      max_subscription: "bg-purple-600/20 text-purple-400 border-purple-600/30",
      env: "bg-yellow-600/20 text-yellow-400 border-yellow-600/30",
    };
    return colors[source] || "bg-gray-600/20 text-gray-400 border-gray-600/30";
  };

  return (
    <section className="bg-gray-900 border border-gray-800 rounded-xl p-6">
      <div className="flex items-center gap-2 mb-4">
        <Key className="w-5 h-5 text-gray-400" />
        <h2 className="text-lg font-semibold">{t("settings.claude_api_key")}</h2>
      </div>

      {status && (
        <div className="flex items-center gap-3 mb-4">
          <span className="text-sm text-gray-400">{t("settings.status")}:</span>
          {status.configured ? (
            <span className="flex items-center gap-1.5 text-green-400 text-sm">
              <CheckCircle className="w-4 h-4" /> {t("settings.configured")}
            </span>
          ) : (
            <span className="flex items-center gap-1.5 text-yellow-400 text-sm">
              <AlertTriangle className="w-4 h-4" /> {t("settings.not_configured")}
            </span>
          )}
          {status.source && (
            <span
              className={`px-2 py-0.5 text-xs font-medium rounded border ${sourceBadge(status.source)}`}
            >
              {status.source}
            </span>
          )}
        </div>
      )}

      <div className="flex gap-2">
        <div className="relative flex-1">
          <input
            type={showKey ? "text" : "password"}
            value={newKey}
            onChange={(e) => setNewKey(e.target.value)}
            placeholder="sk-ant-..."
            className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-red-500 pr-10"
          />
          <button
            type="button"
            onClick={() => setShowKey(!showKey)}
            className="absolute right-2 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300"
          >
            {showKey ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
          </button>
        </div>
        <button
          onClick={handleSet}
          disabled={saving || !newKey.trim()}
          className="px-4 py-2 bg-red-600 hover:bg-red-700 disabled:opacity-50 rounded-lg text-sm font-medium transition-colors"
        >
          {saving ? t("settings.saving") : t("settings.save")}
        </button>
        {status?.configured && (
          <button
            onClick={handleDelete}
            className="px-3 py-2 bg-gray-800 hover:bg-gray-700 border border-gray-700 rounded-lg text-sm transition-colors"
          >
            <Trash2 className="w-4 h-4 text-red-400" />
          </button>
        )}
      </div>

      {msg && <p className="text-sm mt-2 text-gray-400">{msg}</p>}
    </section>
  );
}

/* ── API Token ── */
function ApiTokenSection() {
  const t = useT();
  const [token, setToken] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [msg, setMsg] = useState("");

  const handleGenerate = async () => {
    setGenerating(true);
    setMsg("");
    try {
      const data = await generateApiToken();
      setToken(data.token || data.access_token);
    } catch {
      setMsg(t("settings.token_failed"));
    } finally {
      setGenerating(false);
    }
  };

  const handleRevoke = async () => {
    if (!confirm(t("settings.revoke_confirm"))) return;
    try {
      await revokeApiToken();
      setToken(null);
      setMsg(t("settings.token_revoked"));
    } catch {
      setMsg(t("settings.revoke_failed"));
    }
  };

  const copyToken = () => {
    if (token) {
      navigator.clipboard.writeText(token);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <section className="bg-gray-900 border border-gray-800 rounded-xl p-6">
      <div className="flex items-center gap-2 mb-4">
        <Shield className="w-5 h-5 text-gray-400" />
        <h2 className="text-lg font-semibold">{t("settings.api_token")}</h2>
      </div>
      <p className="text-sm text-gray-500 mb-4">
        {t("settings.api_token_desc")}
      </p>

      {token && (
        <div className="mb-4 p-3 bg-gray-800 border border-gray-700 rounded-lg">
          <div className="flex items-center gap-2">
            <code className="flex-1 text-xs text-green-400 break-all font-mono">{token}</code>
            <button
              onClick={copyToken}
              className="p-1.5 hover:bg-gray-700 rounded transition-colors"
              title="Copy"
            >
              <Copy className="w-4 h-4 text-gray-400" />
            </button>
          </div>
          <p className="text-xs text-yellow-400 mt-2 flex items-center gap-1">
            <AlertTriangle className="w-3 h-3" />
            {t("settings.save_token_warning")}
          </p>
        </div>
      )}

      <div className="flex gap-2">
        <button
          onClick={handleGenerate}
          disabled={generating}
          className="px-4 py-2 bg-red-600 hover:bg-red-700 disabled:opacity-50 rounded-lg text-sm font-medium transition-colors"
        >
          {generating ? t("settings.generating") : t("settings.generate_token")}
        </button>
        <button
          onClick={handleRevoke}
          className="px-4 py-2 bg-gray-800 hover:bg-gray-700 border border-gray-700 rounded-lg text-sm font-medium transition-colors"
        >
          {t("settings.revoke_token")}
        </button>
      </div>

      {msg && <p className="text-sm mt-2 text-gray-400">{msg}</p>}
      {copied && <p className="text-sm mt-2 text-green-400">{t("settings.copied")}</p>}
    </section>
  );
}

/* ── System Info ── */
function SystemInfoSection() {
  const t = useT();
  const [health, setHealth] = useState<any>(null);
  const [loading, setLoading] = useState(false);

  const load = useCallback(() => {
    setLoading(true);
    getHealth()
      .then(setHealth)
      .catch(() => setHealth(null))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const statusDot = (ok: boolean) => (
    <span
      className={`inline-block w-2 h-2 rounded-full ${ok ? "bg-green-500" : "bg-red-500"}`}
    />
  );

  return (
    <section className="bg-gray-900 border border-gray-800 rounded-xl p-6">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Server className="w-5 h-5 text-gray-400" />
          <h2 className="text-lg font-semibold">{t("settings.system_info")}</h2>
        </div>
        <button
          onClick={load}
          disabled={loading}
          className="p-1.5 hover:bg-gray-800 rounded-lg transition-colors"
          title={t("common.refresh")}
        >
          <RefreshCw className={`w-4 h-4 text-gray-500 ${loading ? "animate-spin" : ""}`} />
        </button>
      </div>

      {health ? (
        <div className="grid grid-cols-2 sm:grid-cols-3 gap-4">
          <div className="flex items-center gap-2">
            {statusDot(health.status === "ok" || health.status === "healthy")}
            <div>
              <p className="text-xs text-gray-500 uppercase tracking-wider">{t("settings.backend")}</p>
              <p className="text-sm font-medium capitalize">{health.status || t("common.unknown")}</p>
            </div>
          </div>
          {health.version && (
            <div>
              <p className="text-xs text-gray-500 uppercase tracking-wider">{t("settings.version")}</p>
              <p className="text-sm font-medium">{health.version}</p>
            </div>
          )}
          {health.database !== undefined && (
            <div className="flex items-center gap-2">
              {statusDot(!!health.database)}
              <div>
                <p className="text-xs text-gray-500 uppercase tracking-wider">{t("settings.database")}</p>
                <p className="text-sm font-medium">{health.database ? t("settings.connected") : t("settings.down")}</p>
              </div>
            </div>
          )}
          {health.redis !== undefined && (
            <div className="flex items-center gap-2">
              {statusDot(!!health.redis)}
              <div>
                <p className="text-xs text-gray-500 uppercase tracking-wider">Redis</p>
                <p className="text-sm font-medium">{health.redis ? t("settings.connected") : t("settings.down")}</p>
              </div>
            </div>
          )}
          {health.celery !== undefined && (
            <div className="flex items-center gap-2">
              {statusDot(!!health.celery)}
              <div>
                <p className="text-xs text-gray-500 uppercase tracking-wider">Celery</p>
                <p className="text-sm font-medium">{health.celery ? t("settings.active") : t("settings.down")}</p>
              </div>
            </div>
          )}
          {health.ollama !== undefined && (
            <div className="flex items-center gap-2">
              {statusDot(!!health.ollama)}
              <div>
                <p className="text-xs text-gray-500 uppercase tracking-wider">Ollama</p>
                <p className="text-sm font-medium">{health.ollama ? t("settings.available") : t("settings.unavailable")}</p>
              </div>
            </div>
          )}
        </div>
      ) : (
        <p className="text-sm text-gray-500">{loading ? t("common.loading") : t("settings.failed_load_health")}</p>
      )}
    </section>
  );
}

/* ── Data Management ── */
function DataManagementSection() {
  const t = useT();
  const [exporting, setExporting] = useState<string | null>(null);
  const [resetInput, setResetInput] = useState("");
  const [resetting, setResetting] = useState(false);
  const [msg, setMsg] = useState("");

  const handleExport = async (format: "json" | "csv") => {
    setExporting(format);
    setMsg("");
    try {
      const data = await exportVulnerabilities(format);
      const blob = new Blob(
        [typeof data === "string" ? data : JSON.stringify(data, null, 2)],
        { type: format === "csv" ? "text/csv" : "application/json" }
      );
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `vulnerabilities.${format}`;
      a.click();
      URL.revokeObjectURL(url);
      setMsg(t("settings.exported_as", { format: format.toUpperCase() }));
    } catch {
      setMsg(t("settings.export_failed"));
    } finally {
      setExporting(null);
    }
  };

  const handleReset = async () => {
    if (resetInput !== "RESET") return;
    setResetting(true);
    setMsg("");
    try {
      await resetKnowledge();
      setMsg(t("settings.reset_success"));
      setResetInput("");
    } catch {
      setMsg(t("settings.reset_failed"));
    } finally {
      setResetting(false);
    }
  };

  return (
    <section className="bg-gray-900 border border-gray-800 rounded-xl p-6">
      <div className="flex items-center gap-2 mb-4">
        <Database className="w-5 h-5 text-gray-400" />
        <h2 className="text-lg font-semibold">{t("settings.data_management")}</h2>
      </div>

      <div className="mb-6">
        <h3 className="text-sm font-medium text-gray-300 mb-3">{t("settings.export_vulns")}</h3>
        <div className="flex gap-2">
          <button
            onClick={() => handleExport("json")}
            disabled={!!exporting}
            className="flex items-center gap-2 px-4 py-2 bg-gray-800 hover:bg-gray-700 border border-gray-700 rounded-lg text-sm font-medium transition-colors disabled:opacity-50"
          >
            <Download className="w-4 h-4" />
            {exporting === "json" ? t("settings.exporting") : t("settings.export_json")}
          </button>
          <button
            onClick={() => handleExport("csv")}
            disabled={!!exporting}
            className="flex items-center gap-2 px-4 py-2 bg-gray-800 hover:bg-gray-700 border border-gray-700 rounded-lg text-sm font-medium transition-colors disabled:opacity-50"
          >
            <Download className="w-4 h-4" />
            {exporting === "csv" ? t("settings.exporting") : t("settings.export_csv")}
          </button>
        </div>
      </div>

      {/* Danger Zone */}
      <div className="border border-red-800/50 rounded-lg p-4">
        <h3 className="text-sm font-medium text-red-400 mb-1 flex items-center gap-1.5">
          <AlertTriangle className="w-4 h-4" />
          {t("settings.danger_zone")}
        </h3>
        <p className="text-xs text-gray-500 mb-3">
          {t("settings.reset_knowledge_desc")}
        </p>
        <div className="flex gap-2 items-center">
          <input
            type="text"
            value={resetInput}
            onChange={(e) => setResetInput(e.target.value)}
            placeholder={t("settings.type_reset")}
            className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-red-500 w-52"
          />
          <button
            onClick={handleReset}
            disabled={resetInput !== "RESET" || resetting}
            className="px-4 py-2 bg-red-700 hover:bg-red-600 disabled:opacity-50 disabled:cursor-not-allowed rounded-lg text-sm font-medium transition-colors"
          >
            {resetting ? t("settings.resetting") : t("settings.reset_knowledge")}
          </button>
        </div>
      </div>

      {msg && <p className="text-sm mt-3 text-gray-400">{msg}</p>}
    </section>
  );
}

/* ── User Management (admin only) ── */
function UserManagementSection() {
  const t = useT();
  const [me, setMe] = useState<any>(null);
  const [users, setUsers] = useState<any[]>([]);
  const [error, setError] = useState("");
  const [updating, setUpdating] = useState<string | null>(null);

  useEffect(() => {
    getMe().then(setMe).catch(() => {});
  }, []);

  useEffect(() => {
    if (me?.role === "ADMIN") {
      getUsers()
        .then(setUsers)
        .catch(() => setError(t("settings.failed_load_users")));
    }
  }, [me]);

  if (!me || me.role !== "ADMIN") return null;

  const handleRoleChange = async (userId: string, newRole: string) => {
    setUpdating(userId);
    try {
      await updateUserRole(userId, newRole);
      setUsers((prev) =>
        prev.map((u) => (u.id === userId ? { ...u, role: newRole } : u))
      );
    } catch {
      setError(t("settings.failed_update_role"));
    } finally {
      setUpdating(null);
    }
  };

  const roleBadge = (role: string) => {
    const colors: Record<string, string> = {
      ADMIN: "bg-red-600/20 text-red-400",
      OPERATOR: "bg-blue-600/20 text-blue-400",
      VIEWER: "bg-gray-600/20 text-gray-400",
    };
    return colors[role] || colors.VIEWER;
  };

  return (
    <section className="bg-gray-900 border border-gray-800 rounded-xl p-6">
      <div className="flex items-center gap-2 mb-4">
        <Users className="w-5 h-5 text-gray-400" />
        <h2 className="text-lg font-semibold">{t("settings.user_management")}</h2>
        <span className="ml-auto px-2 py-0.5 text-xs font-medium rounded bg-red-600/20 text-red-400 border border-red-600/30">
          {t("settings.admin_only")}
        </span>
      </div>

      {error && <p className="text-red-400 text-sm mb-3">{error}</p>}

      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-xs text-gray-500 uppercase tracking-wider border-b border-gray-800">
              <th className="pb-2 pr-4">{t("settings.username")}</th>
              <th className="pb-2 pr-4">{t("settings.email")}</th>
              <th className="pb-2 pr-4">{t("settings.current_role")}</th>
              <th className="pb-2">{t("settings.change_role")}</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800/50">
            {users.map((u) => (
              <tr key={u.id} className="hover:bg-gray-800/30">
                <td className="py-3 pr-4 font-medium">{u.username}</td>
                <td className="py-3 pr-4 text-gray-400">{u.email || "-"}</td>
                <td className="py-3 pr-4">
                  <span className={`px-2 py-0.5 text-xs font-medium rounded ${roleBadge(u.role)}`}>
                    {u.role}
                  </span>
                </td>
                <td className="py-3">
                  <select
                    value={u.role}
                    onChange={(e) => handleRoleChange(u.id, e.target.value)}
                    disabled={updating === u.id || u.id === me.id}
                    className="bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs focus:outline-none focus:border-red-500 disabled:opacity-50"
                  >
                    <option value="ADMIN">ADMIN</option>
                    <option value="OPERATOR">OPERATOR</option>
                    <option value="VIEWER">VIEWER</option>
                  </select>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {users.length === 0 && !error && (
        <p className="text-sm text-gray-500 text-center py-4">{t("settings.no_users")}</p>
      )}
    </section>
  );
}

/* ── Notifications ── */
function NotificationSection() {
  const t = useT();
  const [settings, setSettings] = useState<any>(null);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [msg, setMsg] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    getNotificationSettings().then(setSettings).catch(() => setError(t("settings.failed_load")));
  }, []);

  const toggle = (channel: string) => {
    if (!settings) return;
    const channels = settings.enabled_channels || [];
    const updated = channels.includes(channel)
      ? channels.filter((c: string) => c !== channel)
      : [...channels, channel];
    setSettings({ ...settings, enabled_channels: updated });
  };

  const save = async () => {
    setSaving(true);
    setMsg("");
    setError("");
    try {
      await updateNotificationSettings(settings);
      setMsg(t("settings.saved"));
      setTimeout(() => setMsg(""), 2000);
    } catch {
      setError(t("settings.failed_save"));
    } finally {
      setSaving(false);
    }
  };

  const test = async () => {
    setTesting(true);
    setMsg("");
    setError("");
    try {
      const res = await testNotification();
      const ok = res.results?.filter((r: any) => r.success).length || 0;
      const fail = res.results?.filter((r: any) => !r.success).length || 0;
      setMsg(t("settings.test_result", { ok, fail }));
    } catch {
      setError(t("settings.test_failed"));
    } finally {
      setTesting(false);
    }
  };

  if (!settings) return null;

  const channels = [
    { key: "webhook", label: "Webhook" },
    { key: "email", label: "Email (SMTP)" },
    { key: "telegram", label: "Telegram" },
  ];

  return (
    <section className="bg-gray-900 border border-gray-800 rounded-xl p-6">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Bell className="w-5 h-5 text-yellow-400" />
          <h2 className="text-lg font-semibold">{t("settings.notifications")}</h2>
        </div>
        <div className="flex gap-2">
          <button onClick={test} disabled={testing}
            className="flex items-center gap-1 px-3 py-1.5 text-xs bg-gray-800 border border-gray-700 rounded hover:bg-gray-700 disabled:opacity-50">
            <Send className="w-3 h-3" /> {testing ? t("settings.sending") : t("settings.test")}
          </button>
          <button onClick={save} disabled={saving}
            className="px-3 py-1.5 text-xs bg-red-600 rounded hover:bg-red-500 disabled:opacity-50">
            {saving ? t("settings.saving") : t("settings.save")}
          </button>
        </div>
      </div>

      {msg && <p className="text-green-400 text-sm mb-3">{msg}</p>}
      {error && <p className="text-red-400 text-sm mb-3">{error}</p>}

      {/* Channel toggles */}
      <div className="flex gap-3 mb-4">
        {channels.map((ch) => (
          <button key={ch.key} onClick={() => toggle(ch.key)}
            className={`px-3 py-1.5 text-xs rounded border transition ${
              (settings.enabled_channels || []).includes(ch.key)
                ? "bg-red-600/20 border-red-600/50 text-red-400"
                : "bg-gray-800 border-gray-700 text-gray-500"
            }`}>
            {ch.label}
          </button>
        ))}
      </div>

      {/* Event toggles */}
      <div className="grid grid-cols-2 gap-3 mb-4">
        {[
          { key: "notify_critical", label: t("settings.critical_vulns") },
          { key: "notify_high", label: t("settings.high_vulns") },
          { key: "notify_scan_complete", label: t("settings.scan_complete") },
          { key: "notify_new_finding", label: t("settings.every_new_finding") },
        ].map((evt) => (
          <label key={evt.key} className="flex items-center gap-2 text-sm">
            <input type="checkbox" checked={settings[evt.key] ?? false}
              onChange={() => setSettings({ ...settings, [evt.key]: !settings[evt.key] })}
              className="accent-red-600" />
            <span className="text-gray-300">{evt.label}</span>
          </label>
        ))}
      </div>

      {/* Channel configs */}
      <div className="space-y-4">
        {(settings.enabled_channels || []).includes("webhook") && (
          <div>
            <label className="text-xs text-gray-500 mb-1 block">Webhook URL</label>
            <input value={settings.webhook_url || ""} placeholder="https://hooks.slack.com/..."
              onChange={(e) => setSettings({ ...settings, webhook_url: e.target.value })}
              className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm focus:outline-none focus:border-red-500" />
          </div>
        )}

        {(settings.enabled_channels || []).includes("email") && (
          <div className="grid grid-cols-2 gap-3">
            {[
              { key: "smtp_host", label: "SMTP Host", ph: "smtp.gmail.com" },
              { key: "smtp_port", label: "Port", ph: "587" },
              { key: "smtp_user", label: "SMTP User", ph: "user@example.com" },
              { key: "smtp_password", label: "SMTP Password", ph: "••••••••" },
              { key: "email_from", label: "From", ph: "phantom@example.com" },
              { key: "email_to", label: "To", ph: "team@example.com" },
            ].map((f) => (
              <div key={f.key}>
                <label className="text-xs text-gray-500 mb-1 block">{f.label}</label>
                <input value={settings[f.key] ?? ""} placeholder={f.ph}
                  type={f.key === "smtp_password" ? "password" : "text"}
                  onChange={(e) => setSettings({ ...settings, [f.key]: f.key === "smtp_port" ? parseInt(e.target.value) || 587 : e.target.value })}
                  className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm focus:outline-none focus:border-red-500" />
              </div>
            ))}
          </div>
        )}

        {(settings.enabled_channels || []).includes("telegram") && (
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs text-gray-500 mb-1 block">Bot Token</label>
              <input value={settings.telegram_bot_token || ""} placeholder="123456:ABC-DEF..."
                onChange={(e) => setSettings({ ...settings, telegram_bot_token: e.target.value })}
                className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm focus:outline-none focus:border-red-500" />
            </div>
            <div>
              <label className="text-xs text-gray-500 mb-1 block">Chat ID</label>
              <input value={settings.telegram_chat_id || ""} placeholder="-1001234567890"
                onChange={(e) => setSettings({ ...settings, telegram_chat_id: e.target.value })}
                className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm focus:outline-none focus:border-red-500" />
            </div>
          </div>
        )}
      </div>
    </section>
  );
}
