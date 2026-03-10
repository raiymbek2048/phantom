"use client";

import { useState, useEffect, useCallback, useRef } from "react";
import { useAuthStore } from "@/lib/store";
import { useT } from "@/lib/i18n";
import LoginForm from "@/components/LoginForm";
import Sidebar from "@/components/Sidebar";
import {
  startTraining,
  stopTraining,
  getTrainingStatus,
  getSkillsReport,
  getTrainingHistory,
  resetKnowledge,
  injectExpertKnowledge,
  getTrainingModules,
  injectTrainingModule,
  runLiveFeed,
  runAIMutation,
  getPracticeTargets,
  deployPracticeTarget,
  stopPracticeTarget,
  scorePracticeScan,
  getClaudeKeyStatus,
  setClaudeKey,
  deleteClaudeKey,
  getKnowledgeHealth,
  runKnowledgeAging,
  startAdversarialTest,
  getAdversarialStats,
  getAutopilotStatus,
  runAutopilotScan,
  startAutopilot,
  stopAutopilot,
  collectAndAnalyze,
  refreshPrograms,
} from "@/lib/api";
import { cn } from "@/lib/utils";

/** Backend sends UTC datetimes without 'Z' suffix — fix for correct local display */
function utc(iso: string | null | undefined): string {
  if (!iso) return "";
  return iso.endsWith("Z") ? iso : iso + "Z";
}
import {
  Brain,
  Play,
  Square,
  RefreshCw,
  Server,
  Trophy,
  Trash2,
  TrendingUp,
  AlertTriangle,
  CheckCircle,
  Zap,
  BookOpen,
  BarChart3,
  Key,
  Eye,
  EyeOff,
  Shield,
  Swords,
  Activity,
  Database,
  Cpu,
  Target,
  FileText,
  Clock,
  Loader2,
} from "lucide-react";

export default function TrainingPage() {
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
        <CommandCenter />
      </main>
    </div>
  );
}

type TabKey = "autopilot" | "skills" | "intelligence" | "modules" | "range" | "history" | "recommendations";

function CommandCenter() {
  const t = useT();
  const [activeTab, setActiveTab] = useState<TabKey>("autopilot");

  // --- Training state ---
  const [status, setStatus] = useState<any>(null);
  const [skills, setSkills] = useState<any>(null);
  const [history, setHistory] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState(false);
  const [modules, setModules] = useState<any>(null);
  const [moduleLoading, setModuleLoading] = useState<string | null>(null);
  const [moduleResults, setModuleResults] = useState<Record<string, any>>({});
  const [rangeData, setRangeData] = useState<any>(null);
  const [rangeLoading, setRangeLoading] = useState<string | null>(null);
  const [scoreData, setScoreData] = useState<Record<string, any>>({});
  const [claudeKey, setClaudeKeyState] = useState<any>(null);
  const [claudeKeyInput, setClaudeKeyInput] = useState("");
  const [claudeKeyLoading, setClaudeKeyLoading] = useState(false);
  const [showKey, setShowKey] = useState(false);

  // --- Autopilot state ---
  const [apStatus, setApStatus] = useState<any>(null);
  const [apLoading, setApLoading] = useState(true);
  const [taskId, setTaskId] = useState<string | null>(null);
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState<any>(null);
  const [maxScans, setMaxScans] = useState(3);
  const [logs, setLogs] = useState<string[]>([]);
  const [collecting, setCollecting] = useState(false);
  const logsEndRef = useRef<HTMLDivElement>(null);

  const addLog = (msg: string) => {
    setLogs((prev) => [...prev, `[${new Date().toLocaleTimeString()}] ${msg}`]);
  };

  // Training refresh
  const refresh = useCallback(async () => {
    try {
      const [st, sk, hi, ck] = await Promise.all([
        getTrainingStatus(),
        getSkillsReport(),
        getTrainingHistory(10),
        getClaudeKeyStatus().catch(() => null),
      ]);
      setStatus(st);
      setSkills(sk);
      setHistory(hi);
      if (ck) setClaudeKeyState(ck);
    } catch (e) {
      console.error("Failed to load training data:", e);
    } finally {
      setLoading(false);
    }
  }, []);

  const refreshRange = useCallback(async () => {
    try {
      const data = await getPracticeTargets();
      setRangeData(data);
    } catch (e) {
      console.error("Failed to load range data:", e);
    }
  }, []);

  // Autopilot refresh
  const loadApStatus = async () => {
    setApLoading(true);
    try {
      const data = await getAutopilotStatus();
      setApStatus(data);
    } catch (e: any) {
      addLog(`Status error: ${e.message}`);
    } finally {
      setApLoading(false);
    }
  };

  useEffect(() => {
    refresh();
    loadApStatus();
    const interval = setInterval(refresh, 15000);
    return () => clearInterval(interval);
  }, [refresh]);

  useEffect(() => { logsEndRef.current?.scrollIntoView({ behavior: "smooth" }); }, [logs]);

  useEffect(() => {
    if (!taskId) return;
    const interval = setInterval(loadApStatus, 30000);
    return () => clearInterval(interval);
  }, [taskId]);

  // Training handlers
  const handleStart = async () => {
    setActionLoading(true);
    try { await startTraining(); await refresh(); }
    catch (e: any) { alert(e?.response?.data?.detail || "Failed to start training"); }
    finally { setActionLoading(false); }
  };

  const handleStop = async () => {
    setActionLoading(true);
    try { await stopTraining(); await refresh(); }
    catch (e: any) { alert(e?.response?.data?.detail || "Failed to stop training"); }
    finally { setActionLoading(false); }
  };

  const handleReset = async () => {
    if (!confirm("This will delete ALL learned knowledge. Are you sure?")) return;
    setActionLoading(true);
    try { await resetKnowledge(); await refresh(); }
    catch { alert("Failed to reset"); }
    finally { setActionLoading(false); }
  };

  // Autopilot handlers
  const handleSingleScan = async () => {
    setScanning(true);
    setScanResult(null);
    addLog("Starting single autopilot scan...");
    try {
      const result = await runAutopilotScan();
      setScanResult(result);
      addLog(`Scan complete: ${result.domain || "?"} — ${result.vulns_found || 0} vulns, status: ${result.status}`);
      if (result.drafts_created) addLog(`Created ${result.drafts_created} draft submissions`);
      loadApStatus();
    } catch (e: any) {
      addLog(`Scan error: ${e.response?.data?.detail || e.message}`);
    } finally { setScanning(false); }
  };

  const handleStartAutopilot = async () => {
    addLog(`Starting autopilot (${maxScans} scans)...`);
    try {
      const result = await startAutopilot(maxScans);
      setTaskId(result.task_id);
      addLog(`Autopilot started: task_id=${result.task_id}`);
    } catch (e: any) { addLog(`Start error: ${e.response?.data?.detail || e.message}`); }
  };

  const handleStopAutopilot = async () => {
    if (!taskId) return;
    addLog("Stopping autopilot...");
    try {
      await stopAutopilot(taskId);
      addLog("Stop requested. Autopilot will finish current scan and stop.");
      setTaskId(null);
    } catch (e: any) { addLog(`Stop error: ${e.message}`); }
  };

  const handleCollectData = async () => {
    setCollecting(true);
    addLog("Collecting H1 data and refreshing programs...");
    try {
      const [h1, prog] = await Promise.allSettled([
        collectAndAnalyze(5),
        refreshPrograms(30),
      ]);
      if (h1.status === "fulfilled") addLog(`H1: stored=${h1.value?.collection?.stored || 0}, analyzed=${h1.value?.analysis?.analyzed || 0}`);
      if (prog.status === "fulfilled") addLog(`Programs: collected=${prog.value?.collected || 0}, scored=${prog.value?.scored || 0}`);
      loadApStatus();
    } catch (e: any) { addLog(`Error: ${e.message}`); }
    finally { setCollecting(false); }
  };

  if (loading) {
    return (
      <div className="p-8 flex items-center justify-center h-screen">
        <div className="text-gray-500 animate-pulse">Loading...</div>
      </div>
    );
  }

  const overall = skills?.overall || {};
  const skillsMap = skills?.skills || {};
  const techExpertise = skills?.tech_expertise || {};
  const recommendations = skills?.recommendations || [];

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-3">
            <Brain className="w-7 h-7 text-purple-400" />
            {t("training.title")}
          </h1>
          <p className="text-gray-500 text-sm mt-1">{t("training.subtitle")}</p>
        </div>
        <div className="flex items-center gap-2">
          {/* Training status indicator */}
          {status?.training_active && (
            <span className="flex items-center gap-1.5 text-xs text-purple-400 bg-purple-950/30 border border-purple-900/50 rounded-lg px-3 py-1.5">
              <div className="w-2 h-2 rounded-full bg-purple-400 animate-pulse" />
              Training Active
            </span>
          )}
          <button
            onClick={() => { refresh(); loadApStatus(); }}
            className="p-2 rounded-lg bg-gray-800 text-gray-400 hover:text-white transition"
          >
            <RefreshCw className={cn("w-4 h-4", (loading || apLoading) && "animate-spin")} />
          </button>
        </div>
      </div>

      {/* Top row: Overall Score + Quick Stats + Training/Autopilot Controls */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Overall Score */}
        <div className="bg-gray-900/50 border border-gray-800 rounded-xl p-5 flex flex-col items-center justify-center">
          <div className="relative w-28 h-28">
            <svg viewBox="0 0 120 120" className="w-full h-full -rotate-90">
              <circle cx="60" cy="60" r="50" fill="none" stroke="#1f2937" strokeWidth="10" />
              <circle
                cx="60" cy="60" r="50" fill="none"
                stroke={overall.score >= 70 ? "#a855f7" : overall.score >= 40 ? "#eab308" : "#ef4444"}
                strokeWidth="10"
                strokeDasharray={`${(overall.score || 0) * 3.14} 314`}
                strokeLinecap="round"
              />
            </svg>
            <div className="absolute inset-0 flex flex-col items-center justify-center">
              <span className="text-3xl font-bold text-white">{Math.round(overall.score || 0)}</span>
              <span className="text-xs text-gray-500 uppercase">{overall.level || "untrained"}</span>
            </div>
          </div>
          <p className="text-sm text-gray-400 mt-2">AI Skill Level</p>
          <div className="flex gap-3 mt-3 text-[10px] text-gray-500">
            <span>{overall.total_patterns || 0} patterns</span>
            <span>{overall.total_vulns_found || 0} vulns</span>
          </div>
        </div>

        {/* Training Controls */}
        <div className="bg-gray-900/50 border border-gray-800 rounded-xl p-5">
          <h3 className="text-sm font-medium text-gray-400 mb-3">Training Controls</h3>
          <div className="space-y-2">
            {!status?.training_active ? (
              <button onClick={handleStart} disabled={actionLoading}
                className="w-full flex items-center justify-center gap-2 px-4 py-2.5 bg-purple-600 hover:bg-purple-500 text-white rounded-lg text-sm font-medium transition disabled:opacity-50">
                <Play className="w-4 h-4" /> Start Training
              </button>
            ) : (
              <button onClick={handleStop} disabled={actionLoading}
                className="w-full flex items-center justify-center gap-2 px-4 py-2.5 bg-red-600 hover:bg-red-500 text-white rounded-lg text-sm font-medium transition disabled:opacity-50">
                <Square className="w-4 h-4" /> Stop Training
              </button>
            )}
            <button onClick={async () => {
              setActionLoading(true);
              try { const r = await injectExpertKnowledge(); alert(r.message || "Expert knowledge injected!"); await refresh(); }
              catch (e: any) { alert(e?.response?.data?.detail || "Failed to inject"); }
              finally { setActionLoading(false); }
            }} disabled={actionLoading}
              className="w-full flex items-center justify-center gap-2 px-4 py-2 bg-purple-900/30 hover:bg-purple-900/50 text-purple-400 rounded-lg text-xs font-medium transition disabled:opacity-50">
              <Zap className="w-3 h-3" /> Inject Expert Knowledge
            </button>
            <button onClick={handleReset}
              className="w-full flex items-center justify-center gap-2 px-4 py-2 bg-gray-800 hover:bg-red-900/30 text-gray-500 hover:text-red-400 rounded-lg text-xs transition">
              <Trash2 className="w-3 h-3" /> Reset Knowledge
            </button>

            {/* Claude API Key */}
            <div className="pt-2 mt-2 border-t border-gray-800">
              <div className="flex items-center justify-between mb-1.5">
                <span className="text-xs text-gray-400 flex items-center gap-1.5">
                  <Key className="w-3 h-3" /> Claude API Key
                </span>
                {claudeKey?.configured && (
                  <span className={cn("text-[10px] px-1.5 py-0.5 rounded",
                    claudeKey.source === "max_subscription" ? "text-purple-400 bg-purple-950/30" : "text-green-400 bg-green-950/30"
                  )}>
                    {claudeKey.source === "max_subscription" ? "Max Plan" : claudeKey.source === "env" ? "Connected (env)" : "Connected"}
                  </span>
                )}
              </div>
              {claudeKey?.configured ? (
                <div className="flex items-center gap-2">
                  <code className="text-[11px] text-gray-400 bg-gray-800 px-2 py-1 rounded flex-1 font-mono">{claudeKey.key_masked}</code>
                  {claudeKey.source !== "max_subscription" && (
                    <button onClick={async () => {
                      if (!confirm("Remove Claude API key?")) return;
                      setClaudeKeyLoading(true);
                      try { await deleteClaudeKey(); setClaudeKeyState({ configured: false }); }
                      catch { alert("Failed to remove key"); }
                      finally { setClaudeKeyLoading(false); }
                    }} disabled={claudeKeyLoading} className="p-1.5 text-gray-500 hover:text-red-400 transition" title="Remove key">
                      <Trash2 className="w-3 h-3" />
                    </button>
                  )}
                </div>
              ) : (
                <div className="space-y-1.5">
                  <div className="relative">
                    <input type={showKey ? "text" : "password"} value={claudeKeyInput} onChange={(e) => setClaudeKeyInput(e.target.value)}
                      placeholder="sk-ant-api03-..." className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-1.5 text-xs text-white placeholder-gray-600 focus:border-purple-500 focus:outline-none pr-8" />
                    <button onClick={() => setShowKey(!showKey)} className="absolute right-2 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300">
                      {showKey ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                    </button>
                  </div>
                  <button onClick={async () => {
                    if (!claudeKeyInput.trim()) return;
                    setClaudeKeyLoading(true);
                    try { const result = await setClaudeKey(claudeKeyInput.trim()); setClaudeKeyState({ configured: true, key_masked: result.key_masked }); setClaudeKeyInput(""); }
                    catch (e: any) { alert(e?.response?.data?.detail || "Invalid API key"); }
                    finally { setClaudeKeyLoading(false); }
                  }} disabled={claudeKeyLoading || !claudeKeyInput.trim()}
                    className="w-full px-3 py-1.5 bg-gray-800 hover:bg-purple-900/30 text-gray-400 hover:text-purple-400 rounded-lg text-xs transition disabled:opacity-50">
                    {claudeKeyLoading ? "Validating..." : "Save Claude Key"}
                  </button>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Knowledge Stats */}
        <div className="bg-gray-900/50 border border-gray-800 rounded-xl p-5">
          <h3 className="text-sm font-medium text-gray-400 mb-3">Knowledge Stats</h3>
          <div className="space-y-2.5">
            {[
              { label: "Knowledge Patterns", value: overall.total_patterns || 0, icon: BookOpen },
              { label: "Scans Completed", value: overall.total_scans || 0, icon: BarChart3 },
              { label: "Vulns Found (Total)", value: overall.total_vulns_found || 0, icon: Zap },
              { label: "AI Decisions Made", value: overall.total_decisions || 0, icon: Brain },
              { label: "Decision Success", value: `${overall.decision_success_rate || 0}%`, icon: TrendingUp },
              { label: "Training Sessions", value: overall.training_sessions || 0, icon: RefreshCw },
            ].map(({ label, value, icon: Icon }) => (
              <div key={label} className="flex items-center justify-between">
                <span className="flex items-center gap-2 text-xs text-gray-500">
                  <Icon className="w-3.5 h-3.5" /> {label}
                </span>
                <span className="text-sm font-mono text-white">{value}</span>
              </div>
            ))}
          </div>
          {status?.avg_confidence != null && (
            <div className="mt-3 pt-2 border-t border-gray-800 flex items-center justify-between">
              <span className="text-xs text-gray-500">KB Confidence</span>
              <span className={cn("text-sm font-mono", status.avg_confidence > 0.6 ? "text-green-400" : status.avg_confidence > 0.4 ? "text-yellow-400" : "text-red-400")}>
                {(status.avg_confidence * 100).toFixed(1)}%
              </span>
            </div>
          )}
          {status?.pattern_types && Object.keys(status.pattern_types).length > 0 && (
            <div className="mt-2 pt-2 border-t border-gray-800">
              <p className="text-xs text-gray-600 mb-1.5">Pattern Types</p>
              {Object.entries(status.pattern_types)
                .filter(([k]) => k !== "training_session")
                .sort(([,a]: any, [,b]: any) => (b?.count || b) - (a?.count || a))
                .map(([type, data]: [string, any]) => {
                  const count = typeof data === "object" ? data.count : data;
                  const conf = typeof data === "object" ? data.avg_confidence : null;
                  return (
                    <div key={type} className="flex justify-between text-xs py-0.5">
                      <span className="text-gray-500">{type.replace(/_/g, " ")}</span>
                      <span className="text-gray-400">
                        {count}{conf != null && <span className={cn("ml-1.5", conf > 0.7 ? "text-green-500/60" : conf > 0.4 ? "text-yellow-500/60" : "text-red-500/60")}>({(conf * 100).toFixed(0)}%)</span>}
                      </span>
                    </div>
                  );
                })}
            </div>
          )}
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 bg-gray-900/50 rounded-lg p-1 w-fit">
        {([
          { key: "autopilot", label: "Autopilot", icon: Cpu },
          { key: "skills", label: "Skill Matrix", icon: Shield },
          { key: "intelligence", label: "Intelligence", icon: Activity },
          { key: "modules", label: "Training Modules", icon: BookOpen },
          { key: "range", label: "Practice Range", icon: Server },
          { key: "history", label: "History", icon: Clock },
          { key: "recommendations", label: "Recommendations", icon: TrendingUp },
        ] as { key: TabKey; label: string; icon: any }[]).map(({ key, label, icon: Icon }) => (
          <button
            key={key}
            onClick={() => {
              setActiveTab(key);
              if (key === "range" && !rangeData) refreshRange();
              if (key === "modules" && !modules) {
                getTrainingModules().then(setModules).catch(() => {});
              }
              if (key === "autopilot") loadApStatus();
            }}
            className={cn(
              "flex items-center gap-1.5 px-3 py-2 rounded-md text-sm transition",
              activeTab === key
                ? "bg-gray-800 text-white font-medium"
                : "text-gray-500 hover:text-gray-300"
            )}
          >
            <Icon className="w-3.5 h-3.5" />
            {label}
          </button>
        ))}
      </div>

      {/* === AUTOPILOT TAB === */}
      {activeTab === "autopilot" && (
        <div className="space-y-4">
          {/* Autopilot Status Cards */}
          {apStatus && (
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
                <div className="flex items-center gap-2 mb-1">
                  <Zap className={`w-4 h-4 ${apStatus.active_scans > 0 ? "text-green-400 animate-pulse" : "text-gray-600"}`} />
                  <p className="text-xs text-gray-500 uppercase">{t("auto.active_scans")}</p>
                </div>
                <p className="text-2xl font-bold text-white font-mono">{apStatus.active_scans}</p>
              </div>
              <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
                <div className="flex items-center gap-2 mb-1">
                  <Target className="w-4 h-4 text-red-400" />
                  <p className="text-xs text-gray-500 uppercase">{t("auto.programs")}</p>
                </div>
                <p className="text-2xl font-bold text-white font-mono">{apStatus.available_programs}</p>
              </div>
              <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
                <div className="flex items-center gap-2 mb-1">
                  <FileText className="w-4 h-4 text-yellow-400" />
                  <p className="text-xs text-gray-500 uppercase">{t("auto.pending_drafts")}</p>
                </div>
                <p className="text-2xl font-bold text-yellow-400 font-mono">{apStatus.pending_drafts}</p>
              </div>
              <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
                <div className="flex items-center gap-2 mb-1">
                  <Clock className="w-4 h-4 text-blue-400" />
                  <p className="text-xs text-gray-500 uppercase">{t("auto.scans_24h")}</p>
                </div>
                <p className="text-2xl font-bold text-blue-400 font-mono">{apStatus.scans_last_24h}</p>
              </div>
            </div>
          )}

          {/* Next Recommended */}
          {apStatus?.next_recommended && (
            <div className="bg-gradient-to-r from-cyan-900/20 to-blue-900/20 border border-cyan-800/30 rounded-xl p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-xs text-cyan-500 uppercase mb-1">{t("auto.next_target")}</p>
                  <p className="text-lg text-white font-medium">{apStatus.next_recommended.name || apStatus.next_recommended.program}</p>
                  <p className="text-xs text-gray-500">{apStatus.next_recommended.program}</p>
                </div>
                <div className="text-right">
                  <p className="text-xs text-gray-500">{t("programs.roi_score")}</p>
                  <p className="text-2xl font-bold text-cyan-400 font-mono">{(apStatus.next_recommended.roi_score || 0).toFixed(0)}</p>
                </div>
              </div>
            </div>
          )}

          {/* Controls */}
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
            <h2 className="text-lg font-semibold text-white mb-4">{t("auto.controls")}</h2>
            <div className="flex flex-wrap items-center gap-4">
              <button onClick={handleSingleScan} disabled={scanning}
                className="flex items-center gap-2 px-5 py-2.5 bg-cyan-600 hover:bg-cyan-700 disabled:bg-gray-700 rounded-lg text-sm text-white font-medium transition-colors">
                {scanning ? <Loader2 className="w-4 h-4 animate-spin" /> : <Zap className="w-4 h-4" />}
                {scanning ? t("auto.scanning") : t("auto.single_scan")}
              </button>

              {taskId ? (
                <button onClick={handleStopAutopilot}
                  className="flex items-center gap-2 px-5 py-2.5 bg-red-600 hover:bg-red-700 rounded-lg text-sm text-white font-medium transition-colors">
                  <Square className="w-4 h-4" /> {t("auto.stop")}
                </button>
              ) : (
                <div className="flex items-center gap-2">
                  <input type="number" min={1} max={10} value={maxScans}
                    onChange={(e) => setMaxScans(parseInt(e.target.value) || 3)}
                    className="w-16 bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white text-center" />
                  <button onClick={handleStartAutopilot}
                    className="flex items-center gap-2 px-5 py-2.5 bg-green-600 hover:bg-green-700 rounded-lg text-sm text-white font-medium transition-colors">
                    <Play className="w-4 h-4" /> {t("auto.start")}
                  </button>
                </div>
              )}

              <button onClick={handleCollectData} disabled={collecting}
                className="flex items-center gap-2 px-4 py-2.5 bg-gray-800 hover:bg-gray-700 disabled:bg-gray-800 rounded-lg text-sm text-gray-300 transition-colors">
                <Database className={`w-4 h-4 ${collecting ? "animate-pulse" : ""}`} />
                {collecting ? t("auto.collecting") : t("auto.collect_data")}
              </button>

              {taskId && (
                <span className="text-xs text-gray-500 font-mono">Task: {taskId.slice(0, 8)}...</span>
              )}
            </div>
          </div>

          {/* Scan Result */}
          {scanResult && (
            <div className={`border rounded-xl p-4 ${
              scanResult.status === "completed" ? "bg-green-900/10 border-green-800/30" :
              scanResult.status === "no_programs" ? "bg-yellow-900/10 border-yellow-800/30" :
              "bg-gray-900 border-gray-800"
            }`}>
              <h3 className="text-sm font-semibold text-white mb-2">{t("auto.last_result")}</h3>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-sm">
                <div>
                  <p className="text-xs text-gray-500">{t("auto.status")}</p>
                  <p className={`capitalize ${scanResult.status === "completed" ? "text-green-400" : "text-yellow-400"}`}>{scanResult.status}</p>
                </div>
                <div>
                  <p className="text-xs text-gray-500">{t("auto.target")}</p>
                  <p className="text-white">{scanResult.domain || "—"}</p>
                </div>
                <div>
                  <p className="text-xs text-gray-500">{t("auto.program")}</p>
                  <p className="text-gray-300">{scanResult.program_name || scanResult.program || "—"}</p>
                </div>
                <div>
                  <p className="text-xs text-gray-500">{t("scans.vulns_found")}</p>
                  <p className={`font-mono ${(scanResult.vulns_found || 0) > 0 ? "text-red-400" : "text-gray-500"}`}>{scanResult.vulns_found || 0}</p>
                </div>
              </div>
              {scanResult.vuln_types && Object.keys(scanResult.vuln_types).length > 0 && (
                <div className="mt-2 flex flex-wrap gap-2">
                  {Object.entries(scanResult.vuln_types).map(([type, count]: any) => (
                    <span key={type} className="text-xs bg-red-900/20 text-red-400 px-2 py-0.5 rounded">{type}: {count}</span>
                  ))}
                </div>
              )}
              {scanResult.drafts_created > 0 && (
                <p className="mt-2 text-xs text-green-400">
                  <CheckCircle className="w-3 h-3 inline mr-1" />{scanResult.drafts_created} draft submissions created
                </p>
              )}
            </div>
          )}

          {/* Logs */}
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-sm font-semibold text-white">{t("auto.activity_log")}</h2>
              <button onClick={() => setLogs([])} className="text-xs text-gray-600 hover:text-gray-400">{t("auto.clear")}</button>
            </div>
            <div className="bg-gray-950 rounded-lg p-3 h-48 overflow-y-auto font-mono text-xs">
              {logs.length === 0 ? (
                <p className="text-gray-600">{t("auto.no_activity")}</p>
              ) : (
                logs.map((log, i) => (
                  <p key={i} className="text-gray-400 leading-relaxed">{log}</p>
                ))
              )}
              <div ref={logsEndRef} />
            </div>
          </div>
        </div>
      )}

      {/* === SKILLS TAB === */}
      {activeTab === "skills" && (
        <div className="space-y-4">
          <div className="bg-gray-900/50 border border-gray-800 rounded-xl p-5">
            <h3 className="text-sm font-medium text-gray-400 mb-4">Vulnerability Detection Skills</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {Object.values(skillsMap)
                .sort((a: any, b: any) => b.skill_score - a.skill_score)
                .map((s: any) => <SkillBar key={s.vuln_type} skill={s} />)}
            </div>
          </div>
          {Object.keys(techExpertise).length > 0 && (
            <div className="bg-gray-900/50 border border-gray-800 rounded-xl p-5">
              <h3 className="text-sm font-medium text-gray-400 mb-4">Technology Expertise</h3>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                {Object.values(techExpertise)
                  .sort((a: any, b: any) => b.expertise_score - a.expertise_score)
                  .map((te: any) => (
                    <div key={te.technology} className="bg-gray-800/50 border border-gray-700/50 rounded-lg p-3">
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-sm font-medium text-white">{te.technology}</span>
                        <span className={cn("text-[10px] px-1.5 py-0.5 rounded uppercase font-medium",
                          te.level === "expert" ? "bg-purple-950/50 text-purple-400" :
                          te.level === "intermediate" ? "bg-yellow-950/50 text-yellow-400" : "bg-gray-800 text-gray-500"
                        )}>{te.level}</span>
                      </div>
                      <div className="w-full bg-gray-700/30 rounded-full h-1.5">
                        <div className="h-1.5 rounded-full bg-purple-500 transition-all" style={{ width: `${Math.min(100, te.expertise_score)}%` }} />
                      </div>
                      <p className="text-[10px] text-gray-600 mt-1">{te.patterns_count} patterns</p>
                    </div>
                  ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* === INTELLIGENCE TAB === */}
      {activeTab === "intelligence" && <IntelligenceTab />}

      {/* === MODULES TAB === */}
      {activeTab === "modules" && (
        <div className="space-y-4">
          <div className="bg-gradient-to-r from-purple-900/20 to-red-900/20 border border-purple-800/30 rounded-xl p-5">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-lg font-bold text-white">Inject All Knowledge</h3>
                <p className="text-sm text-gray-400 mt-1">Run all 9 training modules at once — inject 500+ expert patterns into Phantom&apos;s AI</p>
              </div>
              <button onClick={async () => {
                setModuleLoading("all");
                try { const r = await injectTrainingModule("all"); setModuleResults(prev => ({ ...prev, all: r })); await refresh(); }
                catch (e: any) { setModuleResults(prev => ({ ...prev, all: { error: e?.response?.data?.detail || "Failed" } })); }
                finally { setModuleLoading(null); }
              }} disabled={moduleLoading !== null}
                className="px-6 py-3 bg-gradient-to-r from-purple-600 to-red-600 hover:from-purple-500 hover:to-red-500 text-white rounded-lg font-medium transition disabled:opacity-50 flex items-center gap-2">
                {moduleLoading === "all" ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Zap className="w-4 h-4" />}
                {moduleLoading === "all" ? "Injecting..." : "Inject All"}
              </button>
            </div>
            {moduleResults.all && (
              <div className={cn("mt-3 text-sm rounded-lg p-3", moduleResults.all.error ? "bg-red-950/30 text-red-400" : "bg-green-950/30 text-green-400")}>
                {moduleResults.all.error || moduleResults.all.message || `Injected ${moduleResults.all.created} patterns`}
              </div>
            )}
          </div>

          <ModuleSection title="Static Knowledge Base" subtitle="One-time injection of curated expert knowledge"
            modules={Array.isArray(modules) ? modules : (modules?.static || [])}
            moduleLoading={moduleLoading} moduleResults={moduleResults}
            onRun={async (mod: any) => {
              setModuleLoading(mod.id);
              try {
                const r = mod.endpoint === "/inject-knowledge" ? await injectExpertKnowledge() : await injectTrainingModule(mod.id);
                setModuleResults(prev => ({ ...prev, [mod.id]: r })); await refresh();
              } catch (e: any) { setModuleResults(prev => ({ ...prev, [mod.id]: { error: e?.response?.data?.detail || "Failed" } })); }
              finally { setModuleLoading(null); }
            }}
          />

          {!Array.isArray(modules) && modules?.live && (
            <>
              <div className="bg-gradient-to-r from-cyan-900/20 to-blue-900/20 border border-cyan-800/30 rounded-xl p-5">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="text-lg font-bold text-white flex items-center gap-2">
                      <RefreshCw className="w-5 h-5 text-cyan-400" /> Live Data Feeds
                    </h3>
                    <p className="text-sm text-gray-400 mt-1">Pull fresh data from security APIs — new results every run</p>
                  </div>
                  <button onClick={async () => {
                    setModuleLoading("live_all");
                    try { const r = await runLiveFeed("all"); setModuleResults(prev => ({ ...prev, live_all: r })); await refresh(); }
                    catch (e: any) { setModuleResults(prev => ({ ...prev, live_all: { error: e?.response?.data?.detail || "Failed" } })); }
                    finally { setModuleLoading(null); }
                  }} disabled={moduleLoading !== null}
                    className="px-5 py-2.5 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white rounded-lg font-medium transition disabled:opacity-50 flex items-center gap-2 text-sm">
                    {moduleLoading === "live_all" ? <RefreshCw className="w-4 h-4 animate-spin" /> : <RefreshCw className="w-4 h-4" />}
                    {moduleLoading === "live_all" ? "Fetching..." : "Fetch All Feeds"}
                  </button>
                </div>
                {moduleResults.live_all && (
                  <div className={cn("mt-3 text-sm rounded-lg p-3", moduleResults.live_all.error ? "bg-red-950/30 text-red-400" : "bg-cyan-950/30 text-cyan-400")}>
                    {moduleResults.live_all.error || moduleResults.live_all.message || `Fetched ${moduleResults.live_all.total_created || 0} new patterns`}
                  </div>
                )}
              </div>
              <ModuleSection title="" subtitle="" modules={modules.live} moduleLoading={moduleLoading} moduleResults={moduleResults} colorScheme="cyan"
                onRun={async (mod: any) => {
                  setModuleLoading(mod.id);
                  try { const r = await runLiveFeed(mod.id); setModuleResults(prev => ({ ...prev, [mod.id]: r })); await refresh(); }
                  catch (e: any) { setModuleResults(prev => ({ ...prev, [mod.id]: { error: e?.response?.data?.detail || "Failed" } })); }
                  finally { setModuleLoading(null); }
                }}
              />
            </>
          )}

          {!Array.isArray(modules) && modules?.ai && (
            <>
              <div className="bg-gradient-to-r from-amber-900/20 to-orange-900/20 border border-amber-800/30 rounded-xl p-5">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="text-lg font-bold text-white flex items-center gap-2">
                      <Brain className="w-5 h-5 text-amber-400" /> AI-Powered Mutation
                    </h3>
                    <p className="text-sm text-gray-400 mt-1">Claude generates unique payload variants — infinite creativity</p>
                  </div>
                  <button onClick={async () => {
                    setModuleLoading("ai_all");
                    try { const r = await runAIMutation("all"); setModuleResults(prev => ({ ...prev, ai_all: r })); await refresh(); }
                    catch (e: any) { setModuleResults(prev => ({ ...prev, ai_all: { error: e?.response?.data?.detail || "Failed" } })); }
                    finally { setModuleLoading(null); }
                  }} disabled={moduleLoading !== null}
                    className="px-5 py-2.5 bg-gradient-to-r from-amber-600 to-orange-600 hover:from-amber-500 hover:to-orange-500 text-white rounded-lg font-medium transition disabled:opacity-50 flex items-center gap-2 text-sm">
                    {moduleLoading === "ai_all" ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Brain className="w-4 h-4" />}
                    {moduleLoading === "ai_all" ? "Generating..." : "Run AI Mutation"}
                  </button>
                </div>
                {moduleResults.ai_all && (
                  <div className={cn("mt-3 text-sm rounded-lg p-3", moduleResults.ai_all.error ? "bg-red-950/30 text-red-400" : "bg-amber-950/30 text-amber-400")}>
                    {moduleResults.ai_all.error || moduleResults.ai_all.message || `Generated ${moduleResults.ai_all.mutations_generated || 0} mutations`}
                  </div>
                )}
              </div>
              <ModuleSection title="" subtitle="" modules={modules.ai} moduleLoading={moduleLoading} moduleResults={moduleResults} colorScheme="amber"
                onRun={async (mod: any) => {
                  setModuleLoading(mod.id);
                  try { const r = await runAIMutation(mod.id); setModuleResults(prev => ({ ...prev, [mod.id]: r })); await refresh(); }
                  catch (e: any) { setModuleResults(prev => ({ ...prev, [mod.id]: { error: e?.response?.data?.detail || "Failed" } })); }
                  finally { setModuleLoading(null); }
                }}
              />
            </>
          )}
        </div>
      )}

      {/* === HISTORY TAB === */}
      {activeTab === "history" && (
        <div className="bg-gray-900/50 border border-gray-800 rounded-xl p-5">
          <h3 className="text-sm font-medium text-gray-400 mb-4">Training Sessions</h3>
          {history.length === 0 ? (
            <p className="text-gray-600 text-sm">No training sessions yet. Click &quot;Start Training&quot; to begin.</p>
          ) : (
            <div className="space-y-4">
              {history.map((session: any, i: number) => (
                <div key={session.id || i} className={cn("border rounded-lg p-4",
                  session.type === "hunt" ? "bg-orange-950/20 border-orange-900/30" : "bg-gray-800/50 border-gray-700/50"
                )}>
                  <div className="flex items-center justify-between mb-3">
                    <span className="text-sm text-white font-medium flex items-center gap-2">
                      {session.type === "hunt" && <span className="text-[10px] px-1.5 py-0.5 rounded bg-orange-900/50 text-orange-400 uppercase font-bold">Hunt</span>}
                      {session.type === "study" && <span className="text-[10px] px-1.5 py-0.5 rounded bg-blue-900/50 text-blue-400 uppercase font-bold">Study</span>}
                      {session.date ? new Date(utc(session.date)).toLocaleString() : "Unknown"}
                    </span>
                    <span className="text-xs text-gray-500">
                      Total: {Math.round(session.duration_seconds / 60)}m {Math.round(session.duration_seconds % 60)}s
                    </span>
                  </div>
                  <div className="grid grid-cols-6 gap-2 text-xs mb-3">
                    <div><span className="text-gray-600">CVEs</span><p className="text-gray-300 font-mono">{session.stats?.cves_processed || 0}</p></div>
                    <div><span className="text-gray-600">Created</span><p className="text-green-400 font-mono">{session.stats?.patterns_created || 0}</p></div>
                    <div><span className="text-gray-600">Updated</span><p className="text-blue-400 font-mono">{session.stats?.patterns_updated || 0}</p></div>
                    <div><span className="text-gray-600">ExploitDB</span><p className="text-purple-400 font-mono">{session.stats?.exploitdb_learned || 0}</p></div>
                    <div><span className="text-gray-600">Hacktivity</span><p className="text-cyan-400 font-mono">{session.stats?.hacktivity_learned || 0}</p></div>
                    <div><span className="text-gray-600">Bounty Scan</span><p className="text-orange-400 font-mono">{session.stats?.bounty_scan_learned || 0}</p></div>
                  </div>
                  {session.phases?.length > 0 && (
                    <div className="border-t border-gray-700/50 pt-3">
                      <p className="text-[10px] text-gray-600 uppercase tracking-wider mb-2">Phase Details</p>
                      <div className="space-y-1.5">
                        {session.phases.map((p: any, j: number) => (
                          <div key={j} className="bg-gray-900/50 rounded-md px-3 py-2 flex items-start justify-between gap-2">
                            <div className="flex-1 min-w-0">
                              <div className="flex items-center gap-2 mb-0.5">
                                <span className={cn("w-1.5 h-1.5 rounded-full flex-shrink-0", p.error ? "bg-red-400" : "bg-green-400")} />
                                <span className="text-xs text-white font-medium">{p.label || p.phase}</span>
                                {p.results !== undefined && p.results !== null && (
                                  <span className="text-[10px] text-gray-500">({typeof p.results === 'number' ? `${p.results} items` : p.results})</span>
                                )}
                              </div>
                              {p.url && <p className="text-[10px] text-gray-500 font-mono truncate ml-3.5">{p.url}</p>}
                              {p.domains && p.domains.length > 0 && <p className="text-[10px] text-orange-400/70 ml-3.5 truncate">Scanned: {p.domains.join(", ")}</p>}
                              {p.error && <p className="text-[10px] text-red-400/70 ml-3.5 truncate">Error: {p.error}</p>}
                            </div>
                            <div className="flex-shrink-0 text-right">
                              {p.start && <p className="text-[10px] text-gray-500">{new Date(utc(p.start)).toLocaleTimeString()}</p>}
                              {p.duration_seconds !== undefined && (
                                <p className="text-[10px] text-gray-400 font-mono">
                                  {p.duration_seconds < 60 ? `${p.duration_seconds}s` : `${Math.floor(p.duration_seconds / 60)}m ${Math.round(p.duration_seconds % 60)}s`}
                                </p>
                              )}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* === RECOMMENDATIONS TAB === */}
      {activeTab === "recommendations" && (
        <div className="bg-gray-900/50 border border-gray-800 rounded-xl p-5">
          <h3 className="text-sm font-medium text-gray-400 mb-4">Training Recommendations</h3>
          {recommendations.length === 0 ? (
            <p className="text-gray-600 text-sm">Run a training session first to get personalized recommendations.</p>
          ) : (
            <div className="space-y-3">
              {recommendations.map((rec: any, i: number) => (
                <div key={i} className={cn("border rounded-lg p-4",
                  rec.priority === "high" ? "bg-red-950/20 border-red-900/50" :
                  rec.priority === "medium" ? "bg-yellow-950/20 border-yellow-900/50" :
                  "bg-gray-800/50 border-gray-700/50"
                )}>
                  <div className="flex items-start gap-3">
                    {rec.priority === "high" ? <AlertTriangle className="w-4 h-4 text-red-400 mt-0.5 flex-shrink-0" /> :
                     rec.priority === "info" ? <CheckCircle className="w-4 h-4 text-green-400 mt-0.5 flex-shrink-0" /> :
                     <TrendingUp className="w-4 h-4 text-yellow-400 mt-0.5 flex-shrink-0" />}
                    <div>
                      <div className="flex items-center gap-2 mb-1">
                        <span className="text-sm font-medium text-white capitalize">{rec.area?.replace(/_/g, " ")}</span>
                        <span className={cn("text-[10px] px-1.5 py-0.5 rounded uppercase font-medium",
                          rec.priority === "high" ? "bg-red-900/50 text-red-400" :
                          rec.priority === "medium" ? "bg-yellow-900/50 text-yellow-400" :
                          "bg-green-900/50 text-green-400"
                        )}>{rec.priority}</span>
                        {rec.current_level && <span className="text-[10px] text-gray-600">Current: {rec.current_level}</span>}
                      </div>
                      <p className="text-sm text-gray-400">{rec.action}</p>
                      {rec.expected_improvement && <p className="text-xs text-gray-600 mt-1">{rec.expected_improvement}</p>}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* === RANGE TAB === */}
      {activeTab === "range" && (
        <div className="bg-gray-900/50 border border-gray-800 rounded-xl p-5">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-medium text-gray-400 flex items-center gap-2">
              <Server className="w-4 h-4" /> Practice Targets
            </h3>
            <button onClick={refreshRange} className="text-xs text-gray-500 hover:text-gray-300 transition">
              <RefreshCw className="w-3.5 h-3.5" />
            </button>
          </div>
          {!rangeData ? (
            <p className="text-gray-600 text-sm animate-pulse">Loading practice targets...</p>
          ) : !rangeData.docker_available ? (
            <div className="bg-red-950/20 border border-red-900/50 rounded-lg p-4 text-sm text-red-400">
              Docker is not available. Practice targets require Docker to deploy vulnerable applications.
            </div>
          ) : (
            <div className="space-y-3">
              {rangeData.targets?.map((target: any) => (
                <div key={target.id} className="bg-gray-800/50 border border-gray-700/50 rounded-lg p-4">
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-3">
                      <h4 className="text-sm font-medium text-white">{target.name}</h4>
                      <span className={cn("text-[10px] px-1.5 py-0.5 rounded uppercase font-medium",
                        target.difficulty === "beginner" ? "bg-green-950/50 text-green-400" :
                        target.difficulty === "intermediate" ? "bg-yellow-950/50 text-yellow-400" :
                        "bg-red-950/50 text-red-400"
                      )}>{target.difficulty}</span>
                      <span className={cn("text-[10px] px-1.5 py-0.5 rounded font-medium",
                        target.status === "running" ? "bg-green-950/50 text-green-400" :
                        target.status === "stopped" ? "bg-yellow-950/50 text-yellow-400" :
                        "bg-gray-800 text-gray-500"
                      )}>
                        {target.status === "running" ? "RUNNING" : target.status === "stopped" ? "STOPPED" : "NOT DEPLOYED"}
                      </span>
                    </div>
                    <div className="flex items-center gap-2">
                      {target.status === "running" ? (
                        <>
                          <button onClick={async () => {
                            setRangeLoading(target.id + "_score");
                            try { const score = await scorePracticeScan(target.id); setScoreData((prev: Record<string, any>) => ({ ...prev, [target.id]: score })); }
                            catch (e: any) { alert(e?.response?.data?.detail || "No scan data found"); }
                            finally { setRangeLoading(null); }
                          }} disabled={rangeLoading === target.id + "_score"}
                            className="px-3 py-1.5 bg-purple-600/20 text-purple-400 rounded text-xs hover:bg-purple-600/30 transition disabled:opacity-50">
                            <Trophy className="w-3 h-3 inline mr-1" />Score
                          </button>
                          <button onClick={async () => {
                            setRangeLoading(target.id);
                            try { await stopPracticeTarget(target.id); await refreshRange(); }
                            finally { setRangeLoading(null); }
                          }} disabled={rangeLoading === target.id}
                            className="px-3 py-1.5 bg-red-600/20 text-red-400 rounded text-xs hover:bg-red-600/30 transition disabled:opacity-50">
                            Stop
                          </button>
                        </>
                      ) : (
                        <button onClick={async () => {
                          setRangeLoading(target.id);
                          try { await deployPracticeTarget(target.id); await refreshRange(); }
                          catch (e: any) { alert(e?.response?.data?.error || "Deploy failed"); }
                          finally { setRangeLoading(null); }
                        }} disabled={rangeLoading === target.id}
                          className="px-3 py-1.5 bg-green-600/20 text-green-400 rounded text-xs hover:bg-green-600/30 transition disabled:opacity-50">
                          {rangeLoading === target.id ? "Deploying..." : "Deploy"}
                        </button>
                      )}
                    </div>
                  </div>
                  <p className="text-xs text-gray-500 mb-2">{target.description}</p>
                  <div className="flex items-center gap-3 text-[10px] text-gray-600">
                    <span>Port: {target.host_port}</span>
                    <span>Expected vulns: {target.total_expected_vulns}</span>
                    <span>Tech: {target.technologies?.join(", ")}</span>
                  </div>
                  {scoreData[target.id] && (
                    <div className="mt-3 pt-3 border-t border-gray-700/50">
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-xs text-gray-400">
                          Scan Score: <span className={cn("font-bold text-sm",
                            scoreData[target.id].grade === "A+" || scoreData[target.id].grade === "A" ? "text-green-400" :
                            scoreData[target.id].grade === "B" ? "text-yellow-400" : "text-red-400"
                          )}>{scoreData[target.id].grade}</span>
                        </span>
                        <span className="text-xs text-gray-500">
                          {scoreData[target.id].total_found}/{scoreData[target.id].total_expected} ({scoreData[target.id].overall_score}%)
                        </span>
                      </div>
                      <div className="grid grid-cols-3 gap-1">
                        {Object.entries(scoreData[target.id].categories || {}).map(([vt, cat]: [string, any]) => (
                          <div key={vt} className={cn("text-[10px] px-2 py-1 rounded",
                            cat.status === "complete" ? "bg-green-950/30 text-green-400" :
                            cat.status === "partial" ? "bg-yellow-950/30 text-yellow-400" :
                            "bg-red-950/30 text-red-400"
                          )}>{vt}: {cat.found}/{cat.expected}</div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/* ── Skill Bar Component ── */
function SkillBar({ skill }: { skill: any }) {
  const levelColors: Record<string, string> = {
    expert: "text-purple-400 bg-purple-950/50",
    advanced: "text-blue-400 bg-blue-950/50",
    intermediate: "text-yellow-400 bg-yellow-950/50",
    beginner: "text-orange-400 bg-orange-950/50",
    untrained: "text-gray-500 bg-gray-800",
  };
  const barColors: Record<string, string> = {
    expert: "bg-purple-500",
    advanced: "bg-blue-500",
    intermediate: "bg-yellow-500",
    beginner: "bg-orange-500",
    untrained: "bg-gray-600",
  };

  return (
    <div className="bg-gray-800/30 rounded-lg p-3">
      <div className="flex items-center justify-between mb-2">
        <span className="text-sm text-white font-medium">{skill.vuln_type.replace(/_/g, " ").toUpperCase()}</span>
        <span className={cn("text-[10px] px-1.5 py-0.5 rounded uppercase font-medium", levelColors[skill.level] || "text-gray-500 bg-gray-800")}>
          {skill.level}
        </span>
      </div>
      <div className="w-full bg-gray-700/30 rounded-full h-2 mb-2">
        <div className={cn("h-2 rounded-full transition-all", barColors[skill.level] || "bg-gray-600")}
          style={{ width: `${Math.min(100, skill.skill_score)}%` }} />
      </div>
      <div className="flex justify-between text-[10px] text-gray-600">
        <span>{skill.payloads_known} payloads</span>
        <span>{skill.vulns_found_total} found</span>
        <span>{skill.waf_bypasses} WAF bypasses</span>
        <span>{Math.round(skill.skill_score)}/100</span>
      </div>
    </div>
  );
}

/* ── Module Section Component ── */
function ModuleSection({ title, subtitle, modules, moduleLoading, moduleResults, onRun, colorScheme = "default" }: {
  title: string; subtitle: string; modules: any[]; moduleLoading: string | null;
  moduleResults: Record<string, any>; onRun: (mod: any) => void; colorScheme?: string;
}) {
  const categoryColors: Record<string, string> = {
    knowledge: "border-blue-800/30 bg-blue-950/10",
    evasion: "border-red-800/30 bg-red-950/10",
    strategy: "border-green-800/30 bg-green-950/10",
    community: "border-amber-800/30 bg-amber-950/10",
    live: "border-cyan-800/30 bg-cyan-950/10",
    ai: "border-amber-800/30 bg-amber-950/10",
  };
  const catBadgeColors: Record<string, string> = {
    knowledge: "text-blue-400 bg-blue-950",
    evasion: "text-red-400 bg-red-950",
    strategy: "text-green-400 bg-green-950",
    community: "text-amber-400 bg-amber-950",
    live: "text-cyan-400 bg-cyan-950",
    ai: "text-amber-400 bg-amber-950",
  };

  return (
    <div>
      {title && (
        <div className="mb-3">
          <h3 className="text-sm font-bold text-gray-300">{title}</h3>
          {subtitle && <p className="text-xs text-gray-600">{subtitle}</p>}
        </div>
      )}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {modules.map((mod: any) => {
          const result = moduleResults[mod.id];
          const isLive = mod.category === "live";
          const isAI = mod.category === "ai";
          return (
            <div key={mod.id} className={cn("border rounded-xl p-4 transition", categoryColors[mod.category] || "border-gray-800 bg-gray-900/50")}>
              <div className="flex items-start justify-between mb-2">
                <h4 className="text-sm font-bold text-white">{mod.name}</h4>
                <span className={cn("text-[10px] px-1.5 py-0.5 rounded uppercase font-bold", catBadgeColors[mod.category] || "text-gray-400 bg-gray-800")}>
                  {isLive ? "LIVE" : isAI ? "AI" : mod.category}
                </span>
              </div>
              <p className="text-xs text-gray-500 mb-3">{mod.description}</p>
              <button onClick={() => onRun(mod)} disabled={moduleLoading !== null}
                className={cn("w-full flex items-center justify-center gap-1.5 px-3 py-2 rounded-lg text-xs font-medium transition disabled:opacity-50",
                  isLive ? "bg-cyan-900/30 hover:bg-cyan-900/50 text-cyan-400" :
                  isAI ? "bg-amber-900/30 hover:bg-amber-900/50 text-amber-400" :
                  "bg-gray-800 hover:bg-gray-700 text-gray-300"
                )}>
                {moduleLoading === mod.id ? <RefreshCw className="w-3 h-3 animate-spin" /> : <Zap className="w-3 h-3" />}
                {moduleLoading === mod.id ? (isLive ? "Fetching..." : isAI ? "Generating..." : "Injecting...") : (isLive ? "Fetch" : isAI ? "Generate" : "Inject")}
              </button>
              {result && (
                <div className={cn("mt-2 text-[11px] rounded p-2", result.error ? "bg-red-950/30 text-red-400" : "bg-green-950/30 text-green-400")}>
                  {result.error || result.message || `+${result.created || result.total_created || result.mutations_generated || 0} patterns`}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

/* ── Intelligence Tab — Knowledge Health, Aging, Adversarial Testing ── */
function IntelligenceTab() {
  const [health, setHealth] = useState<any>(null);
  const [advStats, setAdvStats] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [agingLoading, setAgingLoading] = useState(false);
  const [advLoading, setAdvLoading] = useState(false);
  const [agingResult, setAgingResult] = useState<any>(null);
  const [advResult, setAdvResult] = useState<any>(null);
  const [advVulnType, setAdvVulnType] = useState("");
  const [advRounds, setAdvRounds] = useState(10);

  useEffect(() => {
    Promise.all([
      getKnowledgeHealth().catch(() => null),
      getAdversarialStats().catch(() => null),
    ]).then(([h, a]) => { setHealth(h); setAdvStats(a); setLoading(false); });
  }, []);

  const handleAging = async () => {
    setAgingLoading(true);
    try { const r = await runKnowledgeAging(); setAgingResult(r); const h = await getKnowledgeHealth(); setHealth(h); }
    catch { setAgingResult({ error: "Failed" }); }
    finally { setAgingLoading(false); }
  };

  const handleAdversarial = async () => {
    setAdvLoading(true); setAdvResult(null);
    try { const r = await startAdversarialTest(advVulnType || undefined, advRounds); setAdvResult(r); }
    catch (e: any) { setAdvResult({ error: e?.response?.data?.detail || "Failed" }); }
    finally { setAdvLoading(false); }
  };

  if (loading) return <div className="text-gray-500 animate-pulse p-4">Loading intelligence data...</div>;

  return (
    <div className="space-y-4">
      {/* Knowledge Health */}
      <div className="bg-gray-900/50 border border-gray-800 rounded-xl p-5">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-sm font-medium text-gray-400 flex items-center gap-2">
            <Database className="w-4 h-4" /> Knowledge Base Health
          </h3>
          <button onClick={handleAging} disabled={agingLoading}
            className="px-3 py-1.5 text-xs bg-gray-800 border border-gray-700 rounded hover:bg-gray-700 disabled:opacity-50 flex items-center gap-1">
            <RefreshCw className={cn("w-3 h-3", agingLoading && "animate-spin")} />
            {agingLoading ? "Cleaning..." : "Run Aging & Cleanup"}
          </button>
        </div>
        {agingResult && (
          <div className={cn("text-xs rounded p-2 mb-3", agingResult.error ? "bg-red-950/30 text-red-400" : "bg-green-950/30 text-green-400")}>
            {agingResult.error || `Decayed: ${agingResult.decay?.decayed || 0}, Deleted: ${agingResult.decay?.deleted || 0}, Merged: ${agingResult.dedup?.merged || 0}`}
          </div>
        )}
        {health && (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-4">
            {[
              { label: "Total Patterns", value: health.total_patterns || 0, color: "text-white" },
              { label: "Avg Confidence", value: `${((health.avg_confidence || 0) * 100).toFixed(0)}%`, color: "text-purple-400" },
              { label: "Stale (>90d)", value: health.stale_count || 0, color: (health.stale_count || 0) > 10 ? "text-red-400" : "text-gray-400" },
              { label: "Coverage Gaps", value: health.coverage_gaps?.length || 0, color: (health.coverage_gaps?.length || 0) > 3 ? "text-yellow-400" : "text-green-400" },
            ].map(s => (
              <div key={s.label} className="bg-gray-800/50 rounded-lg p-3 text-center">
                <p className={cn("text-lg font-bold font-mono", s.color)}>{s.value}</p>
                <p className="text-[10px] text-gray-500">{s.label}</p>
              </div>
            ))}
          </div>
        )}
        {health?.by_type && Object.keys(health.by_type).length > 0 && (
          <div>
            <p className="text-xs text-gray-500 mb-2">Pattern Distribution</p>
            <div className="flex flex-wrap gap-1.5">
              {Object.entries(health.by_type)
                .sort(([,a]: any, [,b]: any) => b - a)
                .map(([type, count]: any) => {
                  const intensity = Math.min(1, count / 50);
                  return (
                    <div key={type} title={`${type}: ${count}`}
                      className="px-2 py-1 rounded text-[10px] font-mono border border-gray-700/50"
                      style={{ backgroundColor: `rgba(168, 85, 247, ${0.1 + intensity * 0.4})`, color: intensity > 0.5 ? "#e9d5ff" : "#9ca3af" }}>
                      {type.replace(/_/g, " ")} <span className="font-bold">{count}</span>
                    </div>
                  );
                })}
            </div>
          </div>
        )}
        {health?.coverage_gaps?.length > 0 && (
          <div className="mt-3">
            <p className="text-xs text-yellow-500 mb-1 flex items-center gap-1">
              <AlertTriangle className="w-3 h-3" /> Weak Areas ({"<"}3 patterns)
            </p>
            <div className="flex flex-wrap gap-1.5">
              {health.coverage_gaps.map((vt: string) => (
                <span key={vt} className="px-2 py-0.5 text-[10px] bg-yellow-950/30 text-yellow-400 border border-yellow-900/30 rounded">{vt}</span>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Adversarial Red vs Blue */}
      <div className="bg-gray-900/50 border border-gray-800 rounded-xl p-5">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-sm font-medium text-gray-400 flex items-center gap-2">
            <Swords className="w-4 h-4 text-red-400" /> Adversarial Testing (Red vs Blue)
          </h3>
        </div>
        <p className="text-xs text-gray-500 mb-3">
          RED generates evasive payloads. BLUE tries to detect them. Surviving payloads are saved as high-quality bypasses.
        </p>
        <div className="flex items-end gap-3 mb-4">
          <div>
            <label className="text-[10px] text-gray-500 block mb-1">Vuln Type</label>
            <select value={advVulnType} onChange={e => setAdvVulnType(e.target.value)}
              className="bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-xs focus:outline-none focus:border-purple-500">
              <option value="">All Types</option>
              {["xss", "sqli", "cmd_injection", "ssrf", "lfi"].map(vt => (
                <option key={vt} value={vt}>{vt.toUpperCase()}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="text-[10px] text-gray-500 block mb-1">Rounds</label>
            <input type="number" value={advRounds} onChange={e => setAdvRounds(parseInt(e.target.value) || 10)}
              min={1} max={50} className="w-20 bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-xs focus:outline-none focus:border-purple-500" />
          </div>
          <button onClick={handleAdversarial} disabled={advLoading}
            className="px-4 py-1.5 bg-red-600 hover:bg-red-500 text-white text-xs rounded font-medium disabled:opacity-50 flex items-center gap-1">
            {advLoading ? <RefreshCw className="w-3 h-3 animate-spin" /> : <Swords className="w-3 h-3" />}
            {advLoading ? "Fighting..." : "Start Battle"}
          </button>
        </div>
        {advResult && (
          <div className={cn("text-xs rounded p-3 mb-4", advResult.error ? "bg-red-950/30 text-red-400" : "bg-gray-800 text-gray-300")}>
            {advResult.error ? advResult.error : advResult.message || "Adversarial test launched in background"}
          </div>
        )}
        {advStats && advStats.total_rounds > 0 && (
          <div>
            <div className="grid grid-cols-4 gap-3 mb-4">
              {[
                { label: "Total Rounds", value: advStats.total_rounds, color: "text-white" },
                { label: "RED Wins", value: advStats.total_red_wins, color: "text-red-400" },
                { label: "BLUE Wins", value: advStats.total_blue_wins, color: "text-blue-400" },
                { label: "Survival Rate", value: `${((advStats.overall_survival_rate || 0) * 100).toFixed(0)}%`, color: "text-purple-400" },
              ].map(s => (
                <div key={s.label} className="bg-gray-800/50 rounded-lg p-3 text-center">
                  <p className={cn("text-lg font-bold font-mono", s.color)}>{s.value}</p>
                  <p className="text-[10px] text-gray-500">{s.label}</p>
                </div>
              ))}
            </div>
            {advStats.per_vuln_type && Object.keys(advStats.per_vuln_type).length > 0 && (
              <div>
                <p className="text-xs text-gray-500 mb-2">Win Rate by Vuln Type</p>
                <div className="space-y-2">
                  {Object.entries(advStats.per_vuln_type).map(([vt, data]: any) => {
                    const total = (data.red_wins || 0) + (data.blue_wins || 0);
                    const redPct = total > 0 ? (data.red_wins / total) * 100 : 50;
                    return (
                      <div key={vt}>
                        <div className="flex justify-between text-[10px] mb-1">
                          <span className="text-gray-400 uppercase font-mono">{vt}</span>
                          <span className="text-gray-500">{total} rounds</span>
                        </div>
                        <div className="flex h-2 rounded-full overflow-hidden bg-gray-800">
                          <div className="bg-red-500 transition-all" style={{ width: `${redPct}%` }} title={`RED: ${data.red_wins}`} />
                          <div className="bg-blue-500 transition-all" style={{ width: `${100 - redPct}%` }} title={`BLUE: ${data.blue_wins}`} />
                        </div>
                        <div className="flex justify-between text-[9px] mt-0.5">
                          <span className="text-red-400">RED {data.red_wins}</span>
                          <span className="text-blue-400">BLUE {data.blue_wins}</span>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
            {advStats.most_evasive?.length > 0 && (
              <div className="mt-3">
                <p className="text-xs text-gray-500 mb-1">Most Evasive Techniques</p>
                <div className="flex flex-wrap gap-1.5">
                  {advStats.most_evasive.slice(0, 8).map((te: any, i: number) => (
                    <span key={i} className="px-2 py-0.5 text-[10px] bg-red-950/30 text-red-400 border border-red-900/30 rounded">
                      {typeof te === "string" ? te : te.technique || te.name}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
        {(!advStats || advStats.total_rounds === 0) && (
          <p className="text-xs text-gray-600 text-center py-4">No adversarial tests run yet. Start a battle above.</p>
        )}
      </div>

      {/* Skill Heatmap */}
      <SkillHeatmap />
    </div>
  );
}

/* ── Skill Heatmap — vuln_type x technology matrix ── */
function SkillHeatmap() {
  const [skills, setSkills] = useState<any>(null);

  useEffect(() => {
    getSkillsReport().then(setSkills).catch(() => {});
  }, []);

  if (!skills) return null;

  const skillsMap = skills.skills || {};
  const techExpertise = skills.tech_expertise || {};
  const vulnTypes = Object.keys(skillsMap);
  const techs = Object.keys(techExpertise);

  if (vulnTypes.length === 0 || techs.length === 0) return null;

  return (
    <div className="bg-gray-900/50 border border-gray-800 rounded-xl p-5">
      <h3 className="text-sm font-medium text-gray-400 flex items-center gap-2 mb-4">
        <Activity className="w-4 h-4 text-green-400" /> Skill Heatmap
      </h3>
      <p className="text-xs text-gray-500 mb-3">Vuln detection skill x Technology expertise. Brighter = stronger coverage.</p>
      <div className="overflow-x-auto">
        <table className="text-[10px]">
          <thead>
            <tr>
              <th className="text-left text-gray-500 pr-2 pb-2">Vuln \ Tech</th>
              {techs.slice(0, 12).map(t => (
                <th key={t} className="text-center text-gray-500 px-1 pb-2 font-normal" style={{ writingMode: "vertical-rl", transform: "rotate(180deg)", maxHeight: 60 }}>{t}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {vulnTypes.map(vt => {
              const skillScore = skillsMap[vt]?.skill_score || 0;
              return (
                <tr key={vt}>
                  <td className="text-gray-400 pr-2 py-0.5 whitespace-nowrap font-mono">{vt}</td>
                  {techs.slice(0, 12).map(t => {
                    const techScore = techExpertise[t]?.expertise_score || 0;
                    const combined = Math.sqrt(skillScore * techScore) / 10;
                    const intensity = Math.min(1, combined / 10);
                    return (
                      <td key={t} className="px-0.5 py-0.5">
                        <div className="w-6 h-6 rounded-sm border border-gray-800/50"
                          title={`${vt} × ${t}: skill=${skillScore}, tech=${techScore}`}
                          style={{
                            backgroundColor: intensity > 0.6
                              ? `rgba(34, 197, 94, ${intensity})`
                              : intensity > 0.3
                              ? `rgba(234, 179, 8, ${intensity})`
                              : `rgba(239, 68, 68, ${Math.max(0.1, intensity)})`,
                          }} />
                      </td>
                    );
                  })}
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      <div className="flex items-center gap-4 mt-3 text-[10px] text-gray-500">
        <span className="flex items-center gap-1"><span className="w-3 h-3 rounded-sm bg-red-500/30" /> Weak</span>
        <span className="flex items-center gap-1"><span className="w-3 h-3 rounded-sm bg-yellow-500/50" /> Medium</span>
        <span className="flex items-center gap-1"><span className="w-3 h-3 rounded-sm bg-green-500/70" /> Strong</span>
      </div>
    </div>
  );
}
