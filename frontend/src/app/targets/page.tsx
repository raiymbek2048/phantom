"use client";

import { useState, useEffect, useCallback } from "react";
import { useAuthStore } from "@/lib/store";
import { useNotifications } from "@/lib/notifications";
import LoginForm from "@/components/LoginForm";
import Sidebar from "@/components/Sidebar";
import { getTargets, createTarget, deleteTarget, createScan, createCampaign, createCampaignByTag, getAllTags, updateTargetTags } from "@/lib/api";
import { timeAgo, cn } from "@/lib/utils";
import { Plus, Trash2, Play, Globe, X, CheckSquare, Square, Zap, Tag, RotateCw, Layers, Infinity } from "lucide-react";

export default function TargetsPage() {
  const { isLoggedIn, init } = useAuthStore();
  const [loaded, setLoaded] = useState(false);

  useEffect(() => { init(); setLoaded(true); }, [init]);
  if (!loaded) return null;
  if (!isLoggedIn) return <LoginForm />;

  return (
    <div className="flex">
      <Sidebar />
      <main className="ml-60 flex-1 min-h-screen p-6">
        <TargetsContent />
      </main>
    </div>
  );
}

function TargetsContent() {
  const [targets, setTargets] = useState<any[]>([]);
  const [showAdd, setShowAdd] = useState(false);
  const [domain, setDomain] = useState("");
  const [scope, setScope] = useState("");
  const [adding, setAdding] = useState(false);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [campaignLoading, setCampaignLoading] = useState(false);
  const [campaignScanType, setCampaignScanType] = useState("quick");
  const [allTags, setAllTags] = useState<string[]>([]);
  const [filterTag, setFilterTag] = useState<string>("");
  const [editingTagsId, setEditingTagsId] = useState<string | null>(null);
  const [tagInput, setTagInput] = useState("");
  const [tagCampaignLoading, setTagCampaignLoading] = useState(false);
  const [tagCampaignScanType, setTagCampaignScanType] = useState("quick");
  // Scan launch modal state
  const [scanModal, setScanModal] = useState<{ targetId: string; domain: string } | null>(null);
  const [scanMode, setScanMode] = useState<"single" | "multi" | "continuous">("single");
  const [scanRounds, setScanRounds] = useState(3);
  const [scanType, setScanType] = useState("full");
  const [scanLaunching, setScanLaunching] = useState(false);
  const notify = useNotifications((s) => s.add);

  const load = useCallback(async () => {
    try {
      const [targetsData, tagsData] = await Promise.all([getTargets(), getAllTags()]);
      setTargets(targetsData);
      setAllTags(tagsData);
    } catch {}
  }, []);

  useEffect(() => { load(); }, [load]);

  function toggleSelect(id: string) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  function toggleSelectAll() {
    if (selected.size === targets.length) {
      setSelected(new Set());
    } else {
      setSelected(new Set(targets.map((t: any) => t.id)));
    }
  }

  async function handleCampaignScan() {
    if (selected.size === 0) return;
    setCampaignLoading(true);
    try {
      const result = await createCampaign(Array.from(selected), campaignScanType);
      setSelected(new Set());
      notify({ type: "success", title: "Campaign launched", message: `${result.scans_launched} scans started${result.skipped ? `, ${result.skipped} skipped` : ""}` });
      window.location.href = "/scans";
    } catch (e: any) {
      notify({ type: "error", title: "Campaign failed", message: e?.response?.data?.detail || "Failed to launch campaign" });
    }
    setCampaignLoading(false);
  }

  async function handleTagCampaign() {
    if (!filterTag) return;
    setTagCampaignLoading(true);
    try {
      const result = await createCampaignByTag(filterTag, tagCampaignScanType);
      notify({ type: "success", title: "Tag campaign launched", message: `${result.scans_launched} scans started for tag "${filterTag}"${result.skipped ? `, ${result.skipped} skipped` : ""}` });
      window.location.href = "/scans";
    } catch (e: any) {
      notify({ type: "error", title: "Tag campaign failed", message: e?.response?.data?.detail || "Failed to launch tag campaign" });
    }
    setTagCampaignLoading(false);
  }

  async function handleAdd() {
    if (!domain.trim()) return;
    setAdding(true);
    try {
      await createTarget(domain.trim(), scope.trim() || undefined);
      notify({ type: "success", title: "Target created", message: `${domain.trim()} added successfully` });
      setDomain("");
      setScope("");
      setShowAdd(false);
      load();
    } catch {
      notify({ type: "error", title: "Failed to add target", message: `Could not add ${domain.trim()}` });
    }
    setAdding(false);
  }

  async function handleDelete(id: string) {
    if (!confirm("Delete this target?")) return;
    try {
      await deleteTarget(id);
      notify({ type: "warning", title: "Target deleted", message: "Target has been removed" });
      load();
    } catch {
      notify({ type: "error", title: "Delete failed", message: "Could not delete target" });
    }
  }

  function openScanModal(targetId: string, domain: string) {
    setScanModal({ targetId, domain });
    setScanMode("single");
    setScanRounds(3);
    setScanType("full");
  }

  async function handleLaunchScan() {
    if (!scanModal) return;
    setScanLaunching(true);
    try {
      const rounds = scanMode === "single" ? 1 : scanRounds;
      const continuous = scanMode === "continuous";
      const scan = await createScan(scanModal.targetId, scanType, 5, rounds, continuous);
      setScanModal(null);
      window.location.href = `/scans/${scan.id}`;
    } catch (e: any) {
      notify({ type: "error", title: "Scan failed", message: e?.response?.data?.detail || "Failed to start scan" });
    }
    setScanLaunching(false);
  }

  async function handleAddTag(targetId: string) {
    const tag = tagInput.trim().toLowerCase();
    if (!tag) return;
    const target = targets.find((t: any) => t.id === targetId);
    const currentTags: string[] = target?.tags || [];
    if (currentTags.includes(tag)) {
      setTagInput("");
      return;
    }
    const newTags = [...currentTags, tag];
    try {
      await updateTargetTags(targetId, newTags);
      setTagInput("");
      load();
    } catch {
      notify({ type: "error", title: "Tag error", message: "Failed to update tags" });
    }
  }

  async function handleRemoveTag(targetId: string, tagToRemove: string) {
    const target = targets.find((t: any) => t.id === targetId);
    const currentTags: string[] = target?.tags || [];
    const newTags = currentTags.filter((t) => t !== tagToRemove);
    try {
      await updateTargetTags(targetId, newTags);
      load();
    } catch {
      notify({ type: "error", title: "Tag error", message: "Failed to remove tag" });
    }
  }

  const filteredTargets = filterTag
    ? targets.filter((t: any) => (t.tags || []).includes(filterTag))
    : targets;

  const TAG_COLORS = [
    "bg-blue-900/50 text-blue-300 border-blue-800",
    "bg-purple-900/50 text-purple-300 border-purple-800",
    "bg-emerald-900/50 text-emerald-300 border-emerald-800",
    "bg-amber-900/50 text-amber-300 border-amber-800",
    "bg-rose-900/50 text-rose-300 border-rose-800",
    "bg-cyan-900/50 text-cyan-300 border-cyan-800",
    "bg-indigo-900/50 text-indigo-300 border-indigo-800",
    "bg-teal-900/50 text-teal-300 border-teal-800",
  ];

  function getTagColor(tag: string) {
    let hash = 0;
    for (let i = 0; i < tag.length; i++) hash = tag.charCodeAt(i) + ((hash << 5) - hash);
    return TAG_COLORS[Math.abs(hash) % TAG_COLORS.length];
  }

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-xl font-bold text-white">Targets</h1>
          <p className="text-sm text-gray-500">
            {filterTag ? `${filteredTargets.length} of ${targets.length}` : targets.length} targets{filterTag ? ` tagged "${filterTag}"` : " registered"}
          </p>
        </div>
        <div className="flex items-center gap-3">
          {/* Tag filter */}
          {allTags.length > 0 && (
            <div className="relative flex items-center gap-1">
              <Tag className="w-4 h-4 text-gray-500" />
              <select
                value={filterTag}
                onChange={(e) => setFilterTag(e.target.value)}
                className="bg-gray-800 border border-gray-700 rounded-lg px-2 py-2 text-sm text-white focus:outline-none focus:border-red-500 appearance-none pr-7"
              >
                <option value="">All Tags</option>
                {allTags.map((tag) => (
                  <option key={tag} value={tag}>{tag}</option>
                ))}
              </select>
              {filterTag && (
                <>
                  <button
                    onClick={() => setFilterTag("")}
                    className="text-gray-400 hover:text-white ml-1"
                    title="Clear filter"
                  >
                    <X className="w-3.5 h-3.5" />
                  </button>
                  <select
                    value={tagCampaignScanType}
                    onChange={(e) => setTagCampaignScanType(e.target.value)}
                    className="bg-gray-800 border border-gray-700 rounded-lg px-2 py-2 text-sm text-white focus:outline-none focus:border-red-500 ml-1"
                  >
                    <option value="quick">Quick</option>
                    <option value="full">Full</option>
                    <option value="recon">Recon</option>
                    <option value="stealth">Stealth</option>
                  </select>
                  <button
                    onClick={handleTagCampaign}
                    disabled={tagCampaignLoading}
                    className="bg-indigo-600 hover:bg-indigo-700 disabled:opacity-40 text-white px-3 py-2 rounded-lg text-sm font-medium flex items-center gap-1.5 transition whitespace-nowrap"
                    title={`Scan all targets tagged "${filterTag}"`}
                  >
                    <Zap className="w-3.5 h-3.5" />
                    {tagCampaignLoading ? "Launching..." : `Scan Tag "${filterTag}" (${filteredTargets.length})`}
                  </button>
                </>
              )}
            </div>
          )}
          {/* Campaign controls — visible when targets exist */}
          {targets.length > 0 && (
            <>
              <button
                onClick={toggleSelectAll}
                className="text-gray-400 hover:text-white px-3 py-2 rounded-lg text-sm flex items-center gap-2 transition border border-gray-700 hover:border-gray-500"
              >
                {selected.size === targets.length ? <CheckSquare className="w-4 h-4" /> : <Square className="w-4 h-4" />}
                {selected.size === targets.length ? "Deselect All" : "Select All"}
              </button>
              {selected.size > 0 && (
                <>
                  <select
                    value={campaignScanType}
                    onChange={(e) => setCampaignScanType(e.target.value)}
                    className="bg-gray-800 border border-gray-700 rounded-lg px-2 py-2 text-sm text-white focus:outline-none focus:border-red-500"
                  >
                    <option value="quick">Quick</option>
                    <option value="full">Full</option>
                    <option value="recon">Recon</option>
                    <option value="stealth">Stealth</option>
                  </select>
                  <button
                    onClick={handleCampaignScan}
                    disabled={campaignLoading}
                    className="bg-purple-600 hover:bg-purple-700 disabled:opacity-40 text-white px-4 py-2 rounded-lg text-sm font-medium flex items-center gap-2 transition"
                  >
                    <Zap className="w-4 h-4" />
                    {campaignLoading ? "Launching..." : `Scan Selected (${selected.size})`}
                  </button>
                </>
              )}
            </>
          )}
          <button
            onClick={() => setShowAdd(true)}
            className="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-lg text-sm font-medium flex items-center gap-2 transition"
          >
            <Plus className="w-4 h-4" /> Add Target
          </button>
        </div>
      </div>

      {/* Add Target Modal */}
      {showAdd && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50" onClick={() => setShowAdd(false)}>
          <div className="bg-gray-900 rounded-xl border border-gray-700 p-6 w-full max-w-md" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-semibold">Add Target</h2>
              <button onClick={() => setShowAdd(false)} className="text-gray-500 hover:text-white">
                <X className="w-5 h-5" />
              </button>
            </div>
            <div className="space-y-3">
              <div>
                <label className="text-xs text-gray-500 mb-1 block">Domain *</label>
                <input
                  type="text"
                  value={domain}
                  onChange={(e) => setDomain(e.target.value)}
                  placeholder="example.com"
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-red-500"
                  autoFocus
                />
              </div>
              <div>
                <label className="text-xs text-gray-500 mb-1 block">Scope (one per line, ! to exclude)</label>
                <textarea
                  value={scope}
                  onChange={(e) => setScope(e.target.value)}
                  placeholder={"*.example.com\napi.example.com\n!staging.example.com\n!/admin/*"}
                  rows={3}
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-red-500 font-mono"
                />
              </div>
              <button
                onClick={handleAdd}
                disabled={adding || !domain.trim()}
                className="w-full bg-red-600 hover:bg-red-700 disabled:opacity-40 text-white py-2.5 rounded-lg text-sm font-medium transition"
              >
                {adding ? "Adding..." : "Add Target"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Scan Launch Modal */}
      {scanModal && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50" onClick={() => setScanModal(null)}>
          <div className="bg-gray-900 rounded-xl border border-gray-700 p-6 w-full max-w-lg" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-5">
              <h2 className="text-lg font-semibold text-white">Scan {scanModal.domain}</h2>
              <button onClick={() => setScanModal(null)} className="text-gray-500 hover:text-white">
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Scan Type */}
            <div className="mb-5">
              <label className="text-xs text-gray-500 mb-2 block uppercase tracking-wider">Scan Type</label>
              <div className="grid grid-cols-4 gap-2">
                {[
                  { value: "full", label: "Full", desc: "All 19 phases" },
                  { value: "quick", label: "Quick", desc: "Key phases only" },
                  { value: "stealth", label: "Stealth", desc: "Low & slow" },
                  { value: "recon", label: "Recon", desc: "Info gathering" },
                ].map((t) => (
                  <button
                    key={t.value}
                    onClick={() => setScanType(t.value)}
                    className={cn(
                      "flex flex-col items-center p-3 rounded-lg border text-center transition",
                      scanType === t.value
                        ? "bg-red-600/20 border-red-600/40 text-red-400"
                        : "bg-gray-800 border-gray-700 text-gray-400 hover:border-gray-600"
                    )}
                  >
                    <span className="text-sm font-medium">{t.label}</span>
                    <span className="text-[10px] text-gray-600 mt-0.5">{t.desc}</span>
                  </button>
                ))}
              </div>
            </div>

            {/* Scan Mode */}
            <div className="mb-5">
              <label className="text-xs text-gray-500 mb-2 block uppercase tracking-wider">Scan Mode</label>
              <div className="space-y-2">
                {/* Single */}
                <button
                  onClick={() => setScanMode("single")}
                  className={cn(
                    "w-full flex items-center gap-3 p-3 rounded-lg border transition text-left",
                    scanMode === "single"
                      ? "bg-green-600/10 border-green-600/30 text-green-400"
                      : "bg-gray-800 border-gray-700 text-gray-400 hover:border-gray-600"
                  )}
                >
                  <Zap className="w-5 h-5 flex-shrink-0" />
                  <div className="flex-1">
                    <span className="text-sm font-medium block">Single Pass</span>
                    <span className="text-[10px] text-gray-600">One run through the pipeline — fast and basic</span>
                  </div>
                </button>

                {/* Multi-round */}
                <button
                  onClick={() => setScanMode("multi")}
                  className={cn(
                    "w-full flex items-center gap-3 p-3 rounded-lg border transition text-left",
                    scanMode === "multi"
                      ? "bg-purple-600/10 border-purple-600/30 text-purple-400"
                      : "bg-gray-800 border-gray-700 text-gray-400 hover:border-gray-600"
                  )}
                >
                  <Layers className="w-5 h-5 flex-shrink-0" />
                  <div className="flex-1">
                    <span className="text-sm font-medium block">Multi-Round</span>
                    <span className="text-[10px] text-gray-600">
                      N rounds with different attack strategies: IDOR, injection, infrastructure, WAF bypass...
                    </span>
                  </div>
                  {scanMode === "multi" && (
                    <div className="flex items-center gap-2" onClick={(e) => e.stopPropagation()}>
                      <input
                        type="range"
                        min={2}
                        max={10}
                        value={scanRounds}
                        onChange={(e) => setScanRounds(parseInt(e.target.value))}
                        className="w-20 accent-purple-500"
                      />
                      <span className="text-sm font-mono text-purple-400 w-5 text-right">{scanRounds}</span>
                    </div>
                  )}
                </button>

                {/* Continuous */}
                <button
                  onClick={() => setScanMode("continuous")}
                  className={cn(
                    "w-full flex items-center gap-3 p-3 rounded-lg border transition text-left",
                    scanMode === "continuous"
                      ? "bg-red-600/10 border-red-600/30 text-red-400"
                      : "bg-gray-800 border-gray-700 text-gray-400 hover:border-gray-600"
                  )}
                >
                  <RotateCw className="w-5 h-5 flex-shrink-0" />
                  <div className="flex-1">
                    <span className="text-sm font-medium block">Infinite</span>
                    <span className="text-[10px] text-gray-600">
                      Never stops. AI plans each round, mutates strategies, goes deeper and deeper. Stop manually.
                    </span>
                  </div>
                  <span className="text-[10px] text-red-500 bg-red-950 px-2 py-0.5 rounded">until you stop</span>
                </button>
              </div>
            </div>

            {/* Launch button */}
            <button
              onClick={handleLaunchScan}
              disabled={scanLaunching}
              className="w-full bg-red-600 hover:bg-red-700 disabled:opacity-40 text-white py-3 rounded-lg text-sm font-medium transition flex items-center justify-center gap-2"
            >
              {scanLaunching ? (
                <>
                  <RotateCw className="w-4 h-4 animate-spin" />
                  Launching...
                </>
              ) : (
                <>
                  <Play className="w-4 h-4" />
                  {scanMode === "single" && "Start Scan"}
                  {scanMode === "multi" && `Start ${scanRounds}-Round Scan`}
                  {scanMode === "continuous" && "Start Infinite Scan"}
                </>
              )}
            </button>
          </div>
        </div>
      )}

      {/* Targets Grid */}
      {filteredTargets.length === 0 ? (
        <div className="text-center py-20 text-gray-600">
          <Globe className="w-12 h-12 mx-auto mb-3 opacity-30" />
          <p>{filterTag ? `No targets with tag "${filterTag}".` : "No targets yet. Add your first target to get started."}</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {filteredTargets.map((t: any) => (
            <div
              key={t.id}
              className={cn(
                "bg-gray-900 rounded-xl border p-4 hover:border-gray-700 transition group",
                selected.has(t.id) ? "border-purple-500" : "border-gray-800"
              )}
            >
              <div className="flex items-start justify-between mb-3">
                <div className="flex items-start gap-2">
                  <button
                    onClick={() => toggleSelect(t.id)}
                    className="mt-0.5 text-gray-500 hover:text-white transition"
                    title="Select for campaign"
                  >
                    {selected.has(t.id) ? (
                      <CheckSquare className="w-4 h-4 text-purple-400" />
                    ) : (
                      <Square className="w-4 h-4" />
                    )}
                  </button>
                  <div>
                    <h3 className="text-white font-medium">{t.domain}</h3>
                    <p className="text-xs text-gray-600 mt-0.5">
                      {t.scope || "No scope defined"}
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  {t.monitoring_enabled && (
                    <span className="text-[10px] px-2 py-0.5 rounded uppercase font-medium text-blue-400 bg-blue-950">
                      monitoring
                    </span>
                  )}
                  <span className={cn(
                    "text-[10px] px-2 py-0.5 rounded uppercase font-medium",
                    t.status === "active" ? "text-green-400 bg-green-950" : "text-gray-500 bg-gray-800"
                  )}>
                    {t.status}
                  </span>
                </div>
              </div>

              {/* Subdomain / Tech info */}
              <div className="flex gap-4 text-xs text-gray-500 mb-2">
                <span>{t.subdomains?.length || 0} subdomains</span>
                <span>{Object.keys(t.technologies?.summary || {}).length || 0} technologies</span>
              </div>

              {/* Tags */}
              <div className="mb-3">
                <div className="flex flex-wrap items-center gap-1.5">
                  {(t.tags || []).map((tag: string) => (
                    <span
                      key={tag}
                      onClick={() => setEditingTagsId(editingTagsId === t.id ? null : t.id)}
                      className={cn(
                        "inline-flex items-center gap-1 text-[10px] px-2 py-0.5 rounded-full border cursor-pointer transition hover:opacity-80",
                        getTagColor(tag)
                      )}
                    >
                      {tag}
                      {editingTagsId === t.id && (
                        <button
                          onClick={(e) => { e.stopPropagation(); handleRemoveTag(t.id, tag); }}
                          className="hover:text-white ml-0.5"
                        >
                          <X className="w-2.5 h-2.5" />
                        </button>
                      )}
                    </span>
                  ))}
                  {editingTagsId !== t.id && (
                    <button
                      onClick={() => { setEditingTagsId(t.id); setTagInput(""); }}
                      className="text-gray-600 hover:text-gray-400 transition"
                      title="Edit tags"
                    >
                      <Tag className="w-3 h-3" />
                    </button>
                  )}
                </div>
                {editingTagsId === t.id && (
                  <div className="mt-1.5 flex items-center gap-1.5">
                    <input
                      type="text"
                      value={tagInput}
                      onChange={(e) => setTagInput(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === "Enter") { e.preventDefault(); handleAddTag(t.id); }
                        if (e.key === "Escape") setEditingTagsId(null);
                      }}
                      placeholder="Add tag..."
                      className="flex-1 bg-gray-800 border border-gray-700 rounded px-2 py-1 text-[11px] text-white focus:outline-none focus:border-gray-500 min-w-0"
                      autoFocus
                    />
                    <button
                      onClick={() => setEditingTagsId(null)}
                      className="text-gray-500 hover:text-white text-[10px]"
                    >
                      Done
                    </button>
                  </div>
                )}
              </div>

              <div className="flex items-center justify-between">
                <span className="text-[10px] text-gray-700">Added {timeAgo(t.created_at)}</span>
                <div className="flex gap-2 opacity-0 group-hover:opacity-100 transition">
                  <button
                    onClick={() => openScanModal(t.id, t.domain)}
                    className="text-green-400 hover:text-green-300 p-1"
                    title="Start Scan"
                  >
                    <Play className="w-4 h-4" />
                  </button>
                  <button
                    onClick={() => handleDelete(t.id)}
                    className="text-red-400 hover:text-red-300 p-1"
                    title="Delete"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
