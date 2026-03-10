"use client";

import { useState, useEffect, useCallback } from "react";
import { useAuthStore } from "@/lib/store";
import LoginForm from "@/components/LoginForm";
import Sidebar from "@/components/Sidebar";
import {
  getScanTemplates,
  createScanTemplate,
  updateScanTemplate,
  deleteScanTemplate,
  runScanTemplate,
  getTargets,
} from "@/lib/api";
import { cn } from "@/lib/utils";
import {
  FileText,
  Plus,
  Play,
  Pencil,
  Trash2,
  ChevronDown,
  ChevronUp,
  X,
} from "lucide-react";

const SCAN_TYPE_COLORS: Record<string, string> = {
  full: "bg-red-600/20 text-red-400 border-red-800",
  quick: "bg-green-600/20 text-green-400 border-green-800",
  stealth: "bg-purple-600/20 text-purple-400 border-purple-800",
  recon: "bg-blue-600/20 text-blue-400 border-blue-800",
  bounty: "bg-amber-600/20 text-amber-400 border-amber-800",
  api: "bg-cyan-600/20 text-cyan-400 border-cyan-800",
};

function scanTypeBadge(scanType: string) {
  const colors = SCAN_TYPE_COLORS[scanType] || "bg-gray-600/20 text-gray-400 border-gray-700";
  return colors;
}

export default function TemplatesPage() {
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
        <TemplateManager />
      </main>
    </div>
  );
}

function TemplateManager() {
  const [templates, setTemplates] = useState<any[]>([]);
  const [targets, setTargets] = useState<any[]>([]);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [editTemplate, setEditTemplate] = useState<any | null>(null);
  const [runTemplate, setRunTemplate] = useState<any | null>(null);
  const [deleteConfirm, setDeleteConfirm] = useState<string | null>(null);
  const [expandedConfigs, setExpandedConfigs] = useState<Set<string>>(new Set());

  const load = useCallback(async () => {
    try {
      const [t, tgts] = await Promise.all([getScanTemplates(), getTargets()]);
      setTemplates(t);
      setTargets(tgts);
    } catch {}
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const handleDelete = async (id: string) => {
    try {
      await deleteScanTemplate(id);
      setDeleteConfirm(null);
      load();
    } catch {}
  };

  const toggleConfig = (id: string) => {
    setExpandedConfigs((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white">Scan Templates</h1>
          <p className="text-sm text-gray-500">
            Reusable scan configurations for consistent testing
          </p>
        </div>
        <button
          onClick={() => setShowCreateModal(true)}
          className="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-lg text-sm flex items-center gap-2 transition"
        >
          <Plus className="w-4 h-4" /> Create Template
        </button>
      </div>

      {/* Template Grid */}
      {templates.length === 0 ? (
        <div className="bg-gray-900 rounded-xl border border-gray-800 p-12 text-center">
          <FileText className="w-10 h-10 text-gray-700 mx-auto mb-3" />
          <p className="text-gray-500 text-sm">No scan templates yet</p>
          <p className="text-gray-600 text-xs mt-1">
            Create a template to save scan configurations for reuse
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {templates.map((tmpl: any) => {
            const isBuiltin = tmpl.is_builtin || tmpl.builtin;
            return (
              <div
                key={tmpl.id}
                className="bg-gray-900 rounded-xl border border-gray-800 p-5 flex flex-col"
              >
                {/* Template header */}
                <div className="flex items-start justify-between mb-2">
                  <h3 className="text-white font-bold text-sm leading-tight">
                    {tmpl.name}
                  </h3>
                  <div className="flex items-center gap-1.5 ml-2 flex-shrink-0">
                    <span
                      className={cn(
                        "px-2 py-0.5 rounded text-[10px] font-medium uppercase border",
                        scanTypeBadge(tmpl.scan_type)
                      )}
                    >
                      {tmpl.scan_type}
                    </span>
                    {isBuiltin && (
                      <span className="px-2 py-0.5 rounded text-[10px] font-medium uppercase bg-gray-700/40 text-gray-400 border border-gray-700">
                        Builtin
                      </span>
                    )}
                  </div>
                </div>

                {/* Description */}
                <p className="text-gray-500 text-xs mb-4 line-clamp-2">
                  {tmpl.description || "No description"}
                </p>

                {/* Config preview */}
                {tmpl.config && Object.keys(tmpl.config).length > 0 && (
                  <div className="mb-4">
                    <button
                      onClick={() => toggleConfig(tmpl.id)}
                      className="flex items-center gap-1 text-[11px] text-gray-500 hover:text-gray-300 transition"
                    >
                      {expandedConfigs.has(tmpl.id) ? (
                        <ChevronUp className="w-3 h-3" />
                      ) : (
                        <ChevronDown className="w-3 h-3" />
                      )}
                      Config
                    </button>
                    {expandedConfigs.has(tmpl.id) && (
                      <pre className="mt-2 bg-gray-950 border border-gray-800 rounded-lg p-3 text-[11px] text-gray-400 overflow-x-auto max-h-40 overflow-y-auto">
                        {JSON.stringify(tmpl.config, null, 2)}
                      </pre>
                    )}
                  </div>
                )}

                {/* Actions */}
                <div className="mt-auto flex items-center gap-2 pt-2 border-t border-gray-800">
                  <button
                    onClick={() => setRunTemplate(tmpl)}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-green-600/20 text-green-400 hover:bg-green-600/30 text-xs transition"
                  >
                    <Play className="w-3.5 h-3.5" /> Run
                  </button>
                  {!isBuiltin && (
                    <>
                      <button
                        onClick={() => setEditTemplate(tmpl)}
                        className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-blue-600/20 text-blue-400 hover:bg-blue-600/30 text-xs transition"
                      >
                        <Pencil className="w-3.5 h-3.5" /> Edit
                      </button>
                      {deleteConfirm === tmpl.id ? (
                        <div className="flex items-center gap-1 ml-auto">
                          <button
                            onClick={() => handleDelete(tmpl.id)}
                            className="px-2 py-1.5 rounded-lg bg-red-600 text-white text-xs hover:bg-red-700 transition"
                          >
                            Confirm
                          </button>
                          <button
                            onClick={() => setDeleteConfirm(null)}
                            className="px-2 py-1.5 rounded-lg bg-gray-800 text-gray-400 text-xs hover:bg-gray-700 transition"
                          >
                            Cancel
                          </button>
                        </div>
                      ) : (
                        <button
                          onClick={() => setDeleteConfirm(tmpl.id)}
                          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-red-600/20 text-red-400 hover:bg-red-600/30 text-xs transition ml-auto"
                        >
                          <Trash2 className="w-3.5 h-3.5" /> Delete
                        </button>
                      )}
                    </>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Create / Edit Modal */}
      {(showCreateModal || editTemplate) && (
        <CreateEditModal
          template={editTemplate}
          onClose={() => {
            setShowCreateModal(false);
            setEditTemplate(null);
          }}
          onSaved={() => {
            setShowCreateModal(false);
            setEditTemplate(null);
            load();
          }}
        />
      )}

      {/* Run Modal */}
      {runTemplate && (
        <RunModal
          template={runTemplate}
          targets={targets}
          onClose={() => setRunTemplate(null)}
          onRun={() => {
            setRunTemplate(null);
          }}
        />
      )}
    </div>
  );
}

// ------- Create / Edit Modal -------

function CreateEditModal({
  template,
  onClose,
  onSaved,
}: {
  template: any | null;
  onClose: () => void;
  onSaved: () => void;
}) {
  const isEdit = !!template;
  const [name, setName] = useState(template?.name || "");
  const [description, setDescription] = useState(template?.description || "");
  const [scanType, setScanType] = useState(template?.scan_type || "full");
  const [configText, setConfigText] = useState(
    template?.config ? JSON.stringify(template.config, null, 2) : "{}"
  );
  const [deepChecks, setDeepChecks] = useState(
    template?.config?.deep_checks || false
  );
  const [browserEnabled, setBrowserEnabled] = useState(
    template?.config?.browser_enabled || false
  );
  const [respectScope, setRespectScope] = useState(
    template?.config?.respect_scope ?? true
  );
  const [configError, setConfigError] = useState("");
  const [saving, setSaving] = useState(false);

  const handleSave = async () => {
    let config: Record<string, any>;
    try {
      config = JSON.parse(configText);
    } catch {
      setConfigError("Invalid JSON");
      return;
    }
    // Merge advanced options
    config.deep_checks = deepChecks;
    config.browser_enabled = browserEnabled;
    config.respect_scope = respectScope;

    setSaving(true);
    try {
      if (isEdit) {
        await updateScanTemplate(template.id, {
          name,
          description,
          scan_type: scanType,
          config,
        });
      } else {
        await createScanTemplate(name, description, scanType, config);
      }
      onSaved();
    } catch {
      setSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-gray-900 border border-gray-800 rounded-2xl w-full max-w-lg mx-4 shadow-2xl">
        {/* Modal header */}
        <div className="flex items-center justify-between p-5 border-b border-gray-800">
          <h2 className="text-white font-bold text-sm">
            {isEdit ? "Edit Template" : "Create Template"}
          </h2>
          <button
            onClick={onClose}
            className="text-gray-500 hover:text-gray-300 transition"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Modal body */}
        <div className="p-5 space-y-4 max-h-[70vh] overflow-y-auto">
          {/* Name */}
          <div>
            <label className="text-xs text-gray-500 uppercase mb-1 block">
              Name
            </label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="My Custom Scan"
              className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-red-600 transition"
            />
          </div>

          {/* Description */}
          <div>
            <label className="text-xs text-gray-500 uppercase mb-1 block">
              Description
            </label>
            <textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Describe what this template is for..."
              rows={2}
              className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-red-600 transition resize-none"
            />
          </div>

          {/* Scan Type */}
          <div>
            <label className="text-xs text-gray-500 uppercase mb-1 block">
              Scan Type
            </label>
            <select
              value={scanType}
              onChange={(e) => setScanType(e.target.value)}
              className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-red-600 transition"
            >
              <option value="full">Full</option>
              <option value="quick">Quick</option>
              <option value="stealth">Stealth</option>
              <option value="recon">Recon</option>
              <option value="bounty">Bounty</option>
            </select>
          </div>

          {/* Config JSON */}
          <div>
            <label className="text-xs text-gray-500 uppercase mb-1 block">
              Config (JSON)
            </label>
            <textarea
              value={configText}
              onChange={(e) => {
                setConfigText(e.target.value);
                setConfigError("");
              }}
              rows={5}
              className={cn(
                "w-full bg-gray-950 border rounded-lg px-3 py-2 text-xs text-gray-300 font-mono focus:outline-none transition resize-none",
                configError
                  ? "border-red-600"
                  : "border-gray-700 focus:border-red-600"
              )}
            />
            {configError && (
              <p className="text-red-400 text-xs mt-1">{configError}</p>
            )}
          </div>

          {/* Advanced Options */}
          <div>
            <label className="text-xs text-gray-500 uppercase mb-2 block">
              Advanced Options
            </label>
            <div className="space-y-2">
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={deepChecks}
                  onChange={(e) => setDeepChecks(e.target.checked)}
                  className="w-4 h-4 rounded bg-gray-800 border-gray-700 text-red-600 focus:ring-red-600 focus:ring-offset-0"
                />
                <span className="text-sm text-gray-300">Deep checks</span>
                <span className="text-[10px] text-gray-600 ml-1">
                  Thorough vulnerability analysis
                </span>
              </label>
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={browserEnabled}
                  onChange={(e) => setBrowserEnabled(e.target.checked)}
                  className="w-4 h-4 rounded bg-gray-800 border-gray-700 text-red-600 focus:ring-red-600 focus:ring-offset-0"
                />
                <span className="text-sm text-gray-300">Browser enabled</span>
                <span className="text-[10px] text-gray-600 ml-1">
                  Playwright headless browser
                </span>
              </label>
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={respectScope}
                  onChange={(e) => setRespectScope(e.target.checked)}
                  className="w-4 h-4 rounded bg-gray-800 border-gray-700 text-red-600 focus:ring-red-600 focus:ring-offset-0"
                />
                <span className="text-sm text-gray-300">Respect scope</span>
                <span className="text-[10px] text-gray-600 ml-1">
                  Stay within target scope
                </span>
              </label>
            </div>
          </div>
        </div>

        {/* Modal footer */}
        <div className="flex items-center justify-end gap-2 p-5 border-t border-gray-800">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-lg bg-gray-800 hover:bg-gray-700 text-gray-300 text-sm transition"
          >
            Cancel
          </button>
          <button
            onClick={handleSave}
            disabled={!name.trim() || saving}
            className={cn(
              "px-4 py-2 rounded-lg text-sm text-white transition flex items-center gap-2",
              !name.trim() || saving
                ? "bg-gray-700 text-gray-500 cursor-not-allowed"
                : "bg-red-600 hover:bg-red-700"
            )}
          >
            {saving ? "Saving..." : isEdit ? "Update Template" : "Save Template"}
          </button>
        </div>
      </div>
    </div>
  );
}

// ------- Run Modal -------

function RunModal({
  template,
  targets,
  onClose,
  onRun,
}: {
  template: any;
  targets: any[];
  onClose: () => void;
  onRun: () => void;
}) {
  const [targetId, setTargetId] = useState(targets[0]?.id || "");
  const [priority, setPriority] = useState(5);
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<any>(null);

  const handleRun = async () => {
    if (!targetId) return;
    setRunning(true);
    try {
      const res = await runScanTemplate(template.id, targetId, priority);
      setResult(res);
      setTimeout(() => onRun(), 1500);
    } catch {
      setRunning(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-gray-900 border border-gray-800 rounded-2xl w-full max-w-md mx-4 shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between p-5 border-b border-gray-800">
          <div>
            <h2 className="text-white font-bold text-sm">Run Template</h2>
            <p className="text-gray-500 text-xs mt-0.5">{template.name}</p>
          </div>
          <button
            onClick={onClose}
            className="text-gray-500 hover:text-gray-300 transition"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Body */}
        <div className="p-5 space-y-4">
          {result ? (
            <div className="bg-green-600/10 border border-green-800 rounded-lg p-4 text-center">
              <Play className="w-6 h-6 text-green-400 mx-auto mb-2" />
              <p className="text-green-400 text-sm font-medium">
                Scan launched successfully
              </p>
              {result.scan_id && (
                <p className="text-green-600 text-xs mt-1">
                  Scan ID: {result.scan_id}
                </p>
              )}
            </div>
          ) : (
            <>
              {/* Target selector */}
              <div>
                <label className="text-xs text-gray-500 uppercase mb-1 block">
                  Target
                </label>
                {targets.length === 0 ? (
                  <p className="text-gray-500 text-sm">
                    No targets available. Create a target first.
                  </p>
                ) : (
                  <select
                    value={targetId}
                    onChange={(e) => setTargetId(e.target.value)}
                    className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-red-600 transition"
                  >
                    {targets.map((t: any) => (
                      <option key={t.id} value={t.id}>
                        {t.domain}
                      </option>
                    ))}
                  </select>
                )}
              </div>

              {/* Priority slider */}
              <div>
                <label className="text-xs text-gray-500 uppercase mb-1 block">
                  Priority: {priority}
                </label>
                <input
                  type="range"
                  min={1}
                  max={10}
                  value={priority}
                  onChange={(e) => setPriority(Number(e.target.value))}
                  className="w-full accent-red-600"
                />
                <div className="flex justify-between text-[10px] text-gray-600 mt-0.5">
                  <span>1 (Low)</span>
                  <span>10 (Critical)</span>
                </div>
              </div>
            </>
          )}
        </div>

        {/* Footer */}
        {!result && (
          <div className="flex items-center justify-end gap-2 p-5 border-t border-gray-800">
            <button
              onClick={onClose}
              className="px-4 py-2 rounded-lg bg-gray-800 hover:bg-gray-700 text-gray-300 text-sm transition"
            >
              Cancel
            </button>
            <button
              onClick={handleRun}
              disabled={!targetId || running}
              className={cn(
                "px-4 py-2 rounded-lg text-sm text-white transition flex items-center gap-2",
                !targetId || running
                  ? "bg-gray-700 text-gray-500 cursor-not-allowed"
                  : "bg-green-600 hover:bg-green-700"
              )}
            >
              <Play className="w-3.5 h-3.5" />
              {running ? "Launching..." : "Run Scan"}
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
