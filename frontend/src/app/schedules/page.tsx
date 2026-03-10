"use client";

import { useState, useEffect, useCallback } from "react";
import { useAuthStore } from "@/lib/store";
import LoginForm from "@/components/LoginForm";
import Sidebar from "@/components/Sidebar";
import { getSchedules, getTargets, createSchedule, deleteSchedule, updateSchedule } from "@/lib/api";
import { cn } from "@/lib/utils";
import { Clock, Trash2, Play, Pause, Plus } from "lucide-react";

export default function SchedulesPage() {
  const { isLoggedIn, init } = useAuthStore();
  const [loaded, setLoaded] = useState(false);

  useEffect(() => { init(); setLoaded(true); }, [init]);
  if (!loaded) return null;
  if (!isLoggedIn) return <LoginForm />;

  return (
    <div className="flex">
      <Sidebar />
      <main className="ml-60 flex-1 min-h-screen p-6">
        <ScheduleList />
      </main>
    </div>
  );
}

function ScheduleList() {
  const [schedules, setSchedules] = useState<any[]>([]);
  const [targets, setTargets] = useState<any[]>([]);
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState({ target_id: "", scan_type: "full", interval: "daily" });

  const load = useCallback(async () => {
    try {
      const [s, t] = await Promise.all([getSchedules(), getTargets()]);
      setSchedules(s);
      setTargets(t);
      if (t.length > 0 && !form.target_id) {
        setForm((f) => ({ ...f, target_id: t[0].id }));
      }
    } catch {}
  }, []);

  useEffect(() => { load(); }, [load]);

  const handleCreate = async () => {
    try {
      await createSchedule(form.target_id, form.scan_type, form.interval);
      setShowForm(false);
      load();
    } catch {}
  };

  const handleDelete = async (id: string) => {
    try {
      await deleteSchedule(id);
      load();
    } catch {}
  };

  const handleToggle = async (id: string, isActive: boolean) => {
    try {
      await updateSchedule(id, { is_active: !isActive });
      load();
    } catch {}
  };

  const getTargetDomain = (targetId: string) =>
    targets.find((t: any) => t.id === targetId)?.domain || "Unknown";

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white">Scheduled Scans</h1>
          <p className="text-sm text-gray-500">Automatic recurring scans via Celery Beat</p>
        </div>
        <button
          onClick={() => setShowForm(!showForm)}
          className="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-lg text-sm flex items-center gap-2 transition"
        >
          <Plus className="w-4 h-4" /> New Schedule
        </button>
      </div>

      {showForm && (
        <div className="bg-gray-900 rounded-xl border border-gray-800 p-5 space-y-4">
          <div className="grid grid-cols-3 gap-4">
            <div>
              <label className="text-xs text-gray-500 uppercase mb-1 block">Target</label>
              <select
                value={form.target_id}
                onChange={(e) => setForm({ ...form, target_id: e.target.value })}
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white"
              >
                {targets.map((t: any) => (
                  <option key={t.id} value={t.id}>{t.domain}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="text-xs text-gray-500 uppercase mb-1 block">Scan Type</label>
              <select
                value={form.scan_type}
                onChange={(e) => setForm({ ...form, scan_type: e.target.value })}
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white"
              >
                <option value="full">Full</option>
                <option value="quick">Quick</option>
                <option value="stealth">Stealth</option>
                <option value="recon">Recon Only</option>
              </select>
            </div>
            <div>
              <label className="text-xs text-gray-500 uppercase mb-1 block">Interval</label>
              <select
                value={form.interval}
                onChange={(e) => setForm({ ...form, interval: e.target.value })}
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white"
              >
                <option value="hourly">Hourly</option>
                <option value="daily">Daily</option>
                <option value="weekly">Weekly</option>
                <option value="monthly">Monthly</option>
              </select>
            </div>
          </div>
          <div className="flex gap-2">
            <button
              onClick={handleCreate}
              className="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-lg text-sm transition"
            >
              Create Schedule
            </button>
            <button
              onClick={() => setShowForm(false)}
              className="bg-gray-800 hover:bg-gray-700 text-gray-300 px-4 py-2 rounded-lg text-sm transition"
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      <div className="space-y-2">
        {schedules.length === 0 && (
          <div className="bg-gray-900 rounded-xl border border-gray-800 p-8 text-center">
            <Clock className="w-8 h-8 text-gray-700 mx-auto mb-2" />
            <p className="text-gray-500 text-sm">No scheduled scans yet</p>
          </div>
        )}
        {schedules.map((s: any) => (
          <div key={s.id} className="bg-gray-900 rounded-xl border border-gray-800 p-4 flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div className={cn(
                "w-2 h-2 rounded-full",
                s.is_active ? "bg-green-500 animate-pulse" : "bg-gray-600"
              )} />
              <div>
                <p className="text-white font-medium text-sm">{getTargetDomain(s.target_id)}</p>
                <p className="text-xs text-gray-500">
                  {s.scan_type} &middot; {s.interval}
                  {s.next_run_at && ` · Next: ${new Date(s.next_run_at).toLocaleString()}`}
                </p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={() => handleToggle(s.id, s.is_active)}
                className={cn(
                  "p-2 rounded-lg text-sm transition",
                  s.is_active
                    ? "bg-yellow-600/20 text-yellow-400 hover:bg-yellow-600/30"
                    : "bg-green-600/20 text-green-400 hover:bg-green-600/30"
                )}
                title={s.is_active ? "Pause" : "Resume"}
              >
                {s.is_active ? <Pause className="w-4 h-4" /> : <Play className="w-4 h-4" />}
              </button>
              <button
                onClick={() => handleDelete(s.id)}
                className="p-2 rounded-lg bg-red-600/20 text-red-400 hover:bg-red-600/30 transition"
                title="Delete"
              >
                <Trash2 className="w-4 h-4" />
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
