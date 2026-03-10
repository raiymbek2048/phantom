"use client";

import { useState, useEffect, useCallback } from "react";
import { useAuthStore } from "@/lib/store";
import LoginForm from "@/components/LoginForm";
import Sidebar from "@/components/Sidebar";
import { getTargets } from "@/lib/api";
import { timeAgo, cn } from "@/lib/utils";
import { Radar, Globe, ArrowRight, Search } from "lucide-react";
import Link from "next/link";

export default function ReconPage() {
  const { isLoggedIn, init } = useAuthStore();
  const [loaded, setLoaded] = useState(false);

  useEffect(() => { init(); setLoaded(true); }, [init]);
  if (!loaded) return null;
  if (!isLoggedIn) return <LoginForm />;

  return (
    <div className="flex">
      <Sidebar />
      <main className="ml-60 flex-1 min-h-screen p-6">
        <ReconListContent />
      </main>
    </div>
  );
}

function ReconListContent() {
  const [targets, setTargets] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");

  const load = useCallback(async () => {
    try {
      setTargets(await getTargets());
    } catch {}
    setLoading(false);
  }, []);

  useEffect(() => { load(); }, [load]);

  const filtered = targets.filter((t: any) =>
    t.domain.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-xl font-bold text-white flex items-center gap-2">
            <Radar className="w-5 h-5 text-red-400" />
            Recon Dashboard
          </h1>
          <p className="text-sm text-gray-500">
            Reconnaissance data for {targets.length} target{targets.length !== 1 ? "s" : ""}
          </p>
        </div>
        <div className="relative">
          <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search targets..."
            className="bg-gray-900 border border-gray-800 rounded-lg pl-9 pr-4 py-2 text-sm text-white focus:outline-none focus:border-red-500 w-64"
          />
        </div>
      </div>

      {loading ? (
        <div className="text-center py-20 text-gray-600">
          <Radar className="w-12 h-12 mx-auto mb-3 opacity-30 animate-spin" />
          <p>Loading targets...</p>
        </div>
      ) : filtered.length === 0 ? (
        <div className="text-center py-20 text-gray-600">
          <Globe className="w-12 h-12 mx-auto mb-3 opacity-30" />
          <p>{search ? "No targets match your search." : "No targets found. Add targets first."}</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {filtered.map((t: any) => (
            <Link
              key={t.id}
              href={`/recon/${t.id}`}
              className="bg-gray-900 rounded-xl border border-gray-800 p-5 hover:border-gray-600 transition group block"
            >
              <div className="flex items-start justify-between mb-3">
                <div>
                  <h3 className="text-white font-medium text-lg">{t.domain}</h3>
                  <p className="text-xs text-gray-600 mt-0.5">
                    {t.scope || "No scope defined"}
                  </p>
                </div>
                <span className={cn(
                  "text-[10px] px-2 py-0.5 rounded uppercase font-medium",
                  t.status === "active" ? "text-green-400 bg-green-950" : "text-gray-500 bg-gray-800"
                )}>
                  {t.status}
                </span>
              </div>

              <div className="grid grid-cols-3 gap-3 mb-4">
                <div className="text-center">
                  <p className="text-lg font-bold text-white">{t.subdomains?.length || 0}</p>
                  <p className="text-[10px] text-gray-600 uppercase">Subdomains</p>
                </div>
                <div className="text-center">
                  <p className="text-lg font-bold text-white">{Object.keys(t.technologies?.summary || {}).length || 0}</p>
                  <p className="text-[10px] text-gray-600 uppercase">Technologies</p>
                </div>
                <div className="text-center">
                  <p className="text-lg font-bold text-white">{t.scan_count || 0}</p>
                  <p className="text-[10px] text-gray-600 uppercase">Scans</p>
                </div>
              </div>

              <div className="flex items-center justify-between">
                <span className="text-[10px] text-gray-700">Added {timeAgo(t.created_at)}</span>
                <span className="text-red-400 text-sm flex items-center gap-1 opacity-0 group-hover:opacity-100 transition">
                  View Recon <ArrowRight className="w-3 h-3" />
                </span>
              </div>
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}
