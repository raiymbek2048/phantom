"use client";

import { cn, statusColor } from "@/lib/utils";
import { useT } from "@/lib/i18n";

const PHASE_KEYS = [
  "recon", "subdomain", "portscan", "fingerprint", "endpoint",
  "app_graph", "stateful_crawl", "sensitive_files", "vuln_scan", "nuclei",
  "ai_analysis", "payload_gen", "waf", "exploit", "service_attack",
  "auth_attack", "business_logic", "stress_test", "vuln_confirm",
  "claude_collab", "evidence", "report",
];

interface Props {
  currentPhase: string;
  progress: number;
  status: string;
}

export default function ScanProgress({ currentPhase, progress, status }: Props) {
  const t = useT();
  const currentIndex = PHASE_KEYS.indexOf(currentPhase);

  return (
    <div>
      {/* Progress bar */}
      <div className="flex items-center gap-3 mb-4">
        <div className="flex-1 bg-gray-800 rounded-full h-2 overflow-hidden">
          <div
            className={cn(
              "h-full rounded-full transition-all duration-500",
              status === "completed" ? "bg-green-500" :
              status === "failed" ? "bg-red-500" :
              "bg-red-600"
            )}
            style={{ width: `${progress}%` }}
          />
        </div>
        <span className={cn("text-sm font-mono", statusColor(status))}>
          {progress.toFixed(0)}%
        </span>
      </div>

      {/* Phase indicators */}
      <div className="flex gap-1">
        {PHASE_KEYS.map((key, i) => {
          const done = i < currentIndex || status === "completed";
          const active = i === currentIndex && status === "running";
          return (
            <div key={key} className="text-center flex-1">
              <div
                className={cn(
                  "h-1.5 rounded-full mb-1 transition-all",
                  done ? "bg-green-600" :
                  active ? "bg-red-500 animate-pulse" :
                  "bg-gray-800"
                )}
              />
              <span className={cn(
                "text-[9px] leading-none",
                done ? "text-green-600" :
                active ? "text-red-400" :
                "text-gray-700"
              )}>
                {t(`phase.${key}`)}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
