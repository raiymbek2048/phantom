import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

/** Parse server datetime (UTC without Z suffix) correctly */
export function parseUTC(date: string): Date {
  const utc = date.endsWith("Z") || date.includes("+") ? date : date + "Z";
  return new Date(utc);
}

export function timeAgo(date: string) {
  const seconds = Math.floor((Date.now() - parseUTC(date).getTime()) / 1000);
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

export function severityColor(severity: string) {
  const map: Record<string, string> = {
    critical: "text-red-400 bg-red-950 border-red-800",
    high: "text-orange-400 bg-orange-950 border-orange-800",
    medium: "text-yellow-400 bg-yellow-950 border-yellow-800",
    low: "text-blue-400 bg-blue-950 border-blue-800",
    info: "text-gray-400 bg-gray-800 border-gray-700",
  };
  return map[severity] || map.info;
}

export function statusColor(status: string) {
  const map: Record<string, string> = {
    running: "text-green-400",
    completed: "text-blue-400",
    failed: "text-red-400",
    queued: "text-yellow-400",
    stopped: "text-gray-400",
    paused: "text-yellow-400",
  };
  return map[status] || "text-gray-400";
}
