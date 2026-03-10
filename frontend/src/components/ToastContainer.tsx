"use client";

import { useEffect, useState } from "react";
import { useNotifications, type Notification } from "@/lib/notifications";
import { severityColor, cn } from "@/lib/utils";
import {
  CheckCircle,
  XCircle,
  AlertTriangle,
  Info,
  ShieldAlert,
  X,
} from "lucide-react";

const iconMap = {
  success: CheckCircle,
  error: XCircle,
  warning: AlertTriangle,
  info: Info,
  vuln: ShieldAlert,
};

const borderColorMap: Record<string, string> = {
  success: "border-l-green-500",
  error: "border-l-red-500",
  warning: "border-l-yellow-500",
  info: "border-l-blue-500",
  vuln: "border-l-red-500",
};

const iconColorMap: Record<string, string> = {
  success: "text-green-400",
  error: "text-red-400",
  warning: "text-yellow-400",
  info: "text-blue-400",
  vuln: "text-red-400",
};

function Toast({ notification }: { notification: Notification }) {
  const remove = useNotifications((s) => s.remove);
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    // Trigger slide-in on mount
    const frame = requestAnimationFrame(() => setVisible(true));
    return () => cancelAnimationFrame(frame);
  }, []);

  function handleClose() {
    setVisible(false);
    setTimeout(() => remove(notification.id), 200);
  }

  const Icon = iconMap[notification.type];
  const isVuln = notification.type === "vuln";
  const sevClasses = isVuln && notification.severity
    ? severityColor(notification.severity)
    : "";

  return (
    <div
      className={cn(
        "relative w-80 bg-gray-900 border border-gray-800 border-l-4 rounded-lg shadow-lg shadow-black/40 p-4 transition-all duration-200 ease-out",
        borderColorMap[notification.type],
        visible
          ? "translate-x-0 opacity-100"
          : "translate-x-full opacity-0"
      )}
    >
      <div className="flex items-start gap-3">
        <Icon className={cn("w-5 h-5 flex-shrink-0 mt-0.5", iconColorMap[notification.type])} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <p className="text-sm font-medium text-white truncate">
              {notification.title}
            </p>
            {isVuln && notification.severity && (
              <span
                className={cn(
                  "text-[9px] px-1.5 py-0.5 rounded border font-bold uppercase tracking-wide whitespace-nowrap",
                  sevClasses
                )}
              >
                {notification.severity}
              </span>
            )}
          </div>
          {notification.message && (
            <p className="text-xs text-gray-400 mt-1 line-clamp-2">
              {notification.message}
            </p>
          )}
        </div>
        <button
          onClick={handleClose}
          className="text-gray-600 hover:text-gray-300 transition flex-shrink-0"
        >
          <X className="w-4 h-4" />
        </button>
      </div>
    </div>
  );
}

export default function ToastContainer() {
  const notifications = useNotifications((s) => s.notifications);

  if (notifications.length === 0) return null;

  return (
    <div className="fixed bottom-4 right-4 z-50 flex flex-col gap-2">
      {notifications.map((n) => (
        <Toast key={n.id} notification={n} />
      ))}
    </div>
  );
}
