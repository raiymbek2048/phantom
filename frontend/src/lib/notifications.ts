import { create } from "zustand";

export interface Notification {
  id: string;
  type: "success" | "error" | "warning" | "info" | "vuln";
  title: string;
  message?: string;
  severity?: string;
  duration?: number;
  timestamp: number;
}

interface NotificationStore {
  notifications: Notification[];
  add: (n: Omit<Notification, "id" | "timestamp">) => void;
  remove: (id: string) => void;
  clear: () => void;
}

const MAX_VISIBLE = 5;

export const useNotifications = create<NotificationStore>((set, get) => ({
  notifications: [],

  add: (n) => {
    const id = `${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
    const duration = n.duration ?? 5000;
    const notification: Notification = { ...n, id, timestamp: Date.now() };

    set((state) => ({
      notifications: [...state.notifications, notification].slice(-MAX_VISIBLE),
    }));

    if (duration > 0) {
      setTimeout(() => {
        get().remove(id);
      }, duration);
    }
  },

  remove: (id) => {
    set((state) => ({
      notifications: state.notifications.filter((n) => n.id !== id),
    }));
  },

  clear: () => {
    set({ notifications: [] });
  },
}));
