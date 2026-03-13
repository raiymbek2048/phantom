import { create } from "zustand";

interface AuthStore {
  token: string | null;
  isLoggedIn: boolean;
  setToken: (token: string) => void;
  logout: () => void;
  init: () => void;
}

export const useAuthStore = create<AuthStore>((set) => ({
  token: null,
  isLoggedIn: true, // Auth disabled — internal server only
  setToken: (token) => {
    localStorage.setItem("token", token);
    set({ token, isLoggedIn: true });
  },
  logout: () => {
    // No-op — auth disabled
  },
  init: () => {
    // Always logged in — no auth required
    set({ isLoggedIn: true });
  },
}));
