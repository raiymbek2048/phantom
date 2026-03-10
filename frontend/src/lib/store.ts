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
  isLoggedIn: true, // Auth disabled for development
  setToken: (token) => {
    localStorage.setItem("token", token);
    set({ token, isLoggedIn: true });
  },
  logout: () => {
    // Auth disabled — no-op
  },
  init: () => {
    // Auth disabled — always logged in
    set({ token: "dev", isLoggedIn: true });
  },
}));
