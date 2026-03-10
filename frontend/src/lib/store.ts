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
  isLoggedIn: false,
  setToken: (token) => {
    localStorage.setItem("token", token);
    set({ token, isLoggedIn: true });
  },
  logout: () => {
    localStorage.removeItem("token");
    set({ token: null, isLoggedIn: false });
  },
  init: () => {
    const token = typeof window !== "undefined" ? localStorage.getItem("token") : null;
    if (token) {
      set({ token, isLoggedIn: true });
    } else {
      set({ token: null, isLoggedIn: false });
    }
  },
}));
