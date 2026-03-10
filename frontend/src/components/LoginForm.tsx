"use client";

import { useState } from "react";
import { login, register } from "@/lib/api";
import { useAuthStore } from "@/lib/store";
import { useT } from "@/lib/i18n";
import { Zap } from "lucide-react";

export default function LoginForm() {
  const [isRegister, setIsRegister] = useState(false);
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const { setToken } = useAuthStore();
  const t = useT();

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setLoading(true);

    try {
      if (isRegister) {
        await register(username, email, password);
      }
      const data = await login(username, password);
      setToken(data.access_token);
    } catch (err: any) {
      setError(err.response?.data?.detail || t("auth.failed"));
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen bg-gray-950 flex items-center justify-center">
      <div className="w-full max-w-sm">
        {/* Logo */}
        <div className="text-center mb-8">
          <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-red-600 to-red-800 flex items-center justify-center mx-auto mb-4">
            <Zap className="w-8 h-8 text-white" />
          </div>
          <h1 className="text-2xl font-bold text-white">PHANTOM</h1>
          <p className="text-sm text-gray-600 mt-1">{t("auth.subtitle")}</p>
        </div>

        <form onSubmit={handleSubmit} className="bg-gray-900 rounded-xl border border-gray-800 p-6 space-y-4">
          <h2 className="text-lg font-semibold text-center">
            {isRegister ? t("auth.create_account") : t("auth.sign_in")}
          </h2>

          {error && (
            <div className="bg-red-950/50 border border-red-800 rounded-lg px-3 py-2 text-sm text-red-400">
              {error}
            </div>
          )}

          <div>
            <label className="text-xs text-gray-500 mb-1 block">{t("auth.username")}</label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-red-500"
              required
            />
          </div>

          {isRegister && (
            <div>
              <label className="text-xs text-gray-500 mb-1 block">{t("auth.email")}</label>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-red-500"
                required
              />
            </div>
          )}

          <div>
            <label className="text-xs text-gray-500 mb-1 block">{t("auth.password")}</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-red-500"
              required
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full bg-red-600 hover:bg-red-700 disabled:opacity-50 text-white py-2.5 rounded-lg font-medium text-sm transition"
          >
            {loading ? "..." : isRegister ? t("auth.create_account") : t("auth.sign_in")}
          </button>

          <p className="text-center text-xs text-gray-600">
            {isRegister ? t("auth.has_account") : t("auth.no_account")}{" "}
            <button
              type="button"
              onClick={() => { setIsRegister(!isRegister); setError(""); }}
              className="text-red-400 hover:text-red-300"
            >
              {isRegister ? t("auth.sign_in") : t("auth.register")}
            </button>
          </p>
        </form>
      </div>
    </div>
  );
}
