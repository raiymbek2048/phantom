"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { cn } from "@/lib/utils";
import { useT, useI18nStore } from "@/lib/i18n";
import {
  LayoutDashboard,
  Target,
  Scan,
  ShieldAlert,
  Clock,
  Zap,
  Brain,
  Settings,
  FileText,
  Radar,
  ListOrdered,
  GitBranch,
  ScrollText,
  Bug,
  Trophy,
  Send,
  Globe,
  Bell,
  ShieldCheck,
} from "lucide-react";

const linkDefs = [
  { href: "/", labelKey: "nav.dashboard", icon: LayoutDashboard },
  { href: "/targets", labelKey: "nav.targets", icon: Target },
  { href: "/recon", labelKey: "nav.recon", icon: Radar },
  { href: "/scans", labelKey: "nav.scans", icon: Scan },
  { href: "/queue", labelKey: "nav.queue", icon: ListOrdered },
  { href: "/templates", labelKey: "nav.templates", icon: FileText },
  { href: "/vulnerabilities", labelKey: "nav.vulnerabilities", icon: ShieldAlert },
  { href: "/timeline", labelKey: "nav.timeline", icon: GitBranch },
  { href: "/validate", labelKey: "nav.validate", icon: ShieldCheck },
  { href: "/training", labelKey: "nav.command_center", icon: Brain },
  { href: "/bounty", labelKey: "nav.bounty", icon: Trophy },
  { href: "/bounty/programs", labelKey: "nav.programs", icon: Bug },
  { href: "/bounty/reports", labelKey: "nav.reports", icon: Send },
  { href: "/schedules", labelKey: "nav.schedules", icon: Clock },
  { href: "/notifications", labelKey: "nav.notifications", icon: Bell },
  { href: "/audit", labelKey: "nav.audit", icon: ScrollText },
  { href: "/settings", labelKey: "nav.settings", icon: Settings },
];

export default function Sidebar() {
  const pathname = usePathname();
  const t = useT();
  const { locale, setLocale } = useI18nStore();

  return (
    <aside className="w-60 bg-gray-950 border-r border-gray-800 flex flex-col h-screen fixed left-0 top-0">
      {/* Logo */}
      <div className="p-5 border-b border-gray-800">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-red-600 to-red-800 flex items-center justify-center">
            <Zap className="w-5 h-5 text-white" />
          </div>
          <div>
            <h1 className="text-lg font-bold text-white tracking-tight">PHANTOM</h1>
            <p className="text-[10px] text-gray-600 uppercase tracking-widest">{t("nav.ai_pentester")}</p>
          </div>
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 p-3 space-y-1 overflow-y-auto">
        {linkDefs.map(({ href, labelKey, icon: Icon }) => {
          const active = pathname === href || (href !== "/" && pathname.startsWith(href));
          return (
            <Link
              key={href}
              href={href}
              className={cn(
                "flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-colors",
                active
                  ? "bg-red-600/10 text-red-400 font-medium"
                  : "text-gray-500 hover:text-gray-300 hover:bg-gray-900"
              )}
            >
              <Icon className="w-4 h-4" />
              {t(labelKey)}
            </Link>
          );
        })}
      </nav>

      {/* Language Switcher + System Status */}
      <div className="p-4 border-t border-gray-800">
        {/* Language toggle */}
        <button
          onClick={() => setLocale(locale === "en" ? "ru" : "en")}
          className="flex items-center gap-2 w-full px-2 py-1.5 rounded-lg text-xs text-gray-500 hover:text-gray-300 hover:bg-gray-900 transition-colors mb-3"
        >
          <Globe className="w-3.5 h-3.5" />
          <span>{locale === "en" ? "🇷🇺 Русский" : "🇬🇧 English"}</span>
        </button>

        <p className="text-[10px] text-gray-600 uppercase tracking-wider mb-2">{t("nav.system")}</p>
        <div className="space-y-1.5 text-xs">
          <div className="flex justify-between items-center">
            <span className="text-gray-500">{t("nav.api")}</span>
            <span className="flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse" />
              <span className="text-gray-600">{t("nav.online")}</span>
            </span>
          </div>
          <div className="flex justify-between items-center">
            <span className="text-gray-500">{t("nav.ai_engine")}</span>
            <span className="flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse" />
              <span className="text-gray-600">{t("nav.active")}</span>
            </span>
          </div>
        </div>
      </div>
    </aside>
  );
}
