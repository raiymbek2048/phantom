"use client";

import { useState, useEffect } from "react";
import { useParams } from "next/navigation";
import { useAuthStore } from "@/lib/store";
import LoginForm from "@/components/LoginForm";
import Sidebar from "@/components/Sidebar";
import { getScanGraph, getScan } from "@/lib/api";
import { useT } from "@/lib/i18n";
import { cn } from "@/lib/utils";
import Link from "next/link";
import {
  ArrowLeft,
  Network,
  Shield,
  Lock,
  Code,
  ChevronDown,
  ChevronRight,
  AlertTriangle,
  Layers,
  ArrowRight,
} from "lucide-react";

export default function GraphPage() {
  const { isLoggedIn, init } = useAuthStore();
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    init();
    setLoaded(true);
  }, [init]);
  if (!loaded) return null;
  if (!isLoggedIn) return <LoginForm />;

  return (
    <div className="flex">
      <Sidebar />
      <main className="ml-60 flex-1 min-h-screen p-6">
        <GraphContent />
      </main>
    </div>
  );
}

function GraphContent() {
  const { id } = useParams();
  const t = useT();
  const [graph, setGraph] = useState<any>(null);
  const [scan, setScan] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [activeSection, setActiveSection] = useState("entities");

  useEffect(() => {
    async function load() {
      try {
        const [g, s] = await Promise.all([
          getScanGraph(id as string),
          getScan(id as string),
        ]);
        setGraph(g);
        setScan(s);
      } catch {
      } finally {
        setLoading(false);
      }
    }
    load();
  }, [id]);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-gray-500 animate-pulse">{t("common.loading")}</div>
      </div>
    );
  }

  const isEmpty =
    !graph ||
    (Object.keys(graph).length === 0 &&
      (!graph.entities || graph.entities?.length === 0));

  const sections = [
    { id: "entities", label: t("graph.entity_map"), icon: Layers },
    { id: "attack_paths", label: t("graph.attack_paths"), icon: AlertTriangle },
    { id: "relationships", label: t("graph.relationships"), icon: Network },
    { id: "auth_flows", label: t("graph.auth_flows"), icon: Lock },
    { id: "api_patterns", label: t("graph.api_patterns"), icon: Code },
  ];

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Link
            href={`/scans/${id}`}
            className="text-gray-500 hover:text-white transition"
          >
            <ArrowLeft className="w-5 h-5" />
          </Link>
          <div>
            <h1 className="text-xl font-bold text-white">
              {t("graph.title")}
            </h1>
            <p className="text-xs text-gray-500">{t("graph.subtitle")}</p>
          </div>
        </div>
        <Link
          href={`/scans/${id}`}
          className="bg-gray-800 hover:bg-gray-700 text-gray-300 px-4 py-2 rounded-lg text-sm flex items-center gap-2 transition"
        >
          <ArrowLeft className="w-4 h-4" /> {t("graph.back_to_scan")}
        </Link>
      </div>

      {isEmpty ? (
        <div className="bg-[#12121a] border border-[#1e1e2e] rounded-xl p-12 text-center">
          <Network className="w-12 h-12 text-gray-600 mx-auto mb-4" />
          <p className="text-gray-400 text-lg mb-2">{t("graph.no_data")}</p>
          <p className="text-gray-600 text-sm">{t("graph.no_data_hint")}</p>
        </div>
      ) : (
        <>
          {/* Section Tabs */}
          <div className="flex gap-1 border-b border-gray-800 pb-0">
            {sections.map(({ id: sid, label, icon: Icon }) => (
              <button
                key={sid}
                onClick={() => setActiveSection(sid)}
                className={cn(
                  "flex items-center gap-2 px-4 py-2.5 text-sm border-b-2 transition-colors -mb-[1px]",
                  activeSection === sid
                    ? "border-purple-500 text-purple-400"
                    : "border-transparent text-gray-500 hover:text-gray-300"
                )}
              >
                <Icon className="w-4 h-4" />
                {label}
              </button>
            ))}
          </div>

          {/* Section Content */}
          <div className="mt-4">
            {activeSection === "entities" && (
              <EntityMap entities={graph.entities} t={t} />
            )}
            {activeSection === "attack_paths" && (
              <AttackPaths paths={graph.attack_paths} t={t} />
            )}
            {activeSection === "relationships" && (
              <Relationships relationships={graph.relationships} t={t} />
            )}
            {activeSection === "auth_flows" && (
              <AuthFlows flows={graph.auth_flows} t={t} />
            )}
            {activeSection === "api_patterns" && (
              <ApiPatterns patterns={graph.api_patterns} t={t} />
            )}
          </div>
        </>
      )}
    </div>
  );
}

/* ===============================
   A. Entity Map
   =============================== */

const METHOD_COLORS: Record<string, string> = {
  GET: "bg-green-600/20 text-green-400 border-green-800/50",
  POST: "bg-blue-600/20 text-blue-400 border-blue-800/50",
  PUT: "bg-yellow-600/20 text-yellow-400 border-yellow-800/50",
  PATCH: "bg-orange-600/20 text-orange-400 border-orange-800/50",
  DELETE: "bg-red-600/20 text-red-400 border-red-800/50",
  HEAD: "bg-gray-600/20 text-gray-400 border-gray-800/50",
  OPTIONS: "bg-gray-600/20 text-gray-400 border-gray-800/50",
};

function EntityMap({
  entities,
  t,
}: {
  entities: any[] | undefined;
  t: (key: string) => string;
}) {
  if (!entities || entities.length === 0) {
    return <EmptyState message={t("graph.no_entities")} />;
  }

  return (
    <div>
      <div className="text-sm text-gray-500 mb-3">
        {entities.length} {t("graph.entities")}
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
        {entities.map((entity: any, idx: number) => {
          const methods = entity.methods || [];
          const endpointCount =
            entity.endpoints?.length || entity.endpoint_count || 0;
          const saturation = Math.min(methods.length * 15 + 20, 100);

          return (
            <div
              key={idx}
              className="bg-[#12121a] border border-[#1e1e2e] rounded-xl p-5 hover:border-purple-800/50 transition-colors"
              style={{
                borderLeftWidth: "3px",
                borderLeftColor: `hsl(270, ${saturation}%, 50%)`,
              }}
            >
              {/* Entity name */}
              <div className="flex items-center justify-between mb-3">
                <h3 className="text-white font-semibold text-base truncate">
                  {entity.name || entity.entity || "Unknown"}
                </h3>
                <span className="text-xs text-gray-500 bg-[#0a0a0f] px-2 py-1 rounded">
                  {endpointCount} {t("graph.endpoints")}
                </span>
              </div>

              {/* Methods */}
              {methods.length > 0 && (
                <div className="mb-3">
                  <div className="text-[10px] text-gray-600 uppercase tracking-wider mb-1.5">
                    {t("graph.methods")}
                  </div>
                  <div className="flex flex-wrap gap-1.5">
                    {methods.map((m: string) => (
                      <span
                        key={m}
                        className={cn(
                          "text-[10px] font-bold px-2 py-0.5 rounded border",
                          METHOD_COLORS[m.toUpperCase()] ||
                            "bg-gray-600/20 text-gray-400 border-gray-800/50"
                        )}
                      >
                        {m.toUpperCase()}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Parameters */}
              {entity.parameters && entity.parameters.length > 0 && (
                <div>
                  <div className="text-[10px] text-gray-600 uppercase tracking-wider mb-1.5">
                    {t("graph.parameters")}
                  </div>
                  <div className="flex flex-wrap gap-1">
                    {entity.parameters
                      .slice(0, 10)
                      .map((p: string, pi: number) => (
                        <span
                          key={pi}
                          className="text-xs bg-[#0a0a0f] text-gray-400 px-2 py-0.5 rounded font-mono"
                        >
                          {typeof p === "string" ? p : p?.name || String(p)}
                        </span>
                      ))}
                    {entity.parameters.length > 10 && (
                      <span className="text-xs text-gray-600">
                        +{entity.parameters.length - 10}
                      </span>
                    )}
                  </div>
                </div>
              )}

              {/* Endpoints list (collapsed) */}
              {entity.endpoints && entity.endpoints.length > 0 && (
                <CollapsibleEndpoints endpoints={entity.endpoints} />
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

function CollapsibleEndpoints({ endpoints }: { endpoints: any[] }) {
  const [open, setOpen] = useState(false);

  return (
    <div className="mt-3 pt-3 border-t border-[#1e1e2e]">
      <button
        onClick={() => setOpen(!open)}
        className="flex items-center gap-1 text-xs text-gray-500 hover:text-gray-300 transition"
      >
        {open ? (
          <ChevronDown className="w-3 h-3" />
        ) : (
          <ChevronRight className="w-3 h-3" />
        )}
        {endpoints.length} endpoints
      </button>
      {open && (
        <div className="mt-2 space-y-1 max-h-40 overflow-y-auto">
          {endpoints.map((ep: any, i: number) => (
            <div
              key={i}
              className="text-xs font-mono text-gray-500 flex items-center gap-2"
            >
              {ep.method && (
                <span
                  className={cn(
                    "text-[9px] font-bold px-1.5 py-0.5 rounded",
                    METHOD_COLORS[ep.method?.toUpperCase()] ||
                      "text-gray-400"
                  )}
                >
                  {ep.method}
                </span>
              )}
              <span className="truncate">{ep.url || ep.path || ep}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

/* ===============================
   B. Attack Paths
   =============================== */

const RISK_STYLES: Record<string, string> = {
  critical:
    "bg-red-600/20 text-red-400 border-red-800/50 shadow-red-900/20 shadow-lg",
  high: "bg-orange-600/20 text-orange-400 border-orange-800/50",
  medium: "bg-yellow-600/20 text-yellow-400 border-yellow-800/50",
  low: "bg-blue-600/20 text-blue-400 border-blue-800/50",
  info: "bg-gray-600/20 text-gray-400 border-gray-800/50",
};

function AttackPaths({
  paths,
  t,
}: {
  paths: any[] | undefined;
  t: (key: string) => string;
}) {
  const [expandedIdx, setExpandedIdx] = useState<number | null>(null);

  if (!paths || paths.length === 0) {
    return <EmptyState message={t("graph.no_attack_paths")} />;
  }

  return (
    <div className="space-y-4">
      {paths.map((path: any, idx: number) => {
        const risk = (
          path.risk ||
          path.severity ||
          "medium"
        ).toLowerCase();
        const steps = path.steps || path.chain || [];
        const isExpanded = expandedIdx === idx;

        return (
          <div
            key={idx}
            className="bg-[#12121a] border border-[#1e1e2e] rounded-xl overflow-hidden"
          >
            {/* Path header */}
            <button
              onClick={() => setExpandedIdx(isExpanded ? null : idx)}
              className="w-full flex items-center gap-4 p-5 text-left hover:bg-[#16161f] transition-colors"
            >
              {/* Risk badge */}
              <span
                className={cn(
                  "text-[10px] font-bold px-3 py-1 rounded border uppercase shrink-0",
                  RISK_STYLES[risk] || RISK_STYLES.medium
                )}
              >
                {risk}
              </span>

              {/* Path name / description */}
              <div className="flex-1 min-w-0">
                <div className="text-white font-medium text-sm truncate">
                  {path.name ||
                    path.description ||
                    path.title ||
                    `Attack Path ${idx + 1}`}
                </div>
                {path.description && path.name && (
                  <div className="text-xs text-gray-500 mt-0.5 truncate">
                    {path.description}
                  </div>
                )}
              </div>

              {/* Step count */}
              <span className="text-xs text-gray-600 shrink-0">
                {steps.length} {t("graph.steps")}
              </span>

              {isExpanded ? (
                <ChevronDown className="w-4 h-4 text-gray-500 shrink-0" />
              ) : (
                <ChevronRight className="w-4 h-4 text-gray-500 shrink-0" />
              )}
            </button>

            {/* Flow diagram (always visible as mini) */}
            <div className="px-5 pb-4">
              <div className="flex items-center gap-1 overflow-x-auto pb-2">
                {steps.map((step: any, si: number) => (
                  <div key={si} className="flex items-center shrink-0">
                    <div className="bg-[#0a0a0f] border border-[#1e1e2e] rounded-lg px-3 py-2 text-center min-w-[120px]">
                      {step.method && (
                        <span
                          className={cn(
                            "text-[9px] font-bold px-1.5 py-0.5 rounded inline-block mb-1",
                            METHOD_COLORS[step.method?.toUpperCase()] ||
                              "text-gray-400"
                          )}
                        >
                          {step.method}
                        </span>
                      )}
                      <div className="text-xs text-gray-300 font-mono truncate max-w-[160px]">
                        {step.endpoint ||
                          step.url ||
                          step.path ||
                          step.action ||
                          (typeof step === "string" ? step : JSON.stringify(step))}
                      </div>
                    </div>
                    {si < steps.length - 1 && (
                      <ArrowRight className="w-4 h-4 text-purple-600 mx-1 shrink-0" />
                    )}
                  </div>
                ))}
              </div>
            </div>

            {/* Expanded details */}
            {isExpanded && (
              <div className="border-t border-[#1e1e2e] p-5 bg-[#0e0e15]">
                {path.impact && (
                  <div className="mb-3">
                    <div className="text-[10px] text-gray-600 uppercase tracking-wider mb-1">
                      Impact
                    </div>
                    <p className="text-sm text-gray-300">{path.impact}</p>
                  </div>
                )}
                {path.prerequisites && (
                  <div className="mb-3">
                    <div className="text-[10px] text-gray-600 uppercase tracking-wider mb-1">
                      Prerequisites
                    </div>
                    <p className="text-sm text-gray-400">
                      {Array.isArray(path.prerequisites)
                        ? path.prerequisites.join(", ")
                        : path.prerequisites}
                    </p>
                  </div>
                )}
                {/* Detailed steps */}
                <div className="text-[10px] text-gray-600 uppercase tracking-wider mb-2">
                  Detailed Steps
                </div>
                <div className="space-y-2">
                  {steps.map((step: any, si: number) => (
                    <div
                      key={si}
                      className="flex items-start gap-3 text-sm"
                    >
                      <span className="w-5 h-5 rounded-full bg-purple-900/30 text-purple-400 text-[10px] flex items-center justify-center shrink-0 mt-0.5">
                        {si + 1}
                      </span>
                      <div className="min-w-0">
                        <span className="text-gray-300 font-mono text-xs">
                          {step.method && `${step.method} `}
                          {step.endpoint || step.url || step.path || step.action || String(step)}
                        </span>
                        {step.description && (
                          <p className="text-gray-500 text-xs mt-0.5">
                            {step.description}
                          </p>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

/* ===============================
   C. Relationships
   =============================== */

function Relationships({
  relationships,
  t,
}: {
  relationships: any[] | undefined;
  t: (key: string) => string;
}) {
  if (!relationships || relationships.length === 0) {
    return <EmptyState message={t("graph.no_relationships")} />;
  }

  return (
    <div className="bg-[#12121a] border border-[#1e1e2e] rounded-xl overflow-hidden">
      <table className="w-full">
        <thead>
          <tr className="text-[10px] text-gray-600 uppercase tracking-wider bg-[#0a0a0f]">
            <th className="text-left px-5 py-3">{t("graph.from")}</th>
            <th className="text-left px-5 py-3">{t("graph.relationship")}</th>
            <th className="text-left px-5 py-3">{t("graph.to")}</th>
            <th className="text-left px-5 py-3">{t("graph.via_endpoint")}</th>
          </tr>
        </thead>
        <tbody>
          {relationships.map((rel: any, idx: number) => (
            <tr
              key={idx}
              className="border-t border-[#1e1e2e] hover:bg-[#16161f] transition-colors"
            >
              <td className="px-5 py-3">
                <span className="text-white text-sm font-medium">
                  {rel.from || rel.source || rel.parent || "—"}
                </span>
              </td>
              <td className="px-5 py-3">
                <span className="text-xs bg-purple-900/20 text-purple-400 border border-purple-800/30 px-2 py-0.5 rounded font-mono">
                  {rel.type ||
                    rel.relationship ||
                    rel.relation ||
                    "references"}
                </span>
              </td>
              <td className="px-5 py-3">
                <span className="text-white text-sm font-medium">
                  {rel.to || rel.target || rel.child || "—"}
                </span>
              </td>
              <td className="px-5 py-3">
                <span className="text-xs text-gray-500 font-mono truncate block max-w-[250px]">
                  {rel.via || rel.endpoint || rel.through || "—"}
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/* ===============================
   D. Auth Flows
   =============================== */

const AUTH_TYPE_COLORS: Record<string, string> = {
  login: "bg-green-600/20 text-green-400 border-green-800/50",
  oauth: "bg-blue-600/20 text-blue-400 border-blue-800/50",
  registration: "bg-purple-600/20 text-purple-400 border-purple-800/50",
  signup: "bg-purple-600/20 text-purple-400 border-purple-800/50",
  sso: "bg-cyan-600/20 text-cyan-400 border-cyan-800/50",
  mfa: "bg-yellow-600/20 text-yellow-400 border-yellow-800/50",
  "2fa": "bg-yellow-600/20 text-yellow-400 border-yellow-800/50",
  logout: "bg-red-600/20 text-red-400 border-red-800/50",
  "password-reset": "bg-orange-600/20 text-orange-400 border-orange-800/50",
};

function AuthFlows({
  flows,
  t,
}: {
  flows: any[] | undefined;
  t: (key: string) => string;
}) {
  if (!flows || flows.length === 0) {
    return <EmptyState message={t("graph.no_auth_flows")} />;
  }

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
      {flows.map((flow: any, idx: number) => {
        const flowType = (
          flow.type ||
          flow.flow_type ||
          "unknown"
        ).toLowerCase();
        const endpoints = flow.endpoints || flow.involved_endpoints || [];
        const tokenTypes = flow.token_types || flow.tokens || [];

        return (
          <div
            key={idx}
            className="bg-[#12121a] border border-[#1e1e2e] rounded-xl p-5"
          >
            {/* Flow type badge */}
            <div className="flex items-center gap-3 mb-4">
              <Lock className="w-5 h-5 text-purple-500" />
              <span
                className={cn(
                  "text-xs font-bold px-3 py-1 rounded border uppercase",
                  AUTH_TYPE_COLORS[flowType] ||
                    "bg-gray-600/20 text-gray-400 border-gray-800/50"
                )}
              >
                {flowType}
              </span>
              {flow.name && (
                <span className="text-sm text-white font-medium">
                  {flow.name}
                </span>
              )}
            </div>

            {/* Involved endpoints */}
            {endpoints.length > 0 && (
              <div className="mb-3">
                <div className="text-[10px] text-gray-600 uppercase tracking-wider mb-1.5">
                  {t("graph.involved_endpoints")}
                </div>
                <div className="space-y-1">
                  {endpoints.map((ep: any, ei: number) => (
                    <div
                      key={ei}
                      className="text-xs font-mono text-gray-400 bg-[#0a0a0f] px-3 py-1.5 rounded flex items-center gap-2"
                    >
                      {(ep.method || ep.verb) && (
                        <span
                          className={cn(
                            "text-[9px] font-bold px-1.5 py-0.5 rounded",
                            METHOD_COLORS[
                              (ep.method || ep.verb)?.toUpperCase()
                            ] || "text-gray-400"
                          )}
                        >
                          {ep.method || ep.verb}
                        </span>
                      )}
                      <span className="truncate">
                        {ep.url || ep.path || ep.endpoint || (typeof ep === "string" ? ep : JSON.stringify(ep))}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Token types */}
            {tokenTypes.length > 0 && (
              <div>
                <div className="text-[10px] text-gray-600 uppercase tracking-wider mb-1.5">
                  {t("graph.token_types")}
                </div>
                <div className="flex flex-wrap gap-1.5">
                  {tokenTypes.map((tt: string, ti: number) => (
                    <span
                      key={ti}
                      className="text-xs bg-[#0a0a0f] text-cyan-400 px-2 py-0.5 rounded border border-cyan-900/30"
                    >
                      {typeof tt === "string" ? tt : String(tt)}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Description */}
            {flow.description && (
              <p className="text-xs text-gray-500 mt-3">
                {flow.description}
              </p>
            )}
          </div>
        );
      })}
    </div>
  );
}

/* ===============================
   E. API Patterns
   =============================== */

function ApiPatterns({
  patterns,
  t,
}: {
  patterns: any | undefined;
  t: (key: string) => string;
}) {
  if (!patterns || Object.keys(patterns).length === 0) {
    return <EmptyState message={t("graph.no_api_patterns")} />;
  }

  const restCrud = patterns.rest_crud || patterns.crud_entities || [];
  const graphqlEndpoints =
    patterns.graphql || patterns.graphql_endpoints || [];
  const rpcEndpoints = patterns.rpc || patterns.rpc_endpoints || [];
  const apiVersions =
    patterns.api_versions || patterns.versions || [];

  const hasData =
    restCrud.length > 0 ||
    graphqlEndpoints.length > 0 ||
    rpcEndpoints.length > 0 ||
    apiVersions.length > 0;

  if (!hasData) {
    // Patterns might be in a flat structure, render it as a generic list
    return (
      <div className="bg-[#12121a] border border-[#1e1e2e] rounded-xl p-5">
        <div className="space-y-3">
          {Object.entries(patterns).map(([key, value]: [string, any]) => (
            <div key={key}>
              <div className="text-xs text-gray-600 uppercase tracking-wider mb-1">
                {key.replace(/_/g, " ")}
              </div>
              <div className="text-sm text-gray-300">
                {Array.isArray(value) ? (
                  <div className="flex flex-wrap gap-1.5">
                    {value.map((v: any, i: number) => (
                      <span
                        key={i}
                        className="bg-[#0a0a0f] text-gray-400 px-2 py-0.5 rounded text-xs font-mono"
                      >
                        {typeof v === "string" ? v : JSON.stringify(v)}
                      </span>
                    ))}
                  </div>
                ) : typeof value === "object" ? (
                  <pre className="text-xs text-gray-500 font-mono bg-[#0a0a0f] p-2 rounded overflow-auto max-h-40">
                    {JSON.stringify(value, null, 2)}
                  </pre>
                ) : (
                  <span>{String(value)}</span>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* REST CRUD */}
      {restCrud.length > 0 && (
        <div className="bg-[#12121a] border border-[#1e1e2e] rounded-xl p-5">
          <div className="flex items-center gap-2 mb-4">
            <Code className="w-4 h-4 text-green-500" />
            <h3 className="text-white font-semibold text-sm">
              {t("graph.rest_crud")}
            </h3>
            <span className="text-xs text-gray-600">
              {restCrud.length} {t("graph.entities")}
            </span>
          </div>
          <div className="flex flex-wrap gap-2">
            {restCrud.map((entity: any, idx: number) => (
              <span
                key={idx}
                className="bg-green-900/10 text-green-400 border border-green-800/30 px-3 py-1.5 rounded-lg text-sm font-mono"
              >
                {typeof entity === "string"
                  ? entity
                  : entity.name || entity.entity || JSON.stringify(entity)}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* GraphQL */}
      {graphqlEndpoints.length > 0 && (
        <div className="bg-[#12121a] border border-[#1e1e2e] rounded-xl p-5">
          <div className="flex items-center gap-2 mb-4">
            <Code className="w-4 h-4 text-pink-500" />
            <h3 className="text-white font-semibold text-sm">
              {t("graph.graphql")}
            </h3>
          </div>
          <div className="space-y-1.5">
            {graphqlEndpoints.map((ep: any, idx: number) => (
              <div
                key={idx}
                className="text-xs font-mono text-gray-400 bg-[#0a0a0f] px-3 py-2 rounded"
              >
                {typeof ep === "string"
                  ? ep
                  : ep.url || ep.endpoint || JSON.stringify(ep)}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* RPC */}
      {rpcEndpoints.length > 0 && (
        <div className="bg-[#12121a] border border-[#1e1e2e] rounded-xl p-5">
          <div className="flex items-center gap-2 mb-4">
            <Code className="w-4 h-4 text-yellow-500" />
            <h3 className="text-white font-semibold text-sm">
              {t("graph.rpc")}
            </h3>
          </div>
          <div className="space-y-1.5">
            {rpcEndpoints.map((ep: any, idx: number) => (
              <div
                key={idx}
                className="text-xs font-mono text-gray-400 bg-[#0a0a0f] px-3 py-2 rounded"
              >
                {typeof ep === "string"
                  ? ep
                  : ep.url || ep.endpoint || JSON.stringify(ep)}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* API Versions */}
      {apiVersions.length > 0 && (
        <div className="bg-[#12121a] border border-[#1e1e2e] rounded-xl p-5">
          <div className="flex items-center gap-2 mb-4">
            <Layers className="w-4 h-4 text-purple-500" />
            <h3 className="text-white font-semibold text-sm">
              {t("graph.api_versions")}
            </h3>
          </div>
          <div className="flex flex-wrap gap-2">
            {apiVersions.map((v: any, idx: number) => (
              <span
                key={idx}
                className="bg-purple-900/10 text-purple-400 border border-purple-800/30 px-3 py-1.5 rounded-lg text-sm font-mono"
              >
                {typeof v === "string" ? v : v.version || JSON.stringify(v)}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

/* ===============================
   Shared: Empty State
   =============================== */

function EmptyState({ message }: { message: string }) {
  return (
    <div className="bg-[#12121a] border border-[#1e1e2e] rounded-xl p-10 text-center">
      <Shield className="w-8 h-8 text-gray-700 mx-auto mb-3" />
      <p className="text-gray-500 text-sm">{message}</p>
    </div>
  );
}
