import axios from "axios";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "/api";

const api = axios.create({
  baseURL: API_BASE,
});

api.interceptors.request.use((config) => {
  const token = typeof window !== "undefined" ? localStorage.getItem("token") : null;
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

api.interceptors.response.use(
  (res) => res,
  (err) => {
    // Auth disabled — no redirect to login
    return Promise.reject(err);
  }
);

// Auth
export async function login(username: string, password: string) {
  const params = new URLSearchParams();
  params.append("username", username);
  params.append("password", password);
  const { data } = await api.post("/auth/login", params);
  localStorage.setItem("token", data.access_token);
  return data;
}

export async function register(username: string, email: string, password: string) {
  const { data } = await api.post("/auth/register", { username, email, password });
  return data;
}

// Targets
export async function getTargets() {
  const { data } = await api.get("/targets");
  return data;
}

export async function createTarget(domain: string, scope?: string) {
  const { data } = await api.post("/targets", { domain, scope });
  return data;
}

export async function getTarget(id: string) {
  const { data } = await api.get(`/targets/${id}`);
  return data;
}

export async function deleteTarget(id: string) {
  await api.delete(`/targets/${id}`);
}

// Scans
export async function getScans() {
  const { data } = await api.get("/scans");
  return data;
}

export async function getScan(id: string) {
  const { data } = await api.get(`/scans/${id}`);
  return data;
}

export async function createScan(targetId: string, scanType?: string, priority?: number, rounds?: number, continuous?: boolean) {
  const { data } = await api.post("/scans", {
    target_id: targetId,
    scan_type: scanType || "full",
    priority: priority || 5,
    rounds: rounds || 1,
    continuous: continuous || false,
  });
  return data;
}

export async function stopScan(id: string) {
  const { data } = await api.post(`/scans/${id}/stop`);
  return data;
}

export async function deleteScan(id: string) {
  await api.delete(`/scans/${id}`);
}

export async function getScanLogs(id: string) {
  const { data } = await api.get(`/scans/${id}/logs`);
  return data;
}

export async function compareScans(scanIdA: string, scanIdB: string) {
  const { data } = await api.get(`/scans/compare/${scanIdA}/${scanIdB}`);
  return data;
}

export async function getComparisonReport(scanA: string, scanB: string) {
  const { data } = await api.get(`/scans/compare/${scanA}/${scanB}/report`, {
    responseType: "text",
  });
  return data;
}

// Campaigns
export async function createCampaign(targetIds: string[], scanType?: string, priority?: number) {
  const { data } = await api.post("/scans/campaign", {
    target_ids: targetIds,
    scan_type: scanType || "quick",
    priority: priority || 5,
  });
  return data;
}

export async function createCampaignByTag(tag: string, scanType?: string, priority?: number) {
  const { data } = await api.post("/scans/campaign/by-tag", {
    tag,
    scan_type: scanType || "quick",
    priority: priority || 5,
  });
  return data;
}

export async function getCampaignStatus(campaignId: string) {
  const { data } = await api.get(`/scans/campaign/${campaignId}`);
  return data;
}

// Monitoring
export async function toggleMonitoring(targetId: string, enabled: boolean, interval: string = "daily") {
  const { data } = await api.post(`/targets/${targetId}/monitor`, { enabled, interval });
  return data;
}

export async function getTargetChanges(targetId: string) {
  const { data } = await api.get(`/targets/${targetId}/changes`);
  return data;
}

// Vulnerabilities
export async function getVulnerabilities(params?: Record<string, string>) {
  const { data } = await api.get("/vulnerabilities", { params });
  return data;
}

export async function getVulnerability(vulnId: string) {
  const { data } = await api.get(`/vulnerabilities/${vulnId}`);
  return data;
}

export async function validateVulnerability(vulnId: string) {
  const { data } = await api.post(`/vulnerabilities/${vulnId}/validate`);
  return data;
}

export async function getVulnCompliance(vulnId: string) {
  const { data } = await api.get(`/vulnerabilities/${vulnId}/compliance`);
  return data;
}

export async function reverifyVulnerability(vulnId: string) {
  const { data } = await api.post(`/vulnerabilities/${vulnId}/reverify`);
  return data;
}

export async function getBountyReport(vulnId: string) {
  const { data } = await api.get(`/vulnerabilities/${vulnId}/hackerone`);
  return data;
}

export async function calculateCVSS(vulnId: string) {
  const { data } = await api.post(`/vulnerabilities/${vulnId}/cvss`);
  return data;
}

export async function bulkCalculateCVSS(targetId: string) {
  const { data } = await api.post("/vulnerabilities/calculate-cvss", { target_id: targetId });
  return data;
}

export async function bulkValidateVulnerabilities(targetId: string) {
  const { data } = await api.post("/vulnerabilities/validate-all", { target_id: targetId });
  return data;
}

export async function updateVulnStatus(vulnId: string, status: string) {
  const { data } = await api.put(`/vulnerabilities/${vulnId}`, { status });
  return data;
}

export async function exportVulnerabilities(format: "json" | "csv", params?: Record<string, string>) {
  const { data } = await api.get(`/vulnerabilities/export/${format}`, {
    params,
    responseType: format === "csv" ? "text" : "json",
  });
  return data;
}

// Reports
export async function getTargetReportHtml(targetId: string) {
  const { data } = await api.get(`/reports/target/${targetId}/html`, {
    responseType: "text",
  });
  return data;
}

export async function getScanReportHtml(scanId: string) {
  const { data } = await api.get(`/reports/scan/${scanId}/html`, {
    responseType: "text",
  });
  return data;
}

// Schedules
export async function getSchedules() {
  const { data } = await api.get("/schedules");
  return data;
}

export async function createSchedule(targetId: string, scanType: string, interval: string) {
  const { data } = await api.post("/schedules", {
    target_id: targetId,
    scan_type: scanType,
    interval,
  });
  return data;
}

export async function updateSchedule(id: string, updates: Record<string, any>) {
  const { data } = await api.patch(`/schedules/${id}`, updates);
  return data;
}

export async function deleteSchedule(id: string) {
  await api.delete(`/schedules/${id}`);
}

// PDF Reports
export async function getScanReportPdf(scanId: string) {
  const { data } = await api.get(`/reports/scan/${scanId}/pdf`, {
    responseType: "blob",
  });
  return data;
}

export async function getTargetReportPdf(targetId: string) {
  const { data } = await api.get(`/reports/target/${targetId}/pdf`, {
    responseType: "blob",
  });
  return data;
}

// Report Validation
export async function validateScanReport(scanId: string, rounds: number = 1, continuous: boolean = false) {
  const { data } = await api.post(`/validate/scan/${scanId}`, null, {
    params: { rounds, continuous },
  });
  return data;
}

export async function validateTargetReport(targetId: string, rounds: number = 1, continuous: boolean = false) {
  const { data } = await api.post(`/validate/target/${targetId}`, null, {
    params: { rounds, continuous },
  });
  return data;
}

// Users (admin)
export async function getUsers() {
  const { data } = await api.get("/auth/users");
  return data;
}

export async function updateUserRole(userId: string, role: string) {
  const { data } = await api.patch(`/auth/users/${userId}/role`, { role });
  return data;
}

export async function getMe() {
  const { data } = await api.get("/auth/me");
  return data;
}

// API Tokens
export async function generateApiToken() {
  const { data } = await api.post("/auth/api-token");
  return data;
}

export async function revokeApiToken() {
  await api.delete("/auth/api-token");
}

// Training
export async function startTraining() {
  const { data } = await api.post("/training/start");
  return data;
}

export async function stopTraining() {
  const { data } = await api.post("/training/stop");
  return data;
}

export async function getTrainingStatus() {
  const { data } = await api.get("/training/status");
  return data;
}

export async function getSkillsReport() {
  const { data } = await api.get("/training/skills");
  return data;
}

export async function getTrainingHistory(limit = 20) {
  const { data } = await api.get("/training/history", { params: { limit } });
  return data;
}

export async function resetKnowledge() {
  const { data } = await api.delete("/training/reset");
  return data;
}

export async function getTrainingModules() {
  const { data } = await api.get("/training/modules");
  return data;
}

export async function injectTrainingModule(module: string) {
  const { data } = await api.post("/training/inject-module", { module });
  return data;
}

export async function runLiveFeed(feed: string) {
  const { data } = await api.post("/training/live-feed", { feed });
  return data;
}

export async function runAIMutation(action: string, technology?: string, vulnType?: string, count?: number) {
  const { data } = await api.post("/training/ai-mutate", {
    action,
    technology,
    vuln_type: vulnType,
    count: count || 10,
  });
  return data;
}

export async function injectExpertKnowledge() {
  const { data } = await api.post("/training/inject-knowledge");
  return data;
}

// Knowledge Aging
export async function getKnowledgeHealth() {
  const { data } = await api.get("/training/knowledge-health");
  return data;
}

export async function runKnowledgeAging() {
  const { data } = await api.post("/training/knowledge-aging");
  return data;
}

// Adversarial Testing
export async function startAdversarialTest(vulnType?: string, rounds?: number) {
  const { data } = await api.post("/training/adversarial", {
    vuln_type: vulnType,
    rounds: rounds || 10,
  });
  return data;
}

export async function getAdversarialStats() {
  const { data } = await api.get("/training/adversarial/stats");
  return data;
}

// Practice Range
export async function getPracticeTargets() {
  const { data } = await api.get("/training/range");
  return data;
}

export async function deployPracticeTarget(targetId: string) {
  const { data } = await api.post("/training/range/deploy", { target_id: targetId });
  return data;
}

export async function deployAllTargets() {
  const { data } = await api.post("/training/range/deploy-all");
  return data;
}

export async function stopPracticeTarget(targetId: string) {
  const { data } = await api.post(`/training/range/stop/${targetId}`);
  return data;
}

export async function scorePracticeScan(targetId: string) {
  const { data } = await api.get(`/training/range/score/${targetId}`);
  return data;
}

// Claude API Key Settings
export async function getClaudeKeyStatus() {
  const { data } = await api.get("/training/settings/claude-key");
  return data;
}

export async function setClaudeKey(apiKey: string) {
  const { data } = await api.post("/training/settings/claude-key", { api_key: apiKey });
  return data;
}

export async function deleteClaudeKey() {
  const { data } = await api.delete("/training/settings/claude-key");
  return data;
}

// Dashboard
export async function getDashboardStats() {
  const { data } = await api.get("/dashboard/stats");
  return data;
}

// Health
export async function getHealth() {
  const { data } = await api.get("/health");
  return data;
}

// Scan Templates
export async function getScanTemplates() {
  const { data } = await api.get("/scan-templates");
  return data;
}

export async function createScanTemplate(name: string, description: string, scanType: string, config: Record<string, any>) {
  const { data } = await api.post("/scan-templates", { name, description, scan_type: scanType, config });
  return data;
}

export async function updateScanTemplate(id: string, updates: Record<string, any>) {
  const { data } = await api.put(`/scan-templates/${id}`, updates);
  return data;
}

export async function deleteScanTemplate(id: string) {
  await api.delete(`/scan-templates/${id}`);
}

export async function runScanTemplate(templateId: string, targetId: string, priority: number = 5) {
  const { data } = await api.post(`/scan-templates/${templateId}/run`, { target_id: targetId, priority });
  return data;
}

// Recon
export async function getTargetRecon(targetId: string) {
  const { data } = await api.get(`/targets/${targetId}/recon`);
  return data;
}

// Audit Log
export async function getAuditLogs(params?: Record<string, string | number>) {
  const { data } = await api.get("/audit", { params });
  return data;
}

export async function getAuditActions() {
  const { data } = await api.get("/audit/actions");
  return data;
}

// Target Tags
export async function getAllTags() {
  const { data } = await api.get("/targets/tags");
  return data;
}

export async function updateTargetTags(targetId: string, tags: string[]) {
  const { data } = await api.post(`/targets/${targetId}/tags`, tags);
  return data;
}

// Scan Queue
export async function getScanQueue() {
  const { data } = await api.get("/scans/queue");
  return data;
}

export async function updateScanPriority(scanId: string, priority: number) {
  const { data } = await api.patch(`/scans/${scanId}/priority`, null, { params: { priority } });
  return data;
}

// Vulnerability Lifecycle
export async function getLifecycleInfo() {
  const { data } = await api.get("/vulnerabilities/lifecycle");
  return data;
}

export async function transitionVuln(vulnId: string, newStatus: string) {
  const { data } = await api.post(`/vulnerabilities/${vulnId}/transition`, null, { params: { new_status: newStatus } });
  return data;
}

// Notifications
export async function getNotificationSettings() {
  const { data } = await api.get("/notifications/settings");
  return data;
}

export async function updateNotificationSettings(settings: Record<string, any>) {
  const { data } = await api.put("/notifications/settings", settings);
  return data;
}

export async function testNotification() {
  const { data } = await api.post("/notifications/test");
  return data;
}

export async function getNotificationHistory() {
  const { data } = await api.get("/notifications/history");
  return data;
}

// HackerOne Intelligence
export async function collectHacktivity(pages?: number) {
  const { data } = await api.post("/hackerone/collect", null, { params: { pages } });
  return data;
}

export async function analyzeDisclosedReports(limit?: number) {
  const { data } = await api.post("/hackerone/analyze", null, { params: { limit } });
  return data;
}

export async function getHackeroneStats() {
  const { data } = await api.get("/hackerone/stats");
  return data;
}

export async function collectAndAnalyze(pages?: number) {
  const { data } = await api.post("/hackerone/collect-and-analyze", null, { params: { pages } });
  return data;
}

// Bounty Programs
export async function collectPrograms(limit?: number) {
  const { data } = await api.post("/programs/collect", null, { params: { limit } });
  return data;
}

export async function enrichPrograms() {
  const { data } = await api.post("/programs/enrich");
  return data;
}

export async function scorePrograms() {
  const { data } = await api.post("/programs/score");
  return data;
}

export async function refreshPrograms(limit?: number) {
  const { data } = await api.post("/programs/refresh", null, { params: { limit } });
  return data;
}

export async function getProgramRecommendations(topN?: number) {
  const { data } = await api.get("/programs/recommendations", { params: { top_n: topN } });
  return data;
}

export async function getProgramsDashboard() {
  const { data } = await api.get("/programs/dashboard");
  return data;
}

export async function getProgram(handle: string) {
  const { data } = await api.get(`/programs/${handle}`);
  return data;
}

// H1 Submissions
export async function getSubmissionsDashboard() {
  const { data } = await api.get("/submissions/dashboard");
  return data;
}

export async function getSubmissions(params?: Record<string, string>) {
  const { data } = await api.get("/submissions", { params });
  return data;
}

export async function createSubmission(vulnId: string, programHandle: string) {
  const { data } = await api.post("/submissions", { vulnerability_id: vulnId, program_handle: programHandle });
  return data;
}

export async function getSubmission(id: string) {
  const { data } = await api.get(`/submissions/${id}`);
  return data;
}

export async function submitToH1(id: string) {
  const { data } = await api.post(`/submissions/${id}/submit`);
  return data;
}

export async function updateSubmissionStatus(id: string, status: string, h1Response?: string, bountyAmount?: number) {
  const { data } = await api.post(`/submissions/${id}/status`, {
    status,
    h1_response: h1Response,
    bounty_amount: bountyAmount,
  });
  return data;
}

export async function learnFromAll() {
  const { data } = await api.post("/submissions/learn-all");
  return data;
}

export async function getRejectionAnalysis() {
  const { data } = await api.get("/submissions/rejection-analysis");
  return data;
}

// Autopilot
export async function getAutopilotStatus() {
  const { data } = await api.get("/autopilot/status");
  return data;
}

export async function runAutopilotScan(programHandle?: string) {
  const { data } = await api.post("/autopilot/scan", null, { params: { program_handle: programHandle } });
  return data;
}

export async function runAutopilotCycle(maxScans?: number) {
  const { data } = await api.post("/autopilot/cycle", null, { params: { max_scans: maxScans } });
  return data;
}

export async function startAutopilot(maxScans?: number) {
  const { data } = await api.post("/autopilot/start", null, { params: { max_scans: maxScans } });
  return data;
}

export async function stopAutopilot(taskId: string) {
  const { data } = await api.post("/autopilot/stop", null, { params: { task_id: taskId } });
  return data;
}

export default api;
