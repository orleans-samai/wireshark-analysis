import type { AnalyzerOptions, RuleOptions } from "./capture-types"

export const DEFAULT_ANALYZER_OPTIONS: AnalyzerOptions = {
  packetLimit: 20_000,
  memoryBudgetMb: 256,
  analysisMode: "standard",
  suppressedRuleIds: [],
  ruleSuppressions: [],
  ruleOptions: {
    portScanPorts: 20,
    dnsQueriesPerSecond: 10,
    highConnectionCount: 250,
    unknownPortConnections: 40,
    nxDomainRatio: 0.35,
    retransmissionRatio: 0.08,
    outboundRatio: 5,
    outboundMinimumBytes: 5_000_000,
  },
}

const STORAGE_KEY = "packetlens:analyzer-options:v2"

export function normalizeAnalyzerOptions(input: Partial<AnalyzerOptions> | null | undefined): AnalyzerOptions {
  const rules = (input?.ruleOptions || {}) as Partial<RuleOptions>
  const now = Date.now()
  const hasModernSuppressions = Array.isArray(input?.ruleSuppressions)
  const storedSuppressions = hasModernSuppressions
    ? (input?.ruleSuppressions || []).filter((item) => item && typeof item.ruleId === "string" && Date.parse(item.expiresAt) > now)
    : []
  const legacyIds = !hasModernSuppressions && Array.isArray(input?.suppressedRuleIds) ? input.suppressedRuleIds.filter((id): id is string => typeof id === "string") : []
  const ruleSuppressions = [...storedSuppressions]
  for (const ruleId of legacyIds) {
    if (!ruleSuppressions.some((item) => item.ruleId === ruleId)) ruleSuppressions.push(createSuppression(ruleId, now))
  }
  return {
    packetLimit: clamp(num(input?.packetLimit, DEFAULT_ANALYZER_OPTIONS.packetLimit), 1_000, 100_000),
    memoryBudgetMb: clamp(num(input?.memoryBudgetMb, DEFAULT_ANALYZER_OPTIONS.memoryBudgetMb), 64, 2_048),
    analysisMode: input?.analysisMode === "deep" ? "deep" : "standard",
    suppressedRuleIds: [...new Set(ruleSuppressions.map((item) => item.ruleId))],
    ruleSuppressions,
    ruleOptions: {
      portScanPorts: clamp(num(rules.portScanPorts, DEFAULT_ANALYZER_OPTIONS.ruleOptions.portScanPorts), 5, 1_024),
      dnsQueriesPerSecond: clamp(num(rules.dnsQueriesPerSecond, DEFAULT_ANALYZER_OPTIONS.ruleOptions.dnsQueriesPerSecond), 1, 100_000),
      highConnectionCount: clamp(num(rules.highConnectionCount, DEFAULT_ANALYZER_OPTIONS.ruleOptions.highConnectionCount), 10, 1_000_000),
      unknownPortConnections: clamp(num(rules.unknownPortConnections, DEFAULT_ANALYZER_OPTIONS.ruleOptions.unknownPortConnections), 5, 1_000_000),
      nxDomainRatio: clamp(num(rules.nxDomainRatio, DEFAULT_ANALYZER_OPTIONS.ruleOptions.nxDomainRatio), 0.01, 1),
      retransmissionRatio: clamp(num(rules.retransmissionRatio, DEFAULT_ANALYZER_OPTIONS.ruleOptions.retransmissionRatio), 0.01, 1),
      outboundRatio: clamp(num(rules.outboundRatio, DEFAULT_ANALYZER_OPTIONS.ruleOptions.outboundRatio), 1.1, 100),
      outboundMinimumBytes: clamp(num(rules.outboundMinimumBytes, DEFAULT_ANALYZER_OPTIONS.ruleOptions.outboundMinimumBytes), 100_000, 10_000_000_000),
    },
  }
}

function createSuppression(ruleId: string, now = Date.now()) {
  return { ruleId, scope: "global" as const, createdAt: new Date(now).toISOString(), expiresAt: new Date(now + 30 * 24 * 60 * 60 * 1000).toISOString() }
}

export function withRuleSuppression(options: AnalyzerOptions, ruleId: string, enabled: boolean): AnalyzerOptions {
  const ruleSuppressions = options.ruleSuppressions.filter((item) => item.ruleId !== ruleId)
  if (enabled) ruleSuppressions.push(createSuppression(ruleId))
  return normalizeAnalyzerOptions({ ...options, ruleSuppressions, suppressedRuleIds: ruleSuppressions.map((item) => item.ruleId) })
}

export function loadAnalyzerOptions(): AnalyzerOptions {
  if (typeof window === "undefined") return DEFAULT_ANALYZER_OPTIONS
  try {
    return normalizeAnalyzerOptions(JSON.parse(window.localStorage.getItem(STORAGE_KEY) || "null"))
  } catch {
    return DEFAULT_ANALYZER_OPTIONS
  }
}

export function saveAnalyzerOptions(options: AnalyzerOptions) {
  if (typeof window === "undefined") return
  try {
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(normalizeAnalyzerOptions(options)))
  } catch {
    // Quota esgotada ou storage indisponível: as opções seguem valendo na sessão.
  }
}

function num(value: unknown, fallback: number) {
  const parsed = Number(value)
  return Number.isFinite(parsed) ? parsed : fallback
}

function clamp(value: number, min: number, max: number) {
  return Math.min(max, Math.max(min, value))
}
