import assert from "node:assert/strict"
import { readFile } from "node:fs/promises"
import vm from "node:vm"
import ts from "typescript"

const source = await readFile(new URL("../lib/analyzer-options.ts", import.meta.url), "utf8")
const { outputText } = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 } })
const exports = {}
vm.runInNewContext(outputText, { exports, Date, Math, Number, JSON, Set })

const migrated = exports.normalizeAnalyzerOptions({ suppressedRuleIds: ["port-scan"] })
assert.deepEqual(Array.from(migrated.suppressedRuleIds), ["port-scan"])
assert.equal(migrated.ruleSuppressions.length, 1)
assert.ok(Date.parse(migrated.ruleSuppressions[0].expiresAt) > Date.now())

const expired = exports.normalizeAnalyzerOptions({
  suppressedRuleIds: ["port-scan"],
  ruleSuppressions: [{ ruleId: "port-scan", scope: "global", createdAt: "2020-01-01T00:00:00.000Z", expiresAt: "2020-02-01T00:00:00.000Z" }],
})
assert.equal(expired.suppressedRuleIds.length, 0)

const enabled = exports.withRuleSuppression(exports.DEFAULT_ANALYZER_OPTIONS, "dns-rate", true)
assert.ok(enabled.suppressedRuleIds.includes("dns-rate"))
const disabled = exports.withRuleSuppression(enabled, "dns-rate", false)
assert.equal(disabled.suppressedRuleIds.includes("dns-rate"), false)
console.log("Supressões de regras: migração, expiração e reativação validadas.")
