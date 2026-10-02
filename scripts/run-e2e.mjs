import { spawn, spawnSync } from "node:child_process"
import { fileURLToPath } from "node:url"

const projectRoot = fileURLToPath(new URL("../", import.meta.url))
const server = spawn(process.execPath, ["scripts/run-e2e-server.mjs"], {
  cwd: projectRoot,
  env: process.env,
  stdio: "inherit",
  windowsHide: true,
})

function terminateServer() {
  if (!server.pid || server.exitCode !== null) return
  if (process.platform === "win32") {
    spawnSync("taskkill", ["/pid", String(server.pid), "/t", "/f"], { stdio: "ignore", windowsHide: true })
  } else {
    server.kill("SIGTERM")
  }
}

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.once(signal, () => {
    terminateServer()
    process.exit(130)
  })
}

async function waitForServer() {
  const deadline = Date.now() + 120_000
  while (Date.now() < deadline) {
    if (server.exitCode !== null) throw new Error(`Servidor E2E encerrou antes de ficar pronto (${server.exitCode}).`)
    try {
      const response = await fetch("http://localhost:4173/", { signal: AbortSignal.timeout(2_000) })
      if (response.status < 500) return
    } catch { /* O servidor ainda está iniciando. */ }
    await new Promise((resolve) => setTimeout(resolve, 250))
  }
  throw new Error("Servidor E2E não ficou pronto em 120 segundos.")
}

try {
  await waitForServer()
  const cli = fileURLToPath(new URL("../node_modules/@playwright/test/cli.js", import.meta.url))
  const runner = spawn(process.execPath, [cli, "test", ...process.argv.slice(2)], {
    cwd: projectRoot,
    env: process.env,
    stdio: "inherit",
    windowsHide: true,
  })
  const code = await new Promise((resolve) => runner.once("exit", (status) => resolve(status ?? 1)))
  process.exitCode = code
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error))
  process.exitCode = 1
} finally {
  terminateServer()
}
process.exit(process.exitCode || 0)
