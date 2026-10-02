import { expect, test } from "@playwright/test"
import { readFile } from "node:fs/promises"

function capture(name: string, frames = 1) {
  const dns = Buffer.from("123401000001000000000000076578616d706c6504746573740000010001", "hex")
  const udp = Buffer.alloc(8)
  udp.writeUInt16BE(53000, 0)
  udp.writeUInt16BE(53, 2)
  udp.writeUInt16BE(udp.length + dns.length, 4)
  const ip = Buffer.alloc(20)
  ip[0] = 0x45
  ip.writeUInt16BE(20 + udp.length + dns.length, 2)
  ip[8] = 64
  ip[9] = 17
  Buffer.from([192, 168, 1, 20]).copy(ip, 12)
  Buffer.from([1, 1, 1, 1]).copy(ip, 16)
  const frame = Buffer.concat([Buffer.from("04d4c4882e013c52824fa1200800", "hex"), ip, udp, dns])
  const global = Buffer.alloc(24)
  global.writeUInt32LE(0xa1b2c3d4, 0)
  global.writeUInt16LE(2, 4)
  global.writeUInt16LE(4, 6)
  global.writeUInt32LE(65_535, 16)
  global.writeUInt32LE(1, 20)
  const record = Buffer.alloc(16)
  record.writeUInt32LE(1_700_000_000, 0)
  record.writeUInt32LE(frame.length, 8)
  record.writeUInt32LE(frame.length, 12)
  const buffer = Buffer.concat([global, ...Array.from({ length: frames }, () => Buffer.concat([record, frame]))])
  return { name, mimeType: "application/vnd.tcpdump.pcap", buffer }
}

test("importar, investigar, comparar, tratar erro e exportar CSV", async ({ page }) => {
  await page.goto("/")
  await expect(page.getByRole("button", { name: "Usar tema escuro" })).toBeVisible()
  await page.locator('input[type="file"]').setInputFiles(capture("e2e-primary.pcap"))
  await expect(page.getByRole("heading", { name: "Visão geral da captura" })).toBeVisible()
  await page.getByRole("button", { name: "Explorador de pacotes", exact: true }).click()
  await expect(page.getByText("example.test", { exact: false }).first()).toBeVisible()

  const search = page.getByRole("searchbox", { name: /Pesquisar e filtrar/ })
  await search.fill("192.168.1.20")
  await expect(page.getByText("texto: 192.168.1.20")).toBeVisible()
  await page.getByRole("button", { name: "Comparar", exact: true }).click()
  await page.locator('input[type="file"]').setInputFiles(capture("e2e-secondary.pcap", 2))
  await expect(page.getByText("e2e-secondary.pcap", { exact: true })).toBeVisible()

  await page.locator('input[type="file"]').setInputFiles({ name: "invalid.pcap", mimeType: "application/vnd.tcpdump.pcap", buffer: Buffer.alloc(30) })
  await expect(page.getByRole("alert")).toContainText("Não foi possível substituir")
  await expect(page.getByText("e2e-secondary.pcap", { exact: true })).toBeVisible()

  await page.getByRole("button", { name: "Relatórios", exact: true }).click()
  const row = page.locator("li").filter({ has: page.getByRole("heading", { name: "Pacotes do recorte" }) })
  const downloadPromise = page.waitForEvent("download")
  await row.getByRole("button", { name: "Exportar" }).click()
  const download = await downloadPromise
  expect(download.suggestedFilename()).toBe("packetlens-filtered-packets.csv")
  expect(await readFile(await download.path(), "utf8")).toContain("192.168.1.20")
})

test("cancelar uma comparação mantém a captura principal", async ({ page }) => {
  await page.goto("/")
  await expect(page.getByRole("button", { name: "Usar tema escuro" })).toBeVisible()
  await page.locator('input[type="file"]').setInputFiles(capture("base.pcap"))
  await expect(page.getByRole("heading", { name: "Visão geral da captura" })).toBeVisible()
  await page.getByRole("button", { name: "Comparar", exact: true }).click()
  await page.locator('input[type="file"]').setInputFiles(capture("grande.pcap", 30_000))
  await page.getByRole("button", { name: "Cancelar" }).click()
  await expect(page.getByRole("heading", { name: "Carregar captura de comparação" })).toBeVisible()
  await page.getByRole("button", { name: "Painel geral", exact: true }).click()
  await expect(page.getByText("base.pcap", { exact: true })).toBeVisible()
})

test("abrir evidências de um sinal aplica o escopo no explorador", async ({ page }) => {
  await page.goto("/")
  await expect(page.getByRole("button", { name: "Usar tema escuro" })).toBeVisible()
  await page.getByRole("button", { name: "Abrir uma análise de exemplo" }).click()
  await page.getByRole("button", { name: /^Sinais de segurança/ }).click()
  await page.getByRole("button", { name: "Investigar evidências" }).first().click()
  await expect(page.getByRole("heading", { name: "Explorador de pacotes" })).toBeVisible()
  await expect(page.getByRole("button", { name: /Remover filtro host:/ }).first()).toBeVisible()
})

test("configurações avançadas são persistidas para a próxima análise", async ({ page }) => {
  await page.goto("/")
  await expect(page.getByRole("button", { name: "Usar tema escuro" })).toBeVisible()
  await page.getByRole("button", { name: "Abrir uma análise de exemplo" }).click()
  await page.getByRole("button", { name: "Configurações", exact: true }).click()
  await page.getByRole("combobox", { name: "Profundidade da análise" }).click()
  await page.getByRole("option", { name: "Profunda" }).click()
  await page.getByRole("checkbox", { name: "Varredura de portas" }).check()
  const options = await page.evaluate(() => JSON.parse(localStorage.getItem("packetlens:analyzer-options:v2") || "{}"))
  expect(options.analysisMode).toBe("deep")
  expect(options.suppressedRuleIds).toContain("port-scan")
})

test("criar caso, usar atalho e anexar evidência", async ({ page }) => {
  test.setTimeout(90_000)
  await page.goto("/")
  await expect(page.getByRole("button", { name: "Usar tema escuro" })).toBeVisible()
  await page.getByRole("button", { name: "Abrir uma análise de exemplo" }).click()
  await expect(page.getByRole("heading", { name: "Visão geral da captura" })).toBeVisible()
  await page.keyboard.press("/")
  await expect(page.getByRole("searchbox", { name: /Pesquisar e filtrar/ })).toBeFocused()
  await page.getByRole("button", { name: /Casos/ }).click()
  await page.getByRole("textbox", { name: "Nome do caso" }).fill("Investigação E2E")
  await page.getByRole("textbox", { name: "Responsável pelo caso" }).fill("SOC")
  await page.getByRole("button", { name: "Criar e ativar" }).click()
  await expect(page.getByText("Caso ativo", { exact: true })).toBeVisible()
  await page.keyboard.press("Escape")
  await page.getByRole("button", { name: /^Sinais de segurança/ }).click()
  await page.getByRole("button", { name: "Adicionar ao caso" }).first().click()
  await expect(page.getByText("1 evidência(s)", { exact: false })).toBeVisible()
  await page.reload({ waitUntil: "networkidle" })
  await expect(page.getByRole("button", { name: "Usar tema escuro" })).toBeVisible()
  await page.getByRole("button", { name: "Abrir uma análise de exemplo" }).click()
  await expect(page.getByRole("heading", { name: "Visão geral da captura" })).toBeVisible()
  await page.getByRole("button", { name: /Casos/ }).click()
  await expect(page.getByText("Investigação E2E", { exact: true })).toBeVisible()
})

test("estrutura essencial permanece acessível e sem estouro horizontal", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  await page.goto("/", { waitUntil: "networkidle" })
  await expect(page.getByRole("button", { name: "Usar tema escuro" })).toBeVisible()
  await expect(page.locator("html")).toHaveClass(/dark|light/)
  await page.getByRole("button", { name: "Abrir uma análise de exemplo" }).click()
  await expect(page.getByRole("heading", { name: "Visão geral da captura" })).toBeVisible()
  await page.getByRole("button", { name: "Abrir navegação" }).click()
  await expect(page.getByRole("navigation", { name: "Seções da análise" })).toBeVisible()
  await expect(page.getByRole("heading", { level: 1 })).toHaveCount(1)

  const audit = await page.evaluate(() => {
    const ids = [...document.querySelectorAll<HTMLElement>("[id]")].map((element) => element.id)
    const duplicateIds = [...new Set(ids.filter((id, index) => ids.indexOf(id) !== index))]
    const unnamedButtons = [...document.querySelectorAll<HTMLButtonElement>("button")]
      .filter((button) => button.getClientRects().length > 0 && !button.disabled)
      .filter((button) => !(button.getAttribute("aria-label") || button.getAttribute("title") || button.textContent?.trim()))
      .length
    const unnamedInputs = [...document.querySelectorAll("input, textarea, select")]
      .map((element) => element as HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement)
      .filter((input) => input.getClientRects().length > 0 && (!(input instanceof HTMLInputElement) || input.type !== "hidden"))
      .filter((input) => !(input.getAttribute("aria-label") || input.getAttribute("aria-labelledby") || input.labels?.length))
      .length
    return {
      duplicateIds,
      unnamedButtons,
      unnamedInputs,
      overflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
    }
  })
  expect(audit.duplicateIds).toEqual([])
  expect(audit.unnamedButtons).toBe(0)
  expect(audit.unnamedInputs).toBe(0)
  expect(audit.overflow).toBeLessThanOrEqual(1)
})
