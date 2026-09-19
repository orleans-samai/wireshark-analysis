export function formatBytes(value: number) {
  if (!Number.isFinite(value) || value <= 0) return "0 B"
  const units = ["B", "KB", "MB", "GB", "TB"]
  let amount = value
  let unit = 0
  while (amount >= 1000 && unit < units.length - 1) { amount /= 1000; unit++ }
  return `${amount >= 100 || unit === 0 ? amount.toFixed(0) : amount.toFixed(1)} ${units[unit]}`
}

export function formatNumber(value: number) { return new Intl.NumberFormat("pt-BR").format(value || 0) }

export function formatDuration(seconds: number) {
  if (!Number.isFinite(seconds)) return "0 s"
  const hours = Math.floor(seconds / 3600), minutes = Math.floor((seconds % 3600) / 60), secs = Math.floor(seconds % 60)
  if (hours) return `${hours}h ${minutes}min`
  if (minutes) return `${minutes}min ${secs}s`
  return `${secs}s`
}

