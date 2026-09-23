/** Formats a dashboard value with its unit ("—" when there is no data). */
export function formatValue(v: number | undefined, unit?: string): string {
  if (v === undefined || !Number.isFinite(v)) return '—'
  if (unit === 's') return formatDuration(v)
  const n = Math.abs(v) >= 100 ? v.toFixed(0) : v.toFixed(2)
  if (unit === '%') return `${n} %`
  return unit ? `${n} ${unit}` : n
}

/** Seconds → "3d 4h", "5h 12m", "42m", "12s". */
export function formatDuration(sec: number): string {
  const s = Math.max(0, Math.floor(sec))
  const d = Math.floor(s / 86400)
  const h = Math.floor((s % 86400) / 3600)
  const m = Math.floor((s % 3600) / 60)
  if (d) return `${d}d ${h}h`
  if (h) return `${h}h ${m}m`
  if (m) return `${m}m`
  return `${s}s`
}
