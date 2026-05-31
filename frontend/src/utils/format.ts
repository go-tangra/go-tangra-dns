// Shared formatting helpers for the DNS admin UI.

// formatTime is the time-only variant for headline "Updated 13:42:08"
// strings on the dashboard. Returns '—' for missing input so empty
// cells are visually distinguishable from a real value.
export function formatTime(v: Date | undefined | null): string {
  if (!v) return '—';
  return v.toLocaleTimeString(undefined, {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  });
}

// humanizeSlug turns a snake_case identifier into a single human-
// friendly Title-cased phrase: "no_error" → "No error". Render-only.
export function humanizeSlug(v: string | undefined | null): string {
  if (v === undefined || v === null || v === '') return '—';
  if (v.toLowerCase() === 'ok') return 'OK';
  const spaced = v.replace(/_/g, ' ').trim();
  if (!spaced) return '—';
  return spaced.charAt(0).toUpperCase() + spaced.slice(1).toLowerCase();
}
