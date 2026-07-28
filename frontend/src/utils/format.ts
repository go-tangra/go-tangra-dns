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

// --- Shared date/time display (preference-aware) ---------------------------
// The host publishes the user's resolved time-display preference (timezone +
// 12h/24h) on a well-known `window` global; this reads it so federated remotes
// render timestamps consistently. Display only — never for backend serialization.

const TIME_CONFIG_GLOBAL = '__TANGRA_TIME_CONFIG__';

interface TimeDisplayConfig {
  timeFormat: '12h' | '24h';
  timezone: string;
}

function readConfig(): TimeDisplayConfig {
  const raw = (globalThis as Record<string, any>)[TIME_CONFIG_GLOBAL] as
    | Partial<TimeDisplayConfig>
    | undefined;
  return {
    timeFormat: raw?.timeFormat === '12h' ? '12h' : '24h',
    timezone: typeof raw?.timezone === 'string' ? raw.timezone : '',
  };
}

function toDate(value: Date | number | string): Date | null {
  if (value === null || value === undefined || value === '') {
    return null;
  }
  const date = value instanceof Date ? value : new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

/** Format a timestamp as a localized date-time honouring the user preference. */
export function formatDateTime(value: Date | number | string): string {
  const date = toDate(value);
  if (!date) {
    return '';
  }
  const { timeFormat, timezone } = readConfig();
  try {
    const parts = new Intl.DateTimeFormat('en-CA', {
      timeZone: timezone || undefined,
      hour12: timeFormat === '12h',
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    }).format(date);
    // en-CA yields "YYYY-MM-DD, HH:mm:ss"; drop the comma for a clean look.
    return parts.replace(',', '');
  } catch {
    return date.toLocaleString();
  }
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
