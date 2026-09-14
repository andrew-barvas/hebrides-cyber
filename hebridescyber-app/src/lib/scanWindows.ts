// Scan window enforcement — determines whether a scan is allowed to run
// right now based on the target's configured time-of-day window.
//
// Pure/sync so it's unit-testable without touching Supabase, same pattern
// as scanCadence.ts. The enqueue script passes the window columns in and
// this function just answers yes/no.

export type ScanWindow = {
  startTime: string | null; // "HH:MM" or null (no restriction)
  endTime: string | null;   // "HH:MM" or null (no restriction)
  timezone: string;         // IANA timezone, e.g. "Europe/London"
};

function parseHHMM(hhmm: string): { hours: number; minutes: number } | null {
  const match = hhmm.match(/^(\d{1,2}):(\d{2})$/);
  if (!match) return null;
  const hours = parseInt(match[1], 10);
  const minutes = parseInt(match[2], 10);
  if (hours < 0 || hours > 23 || minutes < 0 || minutes > 59) return null;
  return { hours, minutes };
}

function toMinuteOfDay(hours: number, minutes: number): number {
  return hours * 60 + minutes;
}

/**
 * True when `now` falls within the target's scan window (or when no window is set).
 *
 * Supports overnight windows (e.g. 22:00–06:00) where start > end.
 */
export function isWithinScanWindow(window: ScanWindow, now: Date): boolean {
  if (!window.startTime || !window.endTime) return true;

  const start = parseHHMM(window.startTime);
  const end = parseHHMM(window.endTime);
  if (!start || !end) return true;

  let localTimeStr: string;
  try {
    localTimeStr = now.toLocaleTimeString("en-GB", {
      timeZone: window.timezone,
      hour12: false,
      hour: "2-digit",
      minute: "2-digit",
    });
  } catch {
    return true;
  }

  const localParsed = parseHHMM(localTimeStr);
  if (!localParsed) return true;

  const nowMins = toMinuteOfDay(localParsed.hours, localParsed.minutes);
  const startMins = toMinuteOfDay(start.hours, start.minutes);
  const endMins = toMinuteOfDay(end.hours, end.minutes);

  if (startMins <= endMins) {
    return nowMins >= startMins && nowMins < endMins;
  }
  // Overnight window (e.g. 22:00–06:00)
  return nowMins >= startMins || nowMins < endMins;
}
