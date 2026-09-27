/**
 * One CSV cell: quoted when needed, and neutralised against spreadsheet
 * formula injection. Exported values include text derived from scanned
 * sites (finding titles quote headers, hostnames, paths), so a cell starting
 * with = + - @ or a control character would otherwise execute as a formula
 * when a customer opens the export in Excel or Sheets. The leading
 * apostrophe makes the spreadsheet treat it as literal text (OWASP guidance).
 */
export function csvCell(value: string): string {
  const safe = /^[=+\-@\t\r]/.test(value) ? `'${value}` : value;
  return /[",\r\n]/.test(safe) ? `"${safe.replace(/"/g, '""')}"` : safe;
}
