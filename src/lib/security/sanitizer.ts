/**
 * Sanitizes untrusted strings from external OSINT providers or file metadata.
 * Strips HTML tags, script blocks, null bytes, and control characters.
 */
export function sanitizeText(input: unknown, maxLength = 4000): string {
  if (input === null || input === undefined) return '';
  const raw = String(input);
  const withoutNulls = raw.replace(/\0/g, '');
  const withoutScripts = withoutNulls.replace(
    /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
    ''
  );
  const withoutTags = withoutScripts.replace(/<\/?[^>]+(>|$)/g, '');
  const withoutControl = withoutTags.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');
  return withoutControl.trim().slice(0, maxLength);
}

const DANGEROUS_OBJECT_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

/**
 * Recursively sanitizes string values inside an object or array from an untrusted provider.
 */
export function sanitizeRecord<T>(value: T): T {
  if (typeof value === 'string') {
    return sanitizeText(value) as unknown as T;
  }
  if (Array.isArray(value)) {
    return value.map((item) => sanitizeRecord(item)) as unknown as T;
  }
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      const safeKey = sanitizeText(k, 128);
      if (!safeKey || DANGEROUS_OBJECT_KEYS.has(safeKey.toLowerCase())) {
        continue;
      }
      out[safeKey] = sanitizeRecord(v);
    }
    return out as T;
  }
  return value;
}

const FORMULA_TRIGGERS = new Set(['=', '+', '-', '@', '\t', '\r', '\n']);

/**
 * Neutralizes spreadsheet formula injection (CSV Injection / DDE) and escapes quotes per RFC 4180.
 */
export function escapeCsvCell(value: unknown): string {
  if (value === null || value === undefined) return '""';
  let str = typeof value === 'object' ? JSON.stringify(value) : String(value);
  str = str.replace(/\0/g, '');

  const trimmedLeft = str.trimStart();
  if (
    trimmedLeft.length > 0 &&
    (FORMULA_TRIGGERS.has(str[0]) || FORMULA_TRIGGERS.has(trimmedLeft[0]))
  ) {
    str = `'${str}`;
  }

  const escapedQuotes = str.replace(/"/g, '""');
  return `"${escapedQuotes}"`;
}

const SENSITIVE_LOCATION_KEYS = new Set([
  'gpslatitude',
  'gpslongitude',
  'gpsaltitude',
  'gpscoordinates',
  'exactcoordinates',
  'rawgps'
]);

/**
 * Redacts sensitive location/EXIF coordinates by default unless explicitly revealed by an authorized user action.
 */
export function redactSensitiveAttributes(
  attributes: Record<string, unknown>,
  revealSensitive = false
): Record<string, unknown> {
  if (revealSensitive) return attributes;

  const clone: Record<string, unknown> = {};
  for (const [key, val] of Object.entries(attributes)) {
    if (SENSITIVE_LOCATION_KEYS.has(key.toLowerCase())) {
      clone[key] = '[REDACTED — Explicit Analyst Reveal Required]';
    } else if (val && typeof val === 'object' && !Array.isArray(val)) {
      clone[key] = redactSensitiveAttributes(
        val as Record<string, unknown>,
        revealSensitive
      );
    } else {
      clone[key] = val;
    }
  }
  return clone;
}
