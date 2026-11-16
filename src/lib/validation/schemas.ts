import { z } from 'zod';
import url from 'url';
import net from 'net';
import { parsePhoneNumberFromString } from 'libphonenumber-js';
import { TargetType } from '@/types/osint';
import { classifyIpAddress, isBlockedHostname } from '@/lib/security/ssrf-guard';
import { sanitizeText } from '@/lib/security/sanitizer';

export interface NormalizedTargetResult {
  valid: boolean;
  targetType: TargetType;
  rawInput: string;
  normalizedValue: string;
  metadata: Record<string, unknown>;
  error?: string;
}

/**
 * Validates and normalizes an internationalized or ASCII domain name (DOM-01).
 */
export function validateAndNormalizeDomain(raw: string): NormalizedTargetResult {
  const trimmed = raw.trim().toLowerCase().replace(/\.$/, '');
  if (!trimmed || trimmed.length > 253) {
    return {
      valid: false,
      targetType: 'domain',
      rawInput: raw,
      normalizedValue: trimmed,
      metadata: {},
      error: 'Domain must be between 1 and 253 characters.'
    };
  }

  if (
    trimmed.includes('://') ||
    trimmed.includes('/') ||
    trimmed.includes(':') ||
    trimmed.includes('@') ||
    trimmed.includes(' ')
  ) {
    return {
      valid: false,
      targetType: 'domain',
      rawInput: raw,
      normalizedValue: trimmed,
      metadata: {},
      error: 'Domain must not include protocol schemes, paths, ports, or spaces.'
    };
  }

  const asciiDomain = url.domainToASCII(trimmed);
  if (!asciiDomain) {
    return {
      valid: false,
      targetType: 'domain',
      rawInput: raw,
      normalizedValue: trimmed,
      metadata: {},
      error: 'Invalid internationalized or ASCII domain syntax.'
    };
  }

  if (net.isIP(asciiDomain) !== 0) {
    return {
      valid: false,
      targetType: 'domain',
      rawInput: raw,
      normalizedValue: asciiDomain,
      metadata: {},
      error: 'Input is an IP literal, not a domain name.'
    };
  }

  const hostBlock = isBlockedHostname(asciiDomain);
  if (hostBlock.blocked) {
    return {
      valid: false,
      targetType: 'domain',
      rawInput: raw,
      normalizedValue: asciiDomain,
      metadata: {},
      error: hostBlock.reason || 'Internal/reserved domain is not permitted.'
    };
  }

  const labels = asciiDomain.split('.');
  if (labels.length < 2) {
    return {
      valid: false,
      targetType: 'domain',
      rawInput: raw,
      normalizedValue: asciiDomain,
      metadata: {},
      error: 'Domain must include at least a second-level label and valid TLD.'
    };
  }

  const labelRegex = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
  for (const label of labels) {
    if (!labelRegex.test(label)) {
      return {
        valid: false,
        targetType: 'domain',
        rawInput: raw,
        normalizedValue: asciiDomain,
        metadata: {},
        error: `Invalid DNS label "${label}".`
      };
    }
  }

  const tld = labels[labels.length - 1];
  if (/^\d+$/.test(tld) || tld.length < 2) {
    return {
      valid: false,
      targetType: 'domain',
      rawInput: raw,
      normalizedValue: asciiDomain,
      metadata: {},
      error: `Invalid top-level domain ".${tld}".`
    };
  }

  const unicodeDomain = url.domainToUnicode(asciiDomain);

  return {
    valid: true,
    targetType: 'domain',
    rawInput: raw,
    normalizedValue: asciiDomain,
    metadata: {
      asciiDomain,
      unicodeDomain,
      isInternationalized: asciiDomain !== unicodeDomain,
      tld,
      labelCount: labels.length
    }
  };
}

/**
 * Validates and normalizes an email address (ID-01).
 */
export function validateAndNormalizeEmail(raw: string): NormalizedTargetResult {
  const trimmed = raw.trim();
  const atIndex = trimmed.lastIndexOf('@');
  if (atIndex <= 0 || atIndex === trimmed.length - 1) {
    return {
      valid: false,
      targetType: 'email',
      rawInput: raw,
      normalizedValue: trimmed.toLowerCase(),
      metadata: {},
      error: 'Invalid email address format (missing @ separator).'
    };
  }

  const localPart = trimmed.slice(0, atIndex);
  const domainPart = trimmed.slice(atIndex + 1);

  if (
    localPart.length > 64 ||
    !/^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+$/.test(localPart) ||
    localPart.startsWith('.') ||
    localPart.endsWith('.') ||
    localPart.includes('..')
  ) {
    return {
      valid: false,
      targetType: 'email',
      rawInput: raw,
      normalizedValue: trimmed.toLowerCase(),
      metadata: {},
      error: 'Invalid email local-part syntax.'
    };
  }

  const domainValidation = validateAndNormalizeDomain(domainPart);
  if (!domainValidation.valid) {
    return {
      valid: false,
      targetType: 'email',
      rawInput: raw,
      normalizedValue: trimmed.toLowerCase(),
      metadata: {},
      error: `Invalid email domain: ${domainValidation.error}`
    };
  }

  const normalizedEmail = `${localPart.toLowerCase()}@${domainValidation.normalizedValue}`;
  const plusSplit = localPart.toLowerCase().split('+');

  return {
    valid: true,
    targetType: 'email',
    rawInput: raw,
    normalizedValue: normalizedEmail,
    metadata: {
      localPart: localPart.toLowerCase(),
      baseLocalPart: plusSplit[0],
      subaddressTag: plusSplit.length > 1 ? plusSplit.slice(1).join('+') : null,
      domain: domainValidation.normalizedValue,
      unicodeDomain: domainValidation.metadata.unicodeDomain
    }
  };
}

/**
 * Validates an IPv4 or IPv6 address and blocks private/internal addresses from external OSINT transmission (NET-01).
 */
export function validateAndNormalizeIp(raw: string): NormalizedTargetResult {
  const classification = classifyIpAddress(raw);
  if (classification.version === 0) {
    return {
      valid: false,
      targetType: 'ip',
      rawInput: raw,
      normalizedValue: classification.ip,
      metadata: {},
      error: classification.reason || 'Invalid IPv4 or IPv6 address.'
    };
  }

  if (classification.isBlocked) {
    return {
      valid: false,
      targetType: 'ip',
      rawInput: raw,
      normalizedValue: classification.ip,
      metadata: {
        version: classification.version,
        isPrivateOrReserved: true,
        reason: classification.reason
      },
      error: `Private, loopback, or reserved IP address (${classification.reason}) cannot be sent to external OSINT providers.`
    };
  }

  return {
    valid: true,
    targetType: 'ip',
    rawInput: raw,
    normalizedValue: classification.ip.toLowerCase(),
    metadata: {
      ipVersion: `IPv${classification.version}`,
      isPublic: true
    }
  };
}

/**
 * Validates and normalizes a URL target (WEB-01).
 */
export function validateAndNormalizeUrl(raw: string): NormalizedTargetResult {
  const trimmed = raw.trim();
  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    return {
      valid: false,
      targetType: 'url',
      rawInput: raw,
      normalizedValue: trimmed,
      metadata: {},
      error: 'Invalid URL syntax. Include http:// or https:// scheme.'
    };
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return {
      valid: false,
      targetType: 'url',
      rawInput: raw,
      normalizedValue: trimmed,
      metadata: {},
      error: `Unsupported URL scheme "${parsed.protocol}". Only http: and https: are allowed.`
    };
  }

  if (parsed.username || parsed.password) {
    return {
      valid: false,
      targetType: 'url',
      rawInput: raw,
      normalizedValue: trimmed,
      metadata: {},
      error: 'URLs containing embedded credentials are not permitted.'
    };
  }

  const allowedPorts = new Set(['', '80', '443', '8080', '8443']);
  if (!allowedPorts.has(parsed.port)) {
    return {
      valid: false,
      targetType: 'url',
      rawInput: raw,
      normalizedValue: trimmed,
      metadata: {},
      error: `Port "${parsed.port}" is not permitted. Only standard HTTP/HTTPS ports (80, 443, 8080, 8443) are allowed.`
    };
  }

  const hostCheck = isBlockedHostname(parsed.hostname);
  if (hostCheck.blocked) {
    return {
      valid: false,
      targetType: 'url',
      rawInput: raw,
      normalizedValue: trimmed,
      metadata: {},
      error: hostCheck.reason || 'Blocked internal URL destination.'
    };
  }

  return {
    valid: true,
    targetType: 'url',
    rawInput: raw,
    normalizedValue: parsed.toString(),
    metadata: {
      protocol: parsed.protocol,
      hostname: parsed.hostname,
      pathname: parsed.pathname,
      port: parsed.port || (parsed.protocol === 'https:' ? '443' : '80')
    }
  };
}

/**
 * Validates and normalizes a cryptographic file hash (MD5, SHA-1, SHA-256) (THR-01).
 */
export function validateAndNormalizeFileHash(raw: string): NormalizedTargetResult {
  const cleaned = raw.trim().toLowerCase();
  let algorithm: 'MD5' | 'SHA-1' | 'SHA-256' | null = null;

  if (/^[a-f0-9]{32}$/.test(cleaned)) {
    algorithm = 'MD5';
  } else if (/^[a-f0-9]{40}$/.test(cleaned)) {
    algorithm = 'SHA-1';
  } else if (/^[a-f0-9]{64}$/.test(cleaned)) {
    algorithm = 'SHA-256';
  }

  if (!algorithm) {
    return {
      valid: false,
      targetType: 'file_hash',
      rawInput: raw,
      normalizedValue: cleaned,
      metadata: {},
      error:
        'Invalid file hash. Expected a valid hexadecimal MD5 (32 chars), SHA-1 (40 chars), or SHA-256 (64 chars).'
    };
  }

  return {
    valid: true,
    targetType: 'file_hash',
    rawInput: raw,
    normalizedValue: cleaned,
    metadata: {
      algorithm,
      bitLength: cleaned.length * 4
    }
  };
}

/**
 * Validates and normalizes a phone number using ITU numbering rules (ID-07, ID-08).
 */
export function validateAndNormalizePhone(
  raw: string,
  defaultCountry: 'US' | 'GB' | 'CA' | 'DE' | 'AU' = 'US'
): NormalizedTargetResult {
  const trimmed = raw.trim();
  const parsed = parsePhoneNumberFromString(
    trimmed,
    trimmed.startsWith('+') ? undefined : defaultCountry
  );

  if (!parsed || !parsed.isValid()) {
    return {
      valid: false,
      targetType: 'phone',
      rawInput: raw,
      normalizedValue: trimmed,
      metadata: {},
      error:
        'Invalid phone number format. Provide an international E.164 phone number (e.g. +14155552671).'
    };
  }

  return {
    valid: true,
    targetType: 'phone',
    rawInput: raw,
    normalizedValue: parsed.number, // E.164
    metadata: {
      e164: parsed.number,
      internationalFormat: parsed.formatInternational(),
      nationalFormat: parsed.formatNational(),
      countryCallingCode: `+${parsed.countryCallingCode}`,
      countryIso: parsed.country || 'Unknown',
      isPossible: parsed.isPossible()
    }
  };
}

/**
 * Validates and normalizes a username handle (ID-05, SOC-01).
 */
export function validateAndNormalizeUsername(raw: string): NormalizedTargetResult {
  const cleaned = raw.trim().replace(/^@/, '');
  if (!/^[a-zA-Z0-9._-]{2,64}$/.test(cleaned)) {
    return {
      valid: false,
      targetType: 'username',
      rawInput: raw,
      normalizedValue: cleaned,
      metadata: {},
      error:
        'Username must be 2–64 characters and contain only letters, digits, underscores, hyphens, or dots.'
    };
  }

  return {
    valid: true,
    targetType: 'username',
    rawInput: raw,
    normalizedValue: cleaned,
    metadata: {
      length: cleaned.length
    }
  };
}

/**
 * Validates and normalizes an organization name (ORG-01).
 */
export function validateAndNormalizeOrganization(raw: string): NormalizedTargetResult {
  const cleaned = sanitizeText(raw, 160);
  if (cleaned.length < 2 || cleaned.length > 160) {
    return {
      valid: false,
      targetType: 'organization',
      rawInput: raw,
      normalizedValue: cleaned,
      metadata: {},
      error: 'Organization name must be between 2 and 160 characters.'
    };
  }

  return {
    valid: true,
    targetType: 'organization',
    rawInput: raw,
    normalizedValue: cleaned,
    metadata: {}
  };
}

/**
 * Automatically detects target type when not explicitly specified, then validates and normalizes.
 */
export function classifyAndValidateTarget(
  rawInput: string,
  explicitType?: TargetType
): NormalizedTargetResult {
  const trimmed = rawInput.trim();

  if (explicitType) {
    switch (explicitType) {
      case 'email':
        return validateAndNormalizeEmail(trimmed);
      case 'domain':
        return validateAndNormalizeDomain(trimmed);
      case 'ip':
        return validateAndNormalizeIp(trimmed);
      case 'url':
        return validateAndNormalizeUrl(trimmed);
      case 'file_hash':
        return validateAndNormalizeFileHash(trimmed);
      case 'phone':
        return validateAndNormalizePhone(trimmed);
      case 'username':
        return validateAndNormalizeUsername(trimmed);
      case 'organization':
        return validateAndNormalizeOrganization(trimmed);
      case 'file':
        return {
          valid: true,
          targetType: 'file',
          rawInput: trimmed,
          normalizedValue: sanitizeText(trimmed, 128),
          metadata: {}
        };
    }
  }

  // Heuristic auto-classification order:
  if (/^https?:\/\//i.test(trimmed)) {
    return validateAndNormalizeUrl(trimmed);
  }
  if (trimmed.includes('@') && !trimmed.includes(' ')) {
    return validateAndNormalizeEmail(trimmed);
  }
  if (net.isIP(trimmed.replace(/^\[|\]$/g, '')) !== 0) {
    return validateAndNormalizeIp(trimmed);
  }
  if (/^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/.test(trimmed)) {
    return validateAndNormalizeFileHash(trimmed);
  }
  if (/^\+?[0-9][0-9 ()-]{6,20}$/.test(trimmed)) {
    const phoneAttempt = validateAndNormalizePhone(trimmed);
    if (phoneAttempt.valid) return phoneAttempt;
  }
  if (
    trimmed.includes('.') &&
    !trimmed.includes(' ') &&
    validateAndNormalizeDomain(trimmed).valid
  ) {
    return validateAndNormalizeDomain(trimmed);
  }
  if (trimmed.includes(' ')) {
    return validateAndNormalizeOrganization(trimmed);
  }
  return validateAndNormalizeUsername(trimmed);
}

export const CreateInvestigationSchema = z.object({
  targetValue: z.string().min(1, 'Target value is required').max(2048),
  targetType: z
    .enum([
      'email',
      'domain',
      'ip',
      'url',
      'username',
      'phone',
      'file_hash',
      'organization',
      'file'
    ])
    .optional(),
  title: z.string().min(2).max(160).optional(),
  scope: z
    .string()
    .min(3, 'Investigation scope is required (e.g. Authorized defensive assessment)')
    .max(500),
  purpose: z
    .string()
    .min(3, 'Investigation purpose is required')
    .max(500),
  externalProviderConsent: z.boolean().default(true),
  caseId: z.string().uuid().optional(),
  tags: z.array(z.string().max(40)).max(15).optional()
});

export const CreateCaseSchema = z.object({
  title: z.string().min(3, 'Case title is required').max(160),
  description: z.string().min(5, 'Case description is required').max(2000),
  scopeAndAuthorization: z
    .string()
    .min(5, 'Scope & authorization notes are required')
    .max(2000),
  status: z.enum(['draft', 'active', 'completed', 'archived']).default('active'),
  priority: z.enum(['low', 'medium', 'high', 'critical']).default('medium'),
  tags: z.array(z.string().max(40)).max(20).default([])
});
