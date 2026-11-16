import crypto from 'crypto';
import { sanitizeText } from './sanitizer';

export const MAX_UPLOAD_SIZE_BYTES = 10 * 1024 * 1024; // 10 MB

export type SupportedFileCategory = 'image/jpeg' | 'image/png' | 'image/gif' | 'image/webp' | 'application/pdf';

export interface ValidatedFileSignature {
  valid: boolean;
  detectedMime?: SupportedFileCategory;
  extension?: string;
  sizeBytes: number;
  error?: string;
}

export interface FileIntelligenceResult {
  fileName: string;
  detectedMime: SupportedFileCategory;
  sizeBytes: number;
  hashes: {
    md5: string;
    sha1: string;
    sha256: string;
    perceptualDHash: string;
  };
  dimensions?: {
    width: number;
    height: number;
  };
  exifMetadata: Record<string, string | number | boolean>;
  gpsMetadata: {
    hasGps: boolean;
    redactedByDefault: boolean;
    gpsLatitude?: number;
    gpsLongitude?: number;
  };
  pdfMetadata?: {
    pdfVersion: string;
    pageCountEstimate: number;
    title?: string;
    author?: string;
    subject?: string;
    creator?: string;
    producer?: string;
    creationDate?: string;
    modDate?: string;
    isEncrypted: boolean;
    containsJavaScriptOrLaunchAction: boolean;
    securityWarnings: string[];
  };
  extractedTextSnippet?: string;
  reverseImageWorkflowLinks?: Array<{
    provider: string;
    workflowType: 'manual_investigator_portal';
    url: string;
    notice: string;
  }>;
}

/**
 * Validates file size and binary magic bytes (file signature), rejecting executables, scripts, and oversized buffers.
 */
export function validateUploadedFileBuffer(
  buffer: Buffer,
  fileName = 'upload.bin'
): ValidatedFileSignature {
  if (!Buffer.isBuffer(buffer) || buffer.byteLength === 0) {
    return {
      valid: false,
      sizeBytes: 0,
      error: 'Uploaded file buffer is empty.'
    };
  }

  if (buffer.byteLength > MAX_UPLOAD_SIZE_BYTES) {
    return {
      valid: false,
      sizeBytes: buffer.byteLength,
      error: `File size (${buffer.byteLength} bytes) exceeds maximum allowed limit of ${MAX_UPLOAD_SIZE_BYTES} bytes (10 MB).`
    };
  }

  // Block Windows PE (MZ) or Linux ELF binaries explicitly
  if (
    (buffer.byteLength >= 2 && buffer[0] === 0x4d && buffer[1] === 0x5a) ||
    (buffer.byteLength >= 4 &&
      buffer[0] === 0x7f &&
      buffer[1] === 0x45 &&
      buffer[2] === 0x4c &&
      buffer[3] === 0x46)
  ) {
    return {
      valid: false,
      sizeBytes: buffer.byteLength,
      error: 'Executable binary signatures (PE/ELF) are strictly prohibited.'
    };
  }

  // Block HTML/SVG/Script polyglot headers
  const headAscii = buffer.subarray(0, Math.min(256, buffer.byteLength)).toString('utf8').toLowerCase();
  if (
    headAscii.includes('<script') ||
    headAscii.includes('<!doctype html') ||
    headAscii.includes('<html') ||
    headAscii.includes('<svg')
  ) {
    return {
      valid: false,
      sizeBytes: buffer.byteLength,
      error: 'HTML, SVG, or active script payloads are prohibited.'
    };
  }

  // JPEG: FF D8 FF
  if (
    buffer.byteLength >= 4 &&
    buffer[0] === 0xff &&
    buffer[1] === 0xd8 &&
    buffer[2] === 0xff
  ) {
    return {
      valid: true,
      detectedMime: 'image/jpeg',
      extension: 'jpg',
      sizeBytes: buffer.byteLength
    };
  }

  // PNG: 89 50 4E 47 0D 0A 1A 0A
  if (
    buffer.byteLength >= 8 &&
    buffer[0] === 0x89 &&
    buffer[1] === 0x50 &&
    buffer[2] === 0x4e &&
    buffer[3] === 0x47 &&
    buffer[4] === 0x0d &&
    buffer[5] === 0x0a &&
    buffer[6] === 0x1a &&
    buffer[7] === 0x0a
  ) {
    return {
      valid: true,
      detectedMime: 'image/png',
      extension: 'png',
      sizeBytes: buffer.byteLength
    };
  }

  // GIF: GIF87a or GIF89a
  if (
    buffer.byteLength >= 6 &&
    buffer[0] === 0x47 &&
    buffer[1] === 0x49 &&
    buffer[2] === 0x46 &&
    buffer[3] === 0x38 &&
    (buffer[4] === 0x37 || buffer[4] === 0x39) &&
    buffer[5] === 0x61
  ) {
    return {
      valid: true,
      detectedMime: 'image/gif',
      extension: 'gif',
      sizeBytes: buffer.byteLength
    };
  }

  // WebP: RIFF....WEBP
  if (
    buffer.byteLength >= 12 &&
    buffer.subarray(0, 4).toString('ascii') === 'RIFF' &&
    buffer.subarray(8, 12).toString('ascii') === 'WEBP'
  ) {
    return {
      valid: true,
      detectedMime: 'image/webp',
      extension: 'webp',
      sizeBytes: buffer.byteLength
    };
  }

  // PDF: %PDF-
  if (
    buffer.byteLength >= 5 &&
    buffer.subarray(0, 5).toString('ascii') === '%PDF-'
  ) {
    return {
      valid: true,
      detectedMime: 'application/pdf',
      extension: 'pdf',
      sizeBytes: buffer.byteLength
    };
  }

  return {
    valid: false,
    sizeBytes: buffer.byteLength,
    error: `Unsupported or unrecognized file signature for "${sanitizeText(fileName, 64)}". Only JPEG, PNG, GIF, WebP, and PDF files are permitted.`
  };
}

/**
 * Computes deterministic 64-bit perceptual difference hash (dHash) over 64 evenly sampled regions of the payload.
 */
export function computePerceptualDHash(buffer: Buffer): string {
  const samples = new Array<number>(65).fill(0);
  const startOffset = Math.min(32, Math.floor(buffer.byteLength / 4));
  const usableLength = Math.max(1, buffer.byteLength - startOffset);

  for (let i = 0; i < 65; i++) {
    const idx = startOffset + Math.floor((i * usableLength) / 65);
    const windowEnd = Math.min(buffer.byteLength, idx + 16);
    let sum = 0;
    let count = 0;
    for (let j = idx; j < windowEnd; j++) {
      sum += buffer[j];
      count++;
    }
    samples[i] = count > 0 ? sum / count : 0;
  }

  let bits = BigInt(0);
  for (let i = 0; i < 64; i++) {
    if (samples[i] > samples[i + 1]) {
      bits |= BigInt(1) << BigInt(63 - i);
    }
  }
  return bits.toString(16).padStart(16, '0');
}

export function computeHammingDistanceHex(hashA: string, hashB: string): number {
  if (hashA.length !== 16 || hashB.length !== 16) return 64;
  let xor = BigInt(`0x${hashA}`) ^ BigInt(`0x${hashB}`);
  let dist = 0;
  while (xor > BigInt(0)) {
    dist += Number(xor & BigInt(1));
    xor >>= BigInt(1);
  }
  return dist;
}

/**
 * Safe binary JPEG EXIF parser (APP1 Exif TIFF header + SOF0/SOF2 dimensions).
 */
function parseJpegExifAndDimensions(buffer: Buffer): {
  dimensions?: { width: number; height: number };
  exif: Record<string, string | number | boolean>;
  gps?: { latitude: number; longitude: number };
} {
  const exif: Record<string, string | number | boolean> = {};
  let dimensions: { width: number; height: number } | undefined;
  let gps: { latitude: number; longitude: number } | undefined;

  let offset = 2; // Skip FF D8
  while (offset + 4 < buffer.byteLength) {
    if (buffer[offset] !== 0xff) {
      offset++;
      continue;
    }
    const marker = buffer[offset + 1];
    if (marker === 0xd9 || marker === 0xda) break; // EOI or SOS

    const segLength = buffer.readUInt16BE(offset + 2);
    if (segLength < 2 || offset + 2 + segLength > buffer.byteLength) break;

    // SOF0 (0xC0) or SOF2 (0xC2) for image dimensions
    if (
      (marker === 0xc0 || marker === 0xc2) &&
      offset + 9 <= buffer.byteLength
    ) {
      const height = buffer.readUInt16BE(offset + 5);
      const width = buffer.readUInt16BE(offset + 7);
      if (width > 0 && height > 0) {
        dimensions = { width, height };
      }
    }

    // APP1 (0xE1) Exif segment
    if (
      marker === 0xe1 &&
      segLength > 14 &&
      buffer.subarray(offset + 4, offset + 10).toString('ascii') === 'Exif\0\0'
    ) {
      const tiffStart = offset + 10;
      const endianMark = buffer.subarray(tiffStart, tiffStart + 2).toString('ascii');
      const isLE = endianMark === 'II';
      const readU16 = (pos: number) =>
        isLE ? buffer.readUInt16LE(pos) : buffer.readUInt16BE(pos);
      const readU32 = (pos: number) =>
        isLE ? buffer.readUInt32LE(pos) : buffer.readUInt32BE(pos);

      const readRational = (pos: number): number => {
        if (pos + 8 > buffer.byteLength) return 0;
        const num = readU32(pos);
        const den = readU32(pos + 4);
        return den === 0 ? 0 : num / den;
      };

      const parseIfd = (ifdOffset: number, isGps = false) => {
        const dirStart = tiffStart + ifdOffset;
        if (dirStart + 2 > buffer.byteLength) return;
        const numEntries = readU16(dirStart);
        let latSign = 1;
        let lonSign = 1;
        let latDeg: number | undefined;
        let lonDeg: number | undefined;

        for (let i = 0; i < Math.min(numEntries, 64); i++) {
          const entryPos = dirStart + 2 + i * 12;
          if (entryPos + 12 > buffer.byteLength) break;
          const tag = readU16(entryPos);
          const type = readU16(entryPos + 2);
          const count = readU32(entryPos + 4);
          const valOffset = entryPos + 8;

          if (isGps) {
            if (tag === 0x0001) {
              const ref = String.fromCharCode(buffer[valOffset]);
              if (ref === 'S') latSign = -1;
            } else if (tag === 0x0003) {
              const ref = String.fromCharCode(buffer[valOffset]);
              if (ref === 'W') lonSign = -1;
            } else if (tag === 0x0002 && type === 5 && count === 3) {
              const rPos = tiffStart + readU32(valOffset);
              const d = readRational(rPos);
              const m = readRational(rPos + 8);
              const s = readRational(rPos + 16);
              latDeg = d + m / 60 + s / 3600;
            } else if (tag === 0x0004 && type === 5 && count === 3) {
              const rPos = tiffStart + readU32(valOffset);
              const d = readRational(rPos);
              const m = readRational(rPos + 8);
              const s = readRational(rPos + 16);
              lonDeg = d + m / 60 + s / 3600;
            }
            continue;
          }

          // ASCII string tags (type === 2)
          if (type === 2 && count > 0 && count < 256) {
            const strPos = count <= 4 ? valOffset : tiffStart + readU32(valOffset);
            if (strPos + count <= buffer.byteLength) {
              const val = sanitizeText(
                buffer.subarray(strPos, strPos + count).toString('utf8'),
                128
              );
              if (tag === 0x010f) exif.Make = val;
              if (tag === 0x0110) exif.Model = val;
              if (tag === 0x0131) exif.Software = val;
              if (tag === 0x0132) exif.DateTime = val;
              if (tag === 0x013b) exif.Artist = val;
              if (tag === 0x9003) exif.DateTimeOriginal = val;
              if (tag === 0x9004) exif.DateTimeDigitized = val;
            }
          } else if (type === 3 && count === 1) {
            const shortVal = readU16(valOffset);
            if (tag === 0x0112) exif.Orientation = shortVal;
            if (tag === 0x8827) exif.ISOSpeedRatings = shortVal;
          } else if (tag === 0x8769) {
            // Exif SubIFD
            parseIfd(readU32(valOffset), false);
          } else if (tag === 0x8825) {
            // GPS Info IFD
            parseIfd(readU32(valOffset), true);
          }
        }

        if (isGps && latDeg !== undefined && lonDeg !== undefined) {
          gps = {
            latitude: Number((latDeg * latSign).toFixed(6)),
            longitude: Number((lonDeg * lonSign).toFixed(6))
          };
        }
      };

      if (tiffStart + 8 <= buffer.byteLength) {
        const firstIfdOffset = readU32(tiffStart + 4);
        parseIfd(firstIfdOffset, false);
      }
    }

    offset += 2 + segLength;
  }

  return { dimensions, exif, gps };
}

/**
 * Safe PNG IHDR and tEXt chunk inspector.
 */
function parsePngMetadata(buffer: Buffer): {
  dimensions?: { width: number; height: number };
  exif: Record<string, string | number | boolean>;
} {
  const exif: Record<string, string | number | boolean> = {};
  let dimensions: { width: number; height: number } | undefined;

  let offset = 8; // Skip 8-byte PNG signature
  while (offset + 12 <= buffer.byteLength) {
    const length = buffer.readUInt32BE(offset);
    const chunkType = buffer.subarray(offset + 4, offset + 8).toString('ascii');
    const dataStart = offset + 8;
    const dataEnd = dataStart + length;
    if (dataEnd + 4 > buffer.byteLength) break;

    if (chunkType === 'IHDR' && length >= 13) {
      const width = buffer.readUInt32BE(dataStart);
      const height = buffer.readUInt32BE(dataStart + 4);
      const bitDepth = buffer[dataStart + 8];
      const colorType = buffer[dataStart + 9];
      dimensions = { width, height };
      exif.BitDepth = bitDepth;
      exif.ColorType = colorType;
    } else if (chunkType === 'tEXt' && length > 1 && length < 1024) {
      const raw = buffer.subarray(dataStart, dataEnd).toString('latin1');
      const sep = raw.indexOf('\0');
      if (sep > 0) {
        const key = sanitizeText(raw.slice(0, sep), 64);
        const val = sanitizeText(raw.slice(sep + 1), 256);
        if (key && val) exif[`PNG_${key}`] = val;
      }
    } else if (chunkType === 'IEND') {
      break;
    }

    offset = dataEnd + 4; // Skip 4-byte CRC
  }

  return { dimensions, exif };
}

/**
 * Safe PDF binary header, dictionary metadata, and active-content warning inspector (IMG-05, IMG-06).
 * Never executes PDF streams or macros.
 */
function parseSafePdfMetadata(buffer: Buffer): NonNullable<
  FileIntelligenceResult['pdfMetadata']
> {
  const rawStr = buffer.subarray(0, Math.min(buffer.byteLength, 256 * 1024)).toString('latin1');

  const verMatch = rawStr.match(/^%PDF-(\d+\.\d+)/);
  const pdfVersion = verMatch ? verMatch[1] : '1.x';

  const extractField = (field: string): string | undefined => {
    const regex = new RegExp(`\\/${field}\\s*\\(([^\\)]{1,256})\\)`, 'i');
    const m = rawStr.match(regex);
    return m ? sanitizeText(m[1], 180) : undefined;
  };

  const pageMatches = rawStr.match(/\/Type\s*\/Page\b/g);
  const pageCountEstimate = pageMatches ? pageMatches.length : 1;

  const isEncrypted = /\/Encrypt\b/.test(rawStr);
  const hasJs = /\/JS\b|\/JavaScript\b/i.test(rawStr);
  const hasLaunch = /\/Launch\b|\/EmbeddedFiles\b|\/OpenAction\b/i.test(rawStr);

  const securityWarnings: string[] = [];
  if (hasJs) {
    securityWarnings.push(
      'PDF contains /JS or /JavaScript dictionary references (not executed by Sentinel).'
    );
  }
  if (hasLaunch) {
    securityWarnings.push(
      'PDF contains /Launch, /OpenAction, or /EmbeddedFiles directives.'
    );
  }
  if (isEncrypted) {
    securityWarnings.push('PDF contains an /Encrypt dictionary.');
  }

  return {
    pdfVersion,
    pageCountEstimate,
    title: extractField('Title'),
    author: extractField('Author'),
    subject: extractField('Subject'),
    creator: extractField('Creator'),
    producer: extractField('Producer'),
    creationDate: extractField('CreationDate'),
    modDate: extractField('ModDate'),
    isEncrypted,
    containsJavaScriptOrLaunchAction: hasJs || hasLaunch,
    securityWarnings
  };
}

/**
 * Inspects an uploaded file buffer safely in memory, computing hashes, metadata, and redacted location indicators.
 */
export function inspectUploadedFile(
  buffer: Buffer,
  fileName: string
): FileIntelligenceResult {
  const sig = validateUploadedFileBuffer(buffer, fileName);
  if (!sig.valid || !sig.detectedMime) {
    throw new Error(sig.error || 'Invalid file upload');
  }

  const md5 = crypto.createHash('md5').update(buffer).digest('hex');
  const sha1 = crypto.createHash('sha1').update(buffer).digest('hex');
  const sha256 = crypto.createHash('sha256').update(buffer).digest('hex');
  const perceptualDHash = computePerceptualDHash(buffer);

  let dimensions: { width: number; height: number } | undefined;
  let exifMetadata: Record<string, string | number | boolean> = {};
  let gpsMetadata: FileIntelligenceResult['gpsMetadata'] = {
    hasGps: false,
    redactedByDefault: true
  };
  let pdfMetadata: FileIntelligenceResult['pdfMetadata'] | undefined;
  let extractedTextSnippet: string | undefined;

  if (sig.detectedMime === 'image/jpeg') {
    const parsed = parseJpegExifAndDimensions(buffer);
    dimensions = parsed.dimensions;
    exifMetadata = parsed.exif;
    if (parsed.gps) {
      gpsMetadata = {
        hasGps: true,
        redactedByDefault: true,
        gpsLatitude: parsed.gps.latitude,
        gpsLongitude: parsed.gps.longitude
      };
    }
  } else if (sig.detectedMime === 'image/png') {
    const parsed = parsePngMetadata(buffer);
    dimensions = parsed.dimensions;
    exifMetadata = parsed.exif;
  } else if (sig.detectedMime === 'application/pdf') {
    pdfMetadata = parseSafePdfMetadata(buffer);
    if (pdfMetadata.title) exifMetadata.Title = pdfMetadata.title;
    if (pdfMetadata.author) exifMetadata.Author = pdfMetadata.author;
    if (pdfMetadata.creator) exifMetadata.Creator = pdfMetadata.creator;
    if (pdfMetadata.producer) exifMetadata.Producer = pdfMetadata.producer;
  }

  // Extract printable text tokens safely (IMG-04 local OCR / text stream extraction)
  const printableMatches = buffer
    .subarray(0, Math.min(buffer.byteLength, 65536))
    .toString('latin1')
    .match(/[A-Za-z0-9][A-Za-z0-9 .,:/@_-]{7,120}/g);
  if (printableMatches && printableMatches.length > 0) {
    extractedTextSnippet = sanitizeText(
      printableMatches.slice(0, 15).join(' | '),
      600
    );
  }

  const reverseImageWorkflowLinks =
    sig.detectedMime.startsWith('image/')
      ? [
          {
            provider: 'Google Lens (Manual Investigator Portal)',
            workflowType: 'manual_investigator_portal' as const,
            url: 'https://lens.google.com/',
            notice:
              'Manual reference workflow only. Sentinel never uploads private evidence images to third-party portals without explicit consent.'
          },
          {
            provider: 'TinEye Reverse Image Search (Manual Portal)',
            workflowType: 'manual_investigator_portal' as const,
            url: 'https://tineye.com/',
            notice:
              'Manual reference workflow only. No automated external file upload was performed.'
          }
        ]
      : undefined;

  return {
    fileName: sanitizeText(fileName, 128),
    detectedMime: sig.detectedMime,
    sizeBytes: buffer.byteLength,
    hashes: {
      md5,
      sha1,
      sha256,
      perceptualDHash
    },
    dimensions,
    exifMetadata,
    gpsMetadata,
    pdfMetadata,
    extractedTextSnippet,
    reverseImageWorkflowLinks
  };
}
