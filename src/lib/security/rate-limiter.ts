export interface RateLimitCheckResult {
  allowed: boolean;
  limit: number;
  remaining: number;
  resetAt: string;
  retryAfterSeconds: number;
}

interface BucketWindow {
  timestamps: number[];
}

const buckets = new Map<string, BucketWindow>();

/**
 * Sliding-window rate limiter for per-user and per-provider request protection.
 */
export function checkRateLimit(
  bucketKey: string,
  maxRequests: number,
  windowMs = 60_000
): RateLimitCheckResult {
  const now = Date.now();
  const windowStart = now - windowMs;

  let entry = buckets.get(bucketKey);
  if (!entry) {
    entry = { timestamps: [] };
    buckets.set(bucketKey, entry);
  }

  entry.timestamps = entry.timestamps.filter((ts) => ts > windowStart);

  if (entry.timestamps.length >= maxRequests) {
    const oldestInWindow = entry.timestamps[0] ?? now;
    const resetMs = oldestInWindow + windowMs;
    const retryAfterSeconds = Math.max(1, Math.ceil((resetMs - now) / 1000));
    return {
      allowed: false,
      limit: maxRequests,
      remaining: 0,
      resetAt: new Date(resetMs).toISOString(),
      retryAfterSeconds
    };
  }

  entry.timestamps.push(now);
  const remaining = Math.max(0, maxRequests - entry.timestamps.length);
  return {
    allowed: true,
    limit: maxRequests,
    remaining,
    resetAt: new Date(now + windowMs).toISOString(),
    retryAfterSeconds: 0
  };
}

export function resetRateLimitsForTest(): void {
  buckets.clear();
}
