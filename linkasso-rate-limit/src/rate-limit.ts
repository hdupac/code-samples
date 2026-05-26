/**
 * Code sample extracted from Linkasso, a B2B matchmaking platform connecting
 * student associations with corporate partners.
 *
 * What this file demonstrates:
 *   - Adapter pattern: same `Limiter` interface backed by either Upstash Redis
 *     (production, multi-instance) or an in-memory Map (dev/test).
 *   - Production-grade fail-open: if Redis is unreachable, requests pass through
 *     with a structured JSON log, rather than locking users out on infra hiccup.
 *   - Misconfiguration safety: warn-once in prod if the in-memory fallback gets
 *     selected (= the env vars were forgotten on deploy), without spamming logs.
 *   - Tight `server-only` boundary so this never leaks into the client bundle.
 *
 * Business logic and proprietary identifiers have been replaced with placeholder
 * values for confidentiality. Full implementation in private repo.
 *
 * Hippolyte du Pac — 2026
 */

import "server-only";

import { Ratelimit } from "@upstash/ratelimit";
import { Redis } from "@upstash/redis";

// In production (UPSTASH_REDIS_REST_URL + UPSTASH_REDIS_REST_TOKEN set):
//   → @upstash/ratelimit, sliding window, counter shared across Vercel instances.
//
// In dev / test / missing config:
//   → in-memory fallback (Map<string, Bucket>) — fine locally, NOT multi-instance.
//
// Any Upstash error → fail-open (logged). Locking users out because Redis
// hiccuped is worse than letting a few extra requests through.

export type RateLimitResult = {
  success: boolean;
  remaining: number;
  resetAt: number; // epoch millis
};

export type Limiter = {
  check(key: string): Promise<RateLimitResult>;
};

const NAMESPACE = "app";

let fallbackWarned = false;
function warnFallbackOnce(): void {
  if (fallbackWarned) return;
  fallbackWarned = true;
  if (process.env.NODE_ENV === "production") {
    console.warn(
      "[rate-limit] UPSTASH_REDIS_REST_URL/TOKEN missing in prod — falling back to in-memory limiter. Thresholds will NOT hold on multi-instance deploys.",
    );
  }
}

function shouldUseUpstash(): boolean {
  return Boolean(
    process.env.UPSTASH_REDIS_REST_URL && process.env.UPSTASH_REDIS_REST_TOKEN,
  );
}

function createInMemoryLimiter(max: number, windowMs: number): Limiter {
  const buckets = new Map<string, { count: number; resetAt: number }>();

  return {
    async check(key: string): Promise<RateLimitResult> {
      const now = Date.now();
      const existing = buckets.get(key);

      if (!existing || existing.resetAt <= now) {
        const resetAt = now + windowMs;
        buckets.set(key, { count: 1, resetAt });
        return { success: true, remaining: max - 1, resetAt };
      }

      if (existing.count >= max) {
        return { success: false, remaining: 0, resetAt: existing.resetAt };
      }

      existing.count += 1;
      return {
        success: true,
        remaining: max - existing.count,
        resetAt: existing.resetAt,
      };
    },
  };
}

function createUpstashLimiter(
  prefix: string,
  max: number,
  windowSeconds: number,
): Limiter {
  const redis = Redis.fromEnv();
  const ratelimit = new Ratelimit({
    redis,
    limiter: Ratelimit.slidingWindow(max, `${windowSeconds} s`),
    prefix: `${NAMESPACE}:${prefix}`,
    analytics: false,
  });

  return {
    async check(key: string): Promise<RateLimitResult> {
      try {
        const r = await ratelimit.limit(key);
        return { success: r.success, remaining: r.remaining, resetAt: r.reset };
      } catch (err) {
        // Fail-open on Redis outage: better to let traffic through than to
        // 429 every user. Logged so it shows up on the ops dashboard.
        console.error(
          JSON.stringify({
            msg: "rate-limit-redis-down",
            prefix,
            key,
            error: err instanceof Error ? err.message : String(err),
          }),
        );
        return {
          success: true,
          remaining: max,
          resetAt: Date.now() + windowSeconds * 1000,
        };
      }
    },
  };
}

export function createRateLimiter(
  prefix: string,
  max: number,
  windowSeconds: number,
): Limiter {
  if (shouldUseUpstash()) {
    return createUpstashLimiter(prefix, max, windowSeconds);
  }
  warnFallbackOnce();
  return createInMemoryLimiter(max, windowSeconds * 1000);
}
