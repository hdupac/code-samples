# Linkasso — Rate Limiter (sample)

**Problem.** A B2B SaaS where authenticated actions (signup, contact reveals,
brief submissions) need to be rate-limited per user and per IP across multiple
Vercel serverless instances — without locking users out when the rate-limit
backend itself has a bad minute.

**My role.** Co-founder, owning backend & infrastructure on a two-person team
(I cover backend / data / payments; my co-founder covers frontend).

**Stack.** Next.js 15 (App Router, server components), Supabase (Postgres, RLS,
Auth), Stripe Billing, Resend, Upstash Redis, deployed on Vercel.

**State.** Pre-launch — V0 MVP, hardening pass in progress before opening a
closed beta with a small set of student associations and corporate partners.

The file in `src/` is the rate-limit adapter from the backend. Full codebase
walkthrough available on request.
