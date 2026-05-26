# Linkasso — Rate Limiter (sample)

**Problem.** A B2B SaaS where authenticated actions (signup, contact reveals,
brief submissions) need to be rate-limited per user and per IP across multiple
Vercel serverless instances — without locking users out when the rate-limit
backend itself has a bad minute.

**My role.** Solo founder / sole engineer.

**Stack.** Next.js 15 (App Router, server components), Supabase (Postgres, RLS,
Auth), Stripe Billing, Resend, Upstash Redis, deployed on Vercel.

**State.** Live with paying customers (pilot tier).

**One number.** Rate-limit middleware sits in front of every authenticated
mutation endpoint with zero observed user-visible 5xx attributable to the
limiter since deploy.

The file in `src/` is the production rate-limit adapter — one of ~40 files in
the private repo. Full codebase walkthrough available on request.
