# code-samples

Selected code samples extracted from private projects.
Each subfolder is one project — see its `README.md` for context.

## Projects

### Linkasso — rate-limit adapter
B2B matchmaking SaaS (Next.js 15 / Supabase / Stripe). The sampled file is the
production rate-limiter: an adapter that runs on Upstash Redis in prod and an
in-memory `Map` in dev, with fail-open behaviour on backend outage and a
warn-once guard when the in-memory path gets selected in production (the
classic forgot-an-env-var bug). Solo build, live with paying users.

→ [`linkasso-rate-limit/`](./linkasso-rate-limit/)

---

Hippolyte du Pac — M1 ESSEC
Contact: hippolyte.dupac@gmail.com
