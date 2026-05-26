# code-samples

Selected code samples extracted from private projects.
Each subfolder is one project — see its `README.md` for context.

## Projects

### Linkasso — rate-limit adapter
B2B matchmaking SaaS (Next.js 15 / Supabase / Stripe). The sampled file is the
production rate-limiter: an adapter that runs on Upstash Redis in prod and an
in-memory `Map` in dev, with fail-open behaviour on backend outage and a
warn-once guard when the in-memory path gets selected in production (the
classic forgot-an-env-var bug). Two-person team — I own backend & infra.

→ [`linkasso-rate-limit/`](./linkasso-rate-limit/)

### Production LLM application — prompt-safety layer
A solo-built LLM application running in production for a paying customer.
Project name and domain withheld. The sampled file is the prompt-injection
defense layer — OWASP LLM01-organised pattern detection, XML wrapping with
closing-tag escape, GDPR-aware audit logging. Stack: Python 3.11, Anthropic
Claude.

→ [`llm-prompt-safety/`](./llm-prompt-safety/)

---

Hippolyte du Pac — M1 ESSEC / 
Contact: hippolyte.dupac@gmail.com
