# Sewa Setu MCP Assessment — One-Page Design Note

**Candidate:** Sujal Pandya  
**Repository:** `sewasetu-assistant`  
**Date:** 2026-10-29

---

## Three Decisions That Mattered

### 1. Server-Side Identity Binding from JWT Claims (No Caller-Supplied Identity)

Every MCP tool that touches citizen or officer data extracts identity exclusively from the verified RS256 JWT `sub` claim (`citizen:<mobile>` or `officer:<username>`). The tool schemas deliberately do *not* accept a `mobile_number` or `officer_id` parameter from the caller for identity purposes.

**Why it mattered:** An MCP client is an AI agent; its tool-call arguments are untrusted text. Accepting `mobile_number` from the JSON payload and looking up that citizen's data without token verification would allow any client to impersonate any applicant. Binding identity to the cryptographically signed token — verified against the portal's own JWKS endpoint — eliminates privilege escalation at zero extra implementation cost, and mirrors how the existing portal's `@require_auth` decorator already works.

**Concrete effect:** `get_my_application_status` can only ever return the calling citizen's own records, regardless of what the client sends in the tool arguments.

---

### 2. Native Flask Streamable HTTP over ASGI (Starlette / Uvicorn)

The MCP JSON-RPC 2.0 transport (initialize → tools/list → tools/call, with SSE negotiation header support) was implemented directly as a Flask blueprint (`/mcp/citizen`, `/mcp/officer`) inside the existing Gunicorn sync-worker application — rather than spawning a separate ASGI server.

**Why it mattered:** Introducing `starlette` or `uvicorn` would have required bridging two fundamentally different concurrency models (sync WSGI workers vs. async event loop), duplicating the database connection pool, duplicating the OAuth key cache, and adding a new network hop. The existing portal's session model, `g.db`, request context, and `@require_auth` reuse made the native approach immediate and risk-free.

**Trade-off accepted:** Gunicorn sync workers cannot truly stream indefinitely over SSE — a long-lived SSE connection blocks one worker. For the assessment (short-lived tool calls), this is acceptable. For production, gevent workers or a separate uvicorn sidecar would be the right fix.

---

### 3. Reserved Test-Mobile Prefix (`99900010XX`) with Per-Run Cleanup for Idempotent Evaluations

The evaluation runner issues JWT tokens and creates applications using mobile numbers in the reserved range `9990001001–9990001009`. Before each scenario begins, any existing application for that mobile is cleaned up inside a transaction. The 100,000-row production seed is never touched.

**Why it mattered:** The seed data is the evaluation baseline. Accidentally approving, rejecting, or withdrawing one of the 100k real applications during testing would corrupt the evaluator's ability to independently test officer decisions. The reserved-prefix approach gives each test a clean, deterministic starting state across unlimited re-runs, without requiring `docker compose down -v` (which would delete the seed).

**Concrete safety guarantee:** `test_02_database_seed_protection` queries the count of applications with mobile numbers *not* matching the `99900010` prefix before and after evaluation — if that count changes by even one row, the test fails.

---

## The One Decision I Would Change

**Add proper SSE session keepalive with async (gevent) Gunicorn workers.**

The current implementation handles MCP's optional SSE streaming path synchronously — a connected client holds a Gunicorn worker thread for the duration of the session. In a real deployment serving many concurrent AI agents, this would exhaust the worker pool. The fix is straightforward: switch Gunicorn to `gevent` workers (`-k gevent`) and use `gevent.queue.Queue` for SSE event dispatch. This change is entirely backward-compatible with the existing Flask code and would let the portal scale to hundreds of simultaneous MCP sessions without increasing server costs.

I skipped this for the assessment because it would have required load-testing to validate the gevent event loop interaction with psycopg2's connection pool — a non-trivial rabbit hole for a 2-day window. Given production requirements, it is the first thing I would address post-launch.

---

## Summary of Deliverables

| Deliverable | Status |
|---|---|
| `/mcp/citizen` — 7 tools, JWT-bound, Streamable HTTP | ✅ Delivered |
| `/mcp/officer` — 4 tools, JWT-bound, Streamable HTTP | ✅ Delivered |
| 9-scenario automated evaluation runner | ✅ All 9 passing |
| `/eval-dashboard` interactive UI + JSON APIs | ✅ Live |
| 18 automated tests (11 MCP + 7 eval) | ✅ All passing |
| One-page design note | ✅ This document |
| Public deployment (HTTPS, `PUBLIC_BASE_URL`) | ⏳ Pending VM |
| GitHub `sewasetu-assistant` repo + invite `harshnisar` | ⏳ Pending PAT |
| Loom video (3 min, face + screen) | ⏳ Pending recording |
