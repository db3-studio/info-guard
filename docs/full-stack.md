# Info Guard — the full stack (roadmap)

This repo ships the **redaction layer** only: the patch, the matcher, the
test battery, and this documentation. That is the transferable core — it
works with zero other infrastructure, installs in minutes, and its value is
immediate (your exact secrets stop appearing in tool output, logs, and
transcripts).

Redaction is one layer of a five-layer lifecycle. The remaining four layers
are **deployment-specific**: they depend on where your secrets live, how you
rotate them, and how you want to be alerted. This document is the blueprint —
enough detail that any Hermes agent (or engineer) can build them for a given
environment, the way they were built and proven in the reference deployment.

## The doctrine

**Discover → register → mask → detect → rotate.**

- *Discover*: inventory every secret source (`.env` files, docker compose
  envs, app configs, vault).
- *Register*: every discovered secret gets a registry entry (hashed — never
  plaintext) before its first config read.
- *Mask*: the registered values flow into the pattern file (this repo's
  `info-guard build`); masking is display-only and can never corrupt sources.
- *Detect*: scheduled scans watch transcripts, logs, and repos for registered
  values appearing where they shouldn't.
- *Rotate*: confirmed exposure triggers rotation — vault first, then every
  consumer, then verify old-fails/new-passes.

The layers below are each proven, independent, and incremental: build them in
order, and each one pays for itself.

---

## Layer 2 — Secret inventory (register)

A hashed registry of every known secret with priority tiers. Feeds both
detection (what to scan for) and the matcher (which values get full-mask).

**State file** `<state>/info-guard/known_secrets.json` (chmod 600):

```json
{
  "schema": 2,
  "secrets": [
    {
      "id": "<sha256 of key>",
      "key": "SOME_API_KEY",
      "hash": "<sha256 of value, peppered>",
      "priority": "critical|high|medium|low",
      "source": "env|appconfig|honeytoken|retired",
      "rotation": {"method": "agent|user", "owner": "API/script|UI"},
      "registered": "2026-08-13T00:00:00Z"
    }
  ]
}
```

Clues for the builder:

- **Pepper**: a dedicated env key (`SECRET_INVENTORY_PEPPER`) — hashes are
  `sha256(pepper + value)`, so a leaked registry file is not a lookup table.
- **Priority tiers** (first match wins): spend/org credentials and
  email/password pairs = `critical`; API keys = `high`; local service
  passwords = `medium`; everything else = `low`. Critical values get
  `"mask": "full"` in the pattern file — top-tier secrets never show even a
  two-character fragment.
- **Sources**: `.env` files (repo, daemon, docker compose dirs), app configs
  (per-app env files), honeytokens. Nightly rebuild reconciles reality.
- **Retention**: retired entries are pruned after 30 days (they are expected
  residue — detection classifies them separately, see Layer 3).
- **Key-shape warning**: keys not matching the built-in keyword families
  (KEY/PASS/PW/TOKEN/SECRET...) rely solely on exact-value matching — the
  inventory warns on them so they get registered deliberately.

## Layer 3 — Detection (detect)

Scheduled, silent-when-clean scanners. The reference deployment runs:

| Scanner | Schedule | What it does |
|---|---|---|
| **Preflight (`info-guard preflight`)** | on demand, before install | Zero-config leak scan of Hermes' own transcripts/logs — key-shape regexes + gitleaks tuned ruleset; the same two passes the scheduled scanner runs, without needing a registry. This is the entry point: run it first, schedule it after |
| Leak scan | every 6h | Scans transcripts, logs, and request dumps for registry values, key-shaped secrets, and token-shaped values |
| HIBP exposed check | weekly | Compares registry hashes against haveibeenpwned's exposed-password API |
| gitleaks discovery | nightly | Scans new app configs/repos for unregistered secrets |

**Tiering** (what fires an alert, and at what severity):

- `CONFIRMED` — exact registry-hash match: rotate (critical/high =
  immediate; `retired` class = expected residue, verify no active use).
- `HONEYTOKEN` — a canary value appeared: critical (canaries only exist to
  be touched).
- `HIGH-CONFIDENCE` — gitleaks/generic rule match: register or rotate.
- `SUSPICIOUS` — pattern near-match: human review list, not an alert.

Clues for the builder:

- **Honeytokens**: 3 unique token-shaped canaries seeded into the pattern
  file (so they're masked) AND the registry (so their appearance fires).
  They are also the live proof that masking + detection both work.
- **Alert shape**: silent when clean (a cron tick with no findings produces
  zero output — no alert fatigue), descriptive email subject lines when it
  fires. Delivery target must be a real platform (email), never a session
  that may not exist — a lost alert is worse than none.
- **False-positive classes to exclude by design**: code identifiers
  (`password_hash =`, `set_password`), host/URL/username values, non-secret
  keys (the same exclusion list the matcher uses). Exclusions are
  *exact-hash or explicit-rule* based, never substring guessing.

## Layer 4 — Response (rotate)

Rotation is per-credential: one script per credential class, driven by a
driver with `--full` (all) and targeted modes.

Clues for the builder:

- **Vault-first**: new values are generated and stored in the password
  manager before anything else changes; every consumer picks up the new
  value from the vault — no value ever transits a chat or a shell history.
- **New-value shape**: `key_` + 28 random alphanumerics (≥32 total) —
  self-protecting, because gitleaks' generic rules and token-shape detection
  catch it even if registration is ever missed.
- **Classes**: agent-automatable (API/script credentials) vs user-touch
  (SSO/UI passwords — the user changes them in the UI; the agent verifies).
- **Order**: change the source first, then consumers, then verify
  old-fails / new-passes, then update inventory + pattern file, then
  re-scan to confirm the old value no longer appears anywhere.
- **Drill**: a quarterly scheduled full rotation proves the machinery works
  before an incident needs it.

## Layer 5 — Watchdogs & hygiene (operate)

Small scheduled checks that catch drift before it becomes a leak:

| Check | Schedule | Detects |
|---|---|---|
| Env-drift watchdog | weekly | `.env` files changed without the inventory being rebuilt (silent when clean, email on drift) |
| Config-audit | on change | New/changed config keys in tracked files (diff-based, with an ignore list for known benign churn) |
| Nightly refresh | daily | Rebuild inventory + pattern file, re-run discovery — the "forgot to register" safety net |

## Known failure modes (learned the hard way)

These are the silent-fail classes that make redaction look like it's working
when it isn't. Any implementation of this stack should test for them:

1. **Remapped HOME / relocated install** — hardcoded `~/.hermes` paths in
   tooling silently no-op under a profile or container home. Everything must
   resolve `$HERMES_HOME` with `~/.hermes` fallback. The test battery in
   this repo (test 6) proves the property.
2. **Stale processes** — the agent has multiple surfaces (CLI, gateway,
   web UI) running separate processes. New redaction code requires a restart
   of **all** of them; restarting one leaves the others masking nothing.
3. **Surfaces without the bridge** — a surface that doesn't run Hermes'
   redactor, or ignores the config key, silently uses the default path.
   The default path is the only truly universal option.
4. **Watchdog delivery dead-ends** — jobs delivering to a session/chat that
   isn't guaranteed to exist lose their alert exactly when it matters.
   Deliver to a stable platform.
5. **Patch drift after update** — `hermes update` can overwrite patched
   files. The installer is marker-guarded and fails loudly; the permanent
   fix is the upstream PR (see README).

## Building order for a new deployment

1. Install this repo (redaction) — immediate value, zero dependencies.
2. Layer 2 inventory (needed before detection can be meaningful).
3. Layer 3 detection (needed before rotation is ever triggered).
4. Layer 4 rotation for the two highest-priority credential classes.
5. Layer 5 watchdogs, in the order above.

Each layer's tests: the previous layer's pattern file + one synthetic probe
through the full path (mask → detect → alert → rotate → verify).
