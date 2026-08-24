# Info Guard — the full stack (roadmap)

This repo ships the **product CLI**: the redaction engine (the patch + the
matcher), detection (`preflight`, `watch`, `discover`), rotation mechanics
(`rotate-candidates`, `literals rotate`), the self-sustain commands
(`check --heal`, `update`), the test battery, and this documentation. That is
the transferable core — it works with zero other infrastructure, installs in
minutes, and its value is immediate (your exact secrets stop appearing in
tool output, logs, and transcripts).

Redaction is one layer of a five-layer lifecycle. The product supplies a
mechanism for each layer; what this document describes building is the
**deployment wiring** — where your secrets live, how rotation is driven per
credential class, how you are alerted. This document is the blueprint —
enough detail that any Hermes agent (or engineer) can build it for a given
environment, the way it was built and proven in the reference deployment.

## The doctrine

**Discover → register → mask → detect → rotate.**

- *Discover*: inventory every secret source (`.env` files, docker compose
  envs, app configs, vault).
- *Register*: every discovered secret gets a registry entry (exact value,
  CLI-managed — the registry file is chmod 600, and masking is display-only)
  before its first config read.
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

The inventory backbone is the **product's exact-value registry**
(`custom_literals.json`). There is no separate inventory store to build:
every value you register is the identity source for detection, masking, and
rotation. The old hashed-registry design this layer used to describe is
superseded by it (a hashed mirror is at most an optional hardening note —
see below).

**State file** `<state>/custom_literals.json` (chmod 600) — the product's
registry, CLI-managed (never hand-edited):

```json
{
  "version": 2,
  "literals": [
    {
      "id": "9f3c1e7a2b8d4f60",
      "value": "actual-secret-value",
      "mask": "full",
      "kind": "literal",
      "rotated_from": null,
      "rotated_at": null,
      "retired": false,
      "retired_at": null,
      "rotated_to": null
    }
  ]
}
```

The identity fields matter: `id` is the opaque `value_id` join key across
every surface (watch JSON, rotate candidates); `kind` distinguishes ordinary
literals from honeytokens (canaries); the lineage fields (`rotated_from` /
`rotated_at` / `retired` / `retired_at` / `rotated_to`) make rotation an
identity lifecycle, never string replacement.

Clues for the builder:

- **Register through the CLI only**: `literals add VALUE... [--mask STYLE]
  [--file FILE] [--json]` (bulk via `--file`, per-value mask style via
  `--mask`, machine-readable output via `--json`), `--from SOURCE:KEY` to
  enroll a discovered source value, `--kind honeytoken` to plant a canary.
  `literals list [--json]` inspects the registry; `literals remove ID`
  removes an entry; `literals rotate VALUE_ID [--json]` applies a rotation
  (replacement piped via stdin only — never argv). The registry is a
  CLI-managed surface — hand-editing is unsupported; `build` regenerates
  `redact_patterns.json` from `.env` sources + the registry.
- **Priority tiers are derived, not stored**: the rotate-candidates view
  derives `critical > rotate-now > review > idle` from detection + retirement
  state at read time — no manual tier bookkeeping.
- **Sources**: `.env` files (the default `build` input), `literals add`
  (explicit registration), `discover` + `literals add --from` (at-source
  enrollment), honeytokens. Nightly `build` re-runs reconcile reality.
- **Retention**: retired identities stay registered and detectable until
  explicitly removed (`literals remove`) — a retired credential must still
  be caught if it appears; removal severs the lineage chain, leaving
  surviving references as historical context.
- **Key-shape warning**: keys not matching the built-in keyword families
  (KEY/PASS/PW/TOKEN/SECRET...) rely solely on exact-value matching — the
  inventory warns on them so they get registered deliberately.

**Optional hardening (superseded design, kept as a note):** the pre-registry
design stored a peppered sha256 of each value (`sha256(pepper + value)`) in a
separate `known_secrets.json`, so a leaked inventory file was not a lookup
table. The product registry stores exact values by necessity (exact matching,
lineage, rotation) and is protected as sensitive local state (chmod 600, the
same trust envelope as the pattern file — see the README's honest-boundary
paragraph). A deployment that wants at-rest hardening **in addition** may keep
a hashed mirror for detection-only joins, but it is a derived cache, never a
second source of truth: the product registry is the identity source, and
parallel hash inventories retire (consolidation doctrine: the deployment reads
the product registry).

## Layer 3 — Detection (detect)

Scheduled, silent-when-clean scanners. The reference deployment runs:

| Scanner | Schedule | What it does |
|---|---|---|
| **Preflight (`info-guard preflight`)** | on demand, before install | Zero-config leak scan of Hermes' own transcripts/logs — key-shape regexes + gitleaks tuned ruleset; the same passes the scheduled `watch` runs, without needing a registry. This is the entry point: run it first, schedule `watch` after. gitleaks is optional (preflight checks first and offers to install it); without it, key-shape + token-prefix passes still run |
| `watch` (`info-guard watch [DIR ...]`) | every 6h | Scheduled delta monitor: the same detection passes as preflight over transcripts, logs, and request dumps, alerting on what changed since the baseline — cron-friendly exits, silent when clean |
| HIBP exposed check | weekly | Compares registered values against haveibeenpwned's k-anonymity API (SHA-1 prefix only — the full value never leaves; deployment-side, not shipped in v1) |
| `discover` (`info-guard discover [PATH ...]`) | nightly | Enumerates unregistered key-shaped secrets in named source paths — repos and app configs, where XML/INI/YAML tags name the secret, so format gaps in the transcript scanners don't block identification; enroll findings via `literals add --from` |

**Tiering** (what fires an alert, and at what severity):

- `CONFIRMED` — exact registry-value match: rotate (critical/high =
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
  re-scan to confirm the old value no longer appears anywhere. The product's
  sanctioned handoff: `rotate-candidates --json` selects what to rotate,
  `literals rotate VALUE_ID` applies it (replacement via stdin only — the
  replacement value must never appear as a CLI argument), and
  `build` regenerates the pattern file — deployment drivers consume the
  view and pipe the replacement; they never read or write the registry.
- **Drill**: a quarterly scheduled full rotation proves the machinery works
  before an incident needs it.

## Layer 5 — Watchdogs & hygiene (operate)

Small scheduled checks that catch drift before it becomes a leak:

| Check | Schedule | Detects |
|---|---|---|
| Env-drift watchdog | weekly | `.env` files changed without `info-guard build` being re-run (registry/pattern drift) — silent when clean, email on drift |
| Config-audit | on change | New/changed config keys in tracked files (diff-based, with an ignore list for known benign churn) |
| Nightly refresh | daily | Re-run `info-guard build` + `discover` — the "forgot to register" safety net |
| Release hygiene | per release | Tag + CHANGELOG entry (Keep a Changelog); related micro-fixes consolidate into the most recent entry — versions stay meaningful for pull-based consumers |

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
2. Register into Layer 2 (the product registry — `literals add` / `--from`;
   the registry ships with the product, so this is data entry, not build).
3. Layer 3 detection — schedule `info-guard watch` (`preflight` on demand,
   `discover` for at-source sweeps). Needed before rotation is ever triggered.
4. Layer 4 rotation for the two highest-priority credential classes — drive
   it from `rotate-candidates --json` and `literals rotate VALUE_ID`.
5. Layer 5 watchdogs, in the order above.

Each layer's tests: the previous layer's pattern file + one synthetic probe
through the full path (mask → detect → alert → rotate → verify).
