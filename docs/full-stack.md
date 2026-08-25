# Info Guard — the full stack (roadmap)

This repo ships the **product CLI**: the redaction engine (the patch + the
matcher), the registration CLI (`literals`, `setup`), detection (`preflight`,
`watch`, `discover`), rotation mechanics (`rotate-candidates`,
`literals rotate`), the self-sustain commands (`check --heal`, `update`),
the test battery, and this documentation. That is the transferable core — it
works with zero other infrastructure, installs in minutes, and its value is
immediate (your exact secrets stop appearing in tool output, logs, and
transcripts).

Redaction is one layer of a five-layer lifecycle, and every layer below
lists **only what the product ships**. Deployment wiring — where your
secrets live, how rotation is driven per credential class, how you are
alerted — is a deployment concern, not a product feature.

## The doctrine

**Discover → register → mask → detect → rotate.**

- *Discover*: inventory every secret source (`.env` files, docker compose
  envs, app configs).
- *Register*: every discovered secret gets a registry entry (exact value,
  CLI-managed — the registry file is chmod 600, and masking is display-only)
  before its first config read.
- *Mask*: the registered values flow into the pattern file (this repo's
  `info-guard build`); masking is display-only and can never corrupt sources.
- *Detect*: scheduled scans watch transcripts, logs, and repos for registered
  values appearing where they shouldn't.
- *Rotate*: confirmed exposure triggers rotation — retire the exposed
  identity, register the new value, verify old-fails/new-passes.

**The instruction layer.** A mechanism is only used if the deployment's
agent-facing instructions say so — an agent that does not know
`info-guard env` exists will `cat` the `.env`. Encode each layer's
guardrails in the harness instruction files (`AGENTS.md` / `CLAUDE.md` /
skills / cron prompts), not just in the CLI help; the per-layer clues below
call out which surfaces need them. The proven pattern: a transitional
no-dump list whose entries leave once discovery + redaction prove coverage,
with "prefer masked viewers" as the standing default.

The layers below are each proven, independent, and incremental: build them in
order, and each one pays for itself.

---

## Layer 1 — Redaction (mask)

The installed layer: the engine patch that masks at every Hermes output
boundary, driven by the pattern file it reads. This is what makes the value
immediate — your exact secrets stop appearing in tool output, logs, and
transcripts the moment it is installed.

| Surface | What it does |
|---|---|
| Pattern file (`<state>/redact_patterns.json`, chmod 600) | The compiled set the engine reads at every message boundary (tool output, logs, file reads, transcripts) |
| `info-guard build` | Generate the pattern file from `.env` sources + the registry |
| `info-guard status` | Summary of the current pattern file — the built set, counts, and policy at a glance |
| `info-guard pipe` | Mask any stdin stream against the pattern file (fail-closed: no matcher → exit 2, no passthrough) |
| `info-guard view <surface> <target>` | Masked viewers — systemd unit, docker-env, compose-config, file |
| `info-guard env [FILE] [--check\|--keys]` | Keys + lengths only (never values); `--check` non-executing grammar validation |

Masking is **display-only** (a read-time transform — it can never modify
`.env` or config files), **exact-value or key-form** (never
substring), **fail-safe** (a missing or broken pattern file is a no-op —
built-in redaction keeps running, and a broken file keeps the last-good set
until repaired), and **per-instance** (paths resolve under `$HERMES_HOME`, so
profiles and relocated installs each get their own set automatically).

Clues for the builder:

- **Agent guardrail**: an agent reads env/config/state through the masked
  surfaces (`info-guard env`, `view`, `pipe`) — never a raw dump (the
  no-dump doctrine). The rule has to live in the deployment's agent
  instructions, not only in the CLI help, or the agent's default is `cat`.

## Layer 2 — Secret inventory (register)

The inventory backbone is the **product's exact-value registry**
(`custom_literals.json`). There is no separate inventory store to build:
every value you register is the identity source for detection, masking, and
rotation. The old hashed-registry design this layer used to describe is
superseded by it (a hashed mirror is at most an optional hardening note —
see below).

| Surface | Role |
|---|---|
| Registry (`custom_literals.json`, chmod 600) | Identity source: exact values, opaque `value_id` join keys, kinds, lineage — CLI-managed, never hand-edited |
| `setup [--all]` | Interactive bootstrap — reviews preflight candidates (masked only), registers the confirmed ones as literals, picks `.env` sources, builds the pattern file; `--all` accepts every candidate non-interactively |
| `literals add VALUE... [--mask STYLE] [--file FILE] [--json]` | Register values (bulk via `--file`, per-value mask style via `--mask`, machine-readable output via `--json`); `--from SOURCE:KEY` enrolls a discovered source value; `--kind honeytoken` plants a canary |
| `literals list [--json]` | Inspect the registry |
| `literals remove ID` | Remove an entry (severs the lineage chain) |
| `literals rotate VALUE_ID [--json]` | Apply a rotation — replacement piped via stdin only, never argv |
| `info-guard build` | Regenerate `redact_patterns.json` from `.env` sources + the registry (registry mutations already activate automatically — `build` refreshes `.env`-sourced values) |
| `rotate-candidates` | Derived priority tiers (`critical > rotate-now > review > idle`) at read time — never stored |

**State file** `<state>/custom_literals.json` (chmod 600) — the product's
registry, CLI-managed (never hand-edited):

```json
{
  "version": 2,
  "rev": 3,
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

`rev` (v0.9.3) is the monotonic mutation counter — the identity half of
the activation handshake: the pattern file records the `rev` it was
derived from (`derived_rev`), and `check`/`status` compare the two so an
unbuilt mutation is never silent.

The identity fields matter: `id` is the opaque `value_id` join key across
every surface (watch JSON, rotate candidates); `kind` distinguishes ordinary
literals from honeytokens (canaries); the lineage fields (`rotated_from` /
`rotated_at` / `retired` / `retired_at` / `rotated_to`) make rotation an
identity lifecycle, never string replacement.

Clues for the builder:

- **Sources**: `.env` files (the default `build` input), `literals add`
  (explicit registration), `discover` + `literals add --from` (at-source
  enrollment), honeytokens. Periodic `build` re-runs reconcile reality.
- **Retention**: retired identities stay registered and detectable until
  explicitly removed (`literals remove`) — a retired credential must still
  be caught if it appears; removal severs the lineage chain, leaving
  surviving references as historical context.
- **Key-shape warning**: keys not matching the built-in keyword families
  (KEY/PASS/PW/TOKEN/SECRET...) rely solely on exact-value matching — the
  inventory warns on them so they get registered deliberately.
- **Agent guardrail**: the registry is CLI-managed — agents register via
  `literals add` / `setup`, never by hand-editing `custom_literals.json`
  (hand-editing is unsupported).

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
| `discover` (`info-guard discover [PATH ...]`) | nightly | Enumerates unregistered key-shaped secrets in named source paths — repos and app configs, where XML/INI/YAML tags name the secret, so format gaps in the transcript scanners don't block identification; enroll findings via `literals add --from` |

**Tiering** (what fires an alert, and at what severity):

- `CONFIRMED` — exact registry-value match: rotate (critical/high =
  immediate; `retired` class = expected residue, verify no active use).
- `HONEYTOKEN` — a canary value appeared: critical (canaries only exist to
  be touched).
- `HIGH-CONFIDENCE` — gitleaks/generic rule match: register or rotate.
- `SUSPICIOUS` — pattern near-match: human review list, not an alert.

Clues for the builder:

- **Honeytokens**: plant canaries with `literals add --kind honeytoken`
  (they're masked, and their appearance fires detection) — live proof that
  masking + detection both work.
- **Exit shape**: silent when clean (a cron tick with no findings produces
  zero output — no alert fatigue), cron-friendly exit codes; the deployment
  wires delivery to a stable platform.
- **False-positive classes to exclude by design**: code identifiers
  (`password_hash =`, `set_password`), host/URL/username values, non-secret
  keys (the same exclusion list the matcher uses). Exclusions are
  *exact-hash or explicit-rule* based, never substring guessing.
- **Agent guardrail**: agents run the product scanners (`preflight` /
  `watch` / `discover`) rather than ad-hoc greps over transcripts —
  pattern-only scanning is a false-positive factory (code identifiers such
  as `password_hash =` match every time); detection is exact-value by
  doctrine.

## Layer 4 — Response (rotate)

The product supplies the rotation mechanics; a deployment drives them per
credential class.

| Mechanism | Role |
|---|---|
| `rotate-candidates --json` | Selects what to rotate (read-only view, derived at read time) |
| `literals rotate VALUE_ID` | Applies the rotation (replacement via stdin only — never argv); activates the new identity immediately (verified) |
| `info-guard build` | Refreshes the pattern file from `.env` sources (rotation itself already activated) |

Clues for the builder:

- **New-value shape**: `key_` + 28 random alphanumerics (≥32 total) —
  self-protecting, because gitleaks' generic rules and token-shape detection
  catch it even if registration is ever missed.
- **Classes**: agent-automatable (API/script credentials) vs user-touch
  (SSO/UI passwords — the user changes them in the UI; the agent verifies).
- **Order**: change the source first, then consumers, then verify
  old-fails / new-passes, then re-scan to confirm the old value no longer
  appears anywhere. The product's sanctioned handoff:
  `rotate-candidates --json` selects what to rotate, `literals rotate
  VALUE_ID` applies it (replacement via stdin only — the replacement value
  must never appear as a CLI argument) and activates the new identity
  immediately; deployment drivers consume the view and pipe the
  replacement; they never read or write the registry.
- **Agent guardrail**: a replacement value reaches `literals rotate` via
  stdin only — never as a CLI argument; and never run a secret-touching
  script under `bash -x` / `set -x` (xtrace expands values into the trace).

## Layer 5 — Watchdogs & hygiene (operate)

The product ships the health and update surfaces; a deployment schedules
them (`install.sh --cron` wires the scheduler).

| Check | Schedule | Detects |
|---|---|---|
| Product health (`info-guard check [--heal] [--battery]`) | on demand / scheduled (`install.sh --cron`) | Engine marker, pattern file, custom literals, gitleaks, patch-state, supported-version floor, masking smoke, activation state (registry rev vs pattern `derived_rev`) — `--heal` repairs the engine via install.sh; `--battery` runs the full verification battery |

The product also ships its own update path: `info-guard update [--check]
[--json] [--rollback]` — `--check` probes for a newer release, `--rollback`
reverses an update.

Clues for the builder:

- **Agent guardrail**: `update` runs BEFORE `hermes update` — Info Guard
  first, never after (an overwritten patch silently stops masking); `--heal`
  is explicit-only, never automatic.

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

1. Install this repo (Layer 1 — redaction) — immediate value, zero dependencies.
2. Register into Layer 2 (the product registry — `literals add` / `--from`,
   or the guided `setup` wizard; the registry ships with the product, so
   this is data entry, not build).
3. Layer 3 detection — schedule `info-guard watch` (`preflight` on demand,
   `discover` for at-source sweeps). Needed before rotation is ever triggered.
4. Layer 4 rotation for the two highest-priority credential classes — drive
   it from `rotate-candidates --json` and `literals rotate VALUE_ID`.
5. Layer 5 health + update — schedule `check` (and refresh `build` +
   `discover` on a cadence that fits the deployment).

Each layer's tests: the previous layer's pattern file + one synthetic probe
through the full path (mask → detect → rotate → verify).
