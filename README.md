# Info Guard

**Exact-value redaction for Hermes Agent.** Your secrets, masked — at the
single redaction chokepoint, from a plain-JSON pattern file, with zero
external tooling.

Hermes Agent already redacts *shapes*: any `KEY=value` whose key contains
`PASS`/`TOKEN`/`SECRET`/`API_KEY`/... is masked by the built-in redactor.
Info Guard adds the other half — **your exact values**. Register a value
once, and it is masked everywhere Hermes sees it: tool output, logs,
transcripts, file reads. No matter what key it appears under, or whether it
appears as a bare value at all.

```
Before:  "the token is 7f3a9c2b8d1e4f5a6b7c8d9e0f1a2b3c and the PIN is 4321"
After:   "the token is 7f...3c and the PIN is ***"
```

## Safety properties (the non-negotiables)

- **Display-only** — masking is a read-time transform; it can never modify
  your `.env` files, vault, or config.
- **Fail-safe** — a missing or broken pattern file is a no-op: built-in
  redaction keeps running, and a broken file keeps the last-good pattern set
  (no unmasked gap) until repaired.
- **Sentinel on file reads** — values redacted from file content become a
  non-reusable sentinel, so a masked value can never be written back over
  the real file.
- **Per-instance** — the default path resolves under `$HERMES_HOME`, so
  profiles and relocated installs each get their own redaction set,
  automatically. No cross-instance leakage, no silent no-op.
- **Precision** — exact-value matching, never substring patterns. Literal
  collisions are the only over-redaction surface, and the curated key list
  is the only global one.

**The honest boundary.** The pattern file lives *inside* Hermes' trust
envelope — same OS user, same filesystem. `chmod 600` protects it from
other OS users, and this package never intentionally passes it to model
context — but nothing in-process can protect it from Hermes itself or
from anything running as your user. Hermes' own security model puts the
hard boundary at OS isolation (sandboxes/containers/VMs); in-process
filtering is heuristic. If your threat model requires the registry to be
unreadable by the agent, that is the daemon architecture (a separate
process exposing only a register/unregister/sanitize API) — on the
roadmap as v2.

## Install (any of these)

Requires Hermes Agent **v0.20.0+** — the patch is apply-checked and the
upstream test suite passes 15/15 against v0.20.0, v0.20.1, v0.20.2,
v0.20.3 (2026.8.16.2), and v0.20.4 (2026.8.18) — one version-tolerant
patch; `test.sh` is the package's own 35-check battery, separate from the
upstream suite.
Takes about two minutes.

**Step 0 — preflight (optional but recommended):** before deciding, check
whether you're *already* leaking without knowing it — Hermes' own transcripts
and logs may hold secrets that predate redaction:

```bash
./bin/info-guard preflight          # sample report — one example per family
./bin/info-guard preflight --full   # complete deduplicated ledger, same masking
```

Zero-config, read-only, nothing written, output fully masked. Scans
`<home>/sessions`, `<home>/logs`, and `<home>/cron/output` with two passes:
key-shape regexes (`KEY=value` with secret-family keys, known token prefixes)
and gitleaks' already-tuned ruleset. **gitleaks is optional** — the core
product never needs it — but it powers this scan's provider-format tier. If
it's missing, preflight explains the benefit and offers to install it
(`go install` or the GitHub release binary into `~/.local/bin`); non-tty
runs get the command and continue with the key-shape pass only.

The report (v0.2.4+) is a security assessment structured for humans and
agents alike: header with version + timestamp and a **SCOPE** line, a one-line
STATUS, an EXECUTIVE SUMMARY (metric cards incl. the family-attributed ·
unattributed split), **CREDENTIAL EXPOSURE BY FAMILY** with the distinct
masked-value proof list (`VALUES — MATCH AGAINST YOUR CURRENT CREDENTIALS`),
EXPOSURE LOCATIONS with a qualified pattern observation, REDACTION
EFFECTIVENESS, WHY AM I SEEING THIS, RECOMMENDED ACTIONS, and two appendices
(detection telemetry + the deduplicated finding ledger with trimmed context;
`--full` prints the complete ledger). Tiers are a partition — every finding
is exactly one of credential-shaped / key-name mention / already-masked.
Full format contract: `docs/format-spec.md`.

Already installed? Preflight detects it (engine marker + pattern file) and
frames the run as a health check: findings are at-rest residue that masking
does not remove — rotate or delete them.

**Privacy & credential handling:** preflight is safe-by-construction —
values are masked before they leave the machine, never echoed, and the scan
only reads local files. It is fully **agent-runnable by design** (via your
agent, or directly in a terminal — in a terminal nothing ever leaves the
machine). One consideration: like any tool output, the findings — key
names, file paths, and masked fragments — transit whatever LLM provider the
agent session uses. If you run a local + public provider mix, run preflight
and the follow-up conversation on your local model; that keeps the entire
decide-step off the public wire.
Clean → no leaks found at rest today — a solid baseline; install turns that
baseline into prevention (masking before values ever reach logs).
Findings → each candidate is a value at rest that *looks* like a secret:
review the list, rotate or delete anything you confirm. Installing never
cleans history — it prevents the next occurrence.

**Step 0b — build your config interactively (`info-guard setup`):**

```bash
./bin/info-guard setup
```

The wizard walks every preflight candidate one at a time — **values shown
masked only, never echoed** — and asks which are yours. Confirmed values are
registered as exact-value literals (token-shaped → full mask, key-shaped →
default partial), your `.env` sources are added, and the pattern file is
built and verified in one pass. `info-guard setup --all` accepts every
candidate non-interactively (agent-assisted installs).

**You (terminal):**

```bash
git clone https://github.com/db3-studio/info-guard
cd info-guard
./install.sh          # applies the patch, seeds the pattern file, runs the test battery
./bin/info-guard build   # populate the pattern file from your .env files
```

That's it. Masking is live immediately; a restart of running Hermes
processes (gateway, web UI) picks it up on next start.

**Your Hermes agent:**

> Follow the README at ~/info-guard: run ./install.sh, then ./bin/info-guard
> build, then verify with ./test.sh.

The agent will read `docs/format-spec.md` for the file format and
`docs/full-stack.md` for the optional full stack.

**Everything manual** (no shell skills needed):

1. Apply `patch/redactor-registry-patterns.patch` to your Hermes Agent
   checkout (`git -C <checkout> apply --check` first — it must apply cleanly).
2. Create `<hermes-home>/state/info-guard/redact_patterns.json` (see
   `examples/redact_patterns.json.example`), chmod 600.
3. Set `security.redact_patterns` to that path, or just rely on the default
   path — the default already matches.
4. Restart Hermes processes.

## Upgrades (`hermes update`)

**The rule: update Info Guard BEFORE Hermes, never after.**

Version history: see [CHANGELOG.md](CHANGELOG.md) for what changed in each
release.

The patch is one version-tolerant artifact, verified across the tested
range (**v0.20.0 – v0.20.4**). `hermes update` autostashes and restores
working-tree changes, so within the tested range the patch usually rides
the update untouched — but a release that changes the patched code
(v0.20.2 and v0.20.4 both did) can break the stash restore, and an
untested release may not accept the patch at all. The order that never
strands you:

1. **Update Info Guard first** (a minute, any time):
   `git pull` the package, then re-run `./install.sh`. Since v0.20.4
   support (2026-08-18), install.sh detects an older applied patch and
   **replaces it in place** — your pattern file and custom literals are
   never touched.
2. **`info-guard check`** — expect OK. If it exits non-zero, resolve
   before updating Hermes.
3. **`hermes update`** — the freshly-applied patch rides the updater's
   stash; within the tested range it restores cleanly.
4. **After the update: `info-guard check`** — OK means the patch
   survived. Non-zero means the release drifted it: pull the latest Info
   Guard and re-run `./install.sh`. If install.sh reports the patch
   "does not apply", hold `hermes update` until this package ships a
   rebase for that release — it never silently degrades.

`check` enforces the floor: it verifies the applied patch matches this
package's artifact **and** that your Hermes version is within the tested
range — exit 1 with the exact next step when either fails. That makes it
safe to run as a standing watchdog *before* `hermes update`, not just
after. Schedulable — no alert channel is assumed; wire the non-zero exit
to whatever your scheduler supports (cron mail, ntfy, a log line):

```cron
0 * * * * /path/to/info-guard/bin/info-guard check || echo "info-guard: BROKEN — run install.sh"
```

Cron's five fields are **minute, hour, day-of-month, month, day-of-week** —
`0 * * * *` means "every hour, at minute 0". The `||` reads as "only when
`check` fails" (non-zero exit): a healthy check stays silent, a broken one
runs the echo — which your cron can mail, log, or pipe anywhere.

## Uninstall

```bash
./uninstall.sh            # confirm prompt; --yes to skip it
```

Cleanly reverses install: reverse-applies the patch (skipped if absent),
removes the `security.redact_patterns` config key, and moves the state dir
(`<home>/state/info-guard/`) to `*.bak-<timestamp>` instead of deleting it
(delete the backup once you're sure; `--keep-state` leaves it in place).
Idempotent — safe to re-run. After uninstalling, restart Hermes processes
so the patched code is unloaded from memory. gitleaks (if you accepted the
optional install) is left alone — it's a standalone tool.

## Add your own secrets

Edit `<hermes-home>/state/info-guard/custom_literals.json`:

```json
{"literals": ["someone@example.com", {"value": "anything-sensitive", "mask": "full"}]}
```

Then `./bin/info-guard build`. Live within seconds — no restarts, survives
rebuilds. Email addresses, phone numbers, API tokens, names, anything you
decide is sensitive.

`info-guard build` also pulls every secret-shaped `KEY=value` from your
`.env` files into the pattern file automatically (non-secret keys — hosts,
URLs, usernames, flags, schedules — are excluded: masking those was pure
information loss).

More examples — value types, mask styles, key patterns — in
`examples/redact_patterns.json.example` and `examples/custom_literals.json.example`.

## Test

```bash
./test.sh
```

Synthetic values only — no real secrets. Verifies exact-value masking
(partial / full / short), key-form masking, the file-read sentinel, the
broken-file fail-safe, and the fresh-home default-path property (the
"second instance" test: a brand-new `HERMES_HOME` masks its own values with
zero configuration).

## Profiles & multi-instance

Every Hermes profile is a separate `HERMES_HOME`. Each one gets its own
`state/info-guard/` automatically — separate literals, separate keys,
separate masks. Point several profiles at one pattern file if you want a
shared set, or keep them isolated. Either way: no leakage between instances.

## How it works

| Piece | File |
|---|---|
| Redaction engine (patch) | `patch/redactor-registry-patterns.patch` — exact-value + key-form pass in `agent/redact.py`, config/env bridge at the 3 entry points |
| Pattern-file builder | `bin/info-guard` — .env → `redact_patterns.json` |
| Verification battery | `test.sh` |
| File format spec | `docs/format-spec.md` |

## Next steps: the full stack

This package is the **redaction layer** — the transferable core. It works
alone and installs in minutes, but it is layer 1 of a five-layer lifecycle.
For a complete posture, build the rest — in order, one at a time; each
layer is independent and pays for itself:

| Layer | What it does | Why it matters |
|---|---|---|
| **1. Redaction** (this package) | Masks your exact values + key forms at every message boundary | Prevention — leaks never exist in the first place |
| **2. Inventory** | Hashed registry of every secret **beyond `.env`** — app configs, compose envs, vault items, honeytokens — with priority tiers (`.env` is already the default source for `info-guard build`) | You can't protect what you haven't found; feeds detection and full-mask decisions |
| **3. Detection** | Scheduled scans (leak scan, HIBP, gitleaks discovery) over transcripts, logs, repos | Finds what slipped through — including residue that predates redaction |
| **4. Rotation** | Per-credential rotation, vault-first, old-fails/new-passes verification | An exposed credential is only an incident while it still works |
| **5. Watchdogs** | Env-drift, config-audit, nightly refresh, engine-marker checks | Catches drift before it becomes a leak — nothing fails silently |

The doctrine: **discover → register → mask → detect → rotate.**

The buildable blueprint lives in **`docs/full-stack.md`**: state-file
schemas, scanner tiers and schedules, rotation-driver patterns, known
silent-fail classes, and a building order — with enough detail for any
Hermes agent to build the remaining layers for your environment.

## Upstream

The redaction engine is being upstreamed to NousResearch/hermes-agent
(PR [NousResearch/hermes-agent#87953](https://github.com/NousResearch/hermes-agent/pull/87953) — "exact-value secret redaction from user pattern file").
Once merged, `install.sh`'s patch step disappears and this repo becomes
pure tooling + docs. Until then, `install.sh` is marker-guarded and fails
loudly if a `hermes update` drifts the patch context — it will never
silently disable redaction.

## License

MIT — see LICENSE. Independent of Hermes Agent's license.
