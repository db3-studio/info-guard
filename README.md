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

## Install (any of these)

Requires Hermes Agent **v0.20.1+**. Takes about two minutes.

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
| Full stack blueprint | `docs/full-stack.md` — inventory, detection, rotation, watchdogs |

## Upstream

The redaction engine is being upstreamed to NousResearch/hermes-agent
(PR #85064 — "exact-value secret redaction from user pattern file"). Once
merged, `install.sh`'s patch step disappears and this repo becomes pure
tooling + docs. Until then, `install.sh` is marker-guarded and fails loudly
if a `hermes update` drifts the patch context — it will never silently
disable redaction.

## License

MIT — see LICENSE. Independent of Hermes Agent's license.
