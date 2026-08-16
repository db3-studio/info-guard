# Info Guard — pattern file format (v1)

The pattern file is the **single interface** between your secrets and Hermes'
redaction engine. Hermes reads it at every message boundary (tool output,
logs, transcripts, file reads) and masks anything it contains. The file is
plain JSON — you can generate it with `bin/info-guard build`, edit it by
hand, or have your agent maintain it.

## Location & precedence

1. `security.redact_patterns` in `~/.hermes/config.yaml` (set by `install.sh`)
2. `$HERMES_REDACT_PATTERNS` environment variable
3. Code default: `$HERMES_HOME/state/info-guard/redact_patterns.json`
   (fallback `~/.hermes/...`) — one file **per Hermes instance**, so every
   profile gets its own redaction set automatically.

Pattern-file *content* changes apply immediately (mtime-cached, proven).
Path *changes* apply at the next process start.

## Top-level shape

```json
{
  "mask": {"head": 2, "tail": 2, "floor": 12},
  "literals": ["exact-value", {"value": "...", "mask": "full"}],
  "key_patterns": {"PIN": true, "MY_CUSTOM_SECRET": true},
  "generated": "2026-08-16T17:40:00+00:00"
}
```

All sections optional. A missing or unreadable file is a **no-op** — the
built-in redactor keeps running; nothing ever crashes because of this file.

## Sections

### `mask` — the default masking style

Length-driven partial masking, applied to every literal without its own
override:

| Field | Default | Meaning |
|---|---|---|
| `head` | `2` | visible leading characters |
| `tail` | `2` | visible trailing characters |
| `floor` | `12` | values shorter than this are fully masked (`***`) |

Rationale for the defaults: keeps the built-in redactor's invariant that at
least 8 characters are always hidden, while values like phone numbers (12
chars) and short emails stay partially visible for troubleshooting. Values
≤ 10 chars (PINs) are fully masked by default.

### `literals` — exact-value masking

Each entry is either a plain string (use the default mask) or an object:

```json
{"value": "super-sensitive-value", "mask": "full"}
```

`mask` accepts `"full"` (nothing visible) or a custom object
`{"head": 3, "tail": 1, "floor": 8}`. Anything unknown falls back to the
safe default — never an unmask, never a crash.

Matching notes:

- Longest literals match first, so overlapping values mask deterministically.
- Built-in keyword families (`KEY=value` with `PASS`/`TOKEN`/`SECRET`/... in
  the key) are masked by Hermes even without this file — Info Guard adds
  **your exact values** and your **custom keys**.
- Values are matched as exact strings (never substring patterns) — this is
  the precision property that keeps over-redaction near zero.

### `key_patterns` — key-aware masking

`{"KEY_NAME": true}` masks the value of that key in `KEY=value`,
`KEY: value`, and JSON `"KEY": "value"` forms — **regardless of value
length**. This covers the class of short secrets (`PIN`, `x_passphrase`)
that exact-value matching can't safely touch.

`info-guard build` populates this from your `.env` files (every secret-shaped
key) plus a curated built-in list (`PIN`, `WEBUI_PIN`,
`HERMES_WEBUI_PASSWORD`, `x_passphrase`, `client_secret`, `refresh_token`,
`access_token`, `dns_provider_credentials`). Non-secret keys — hosts, URLs,
usernames, emails, ports, flags, schedules, model configs — are excluded:
masking those values was pure information loss.

## Safety properties

- **Fail-safe**: missing/broken/unreadable file = no-op; a broken file keeps
  the last-good pattern set active (no unmasked gap) and auto-recovers when
  repaired.
- **Sentinel on file reads**: values redacted from file *content* are
  replaced with a non-reusable sentinel, so a masked value can never be
  written back over the real file. Tool output and logs get partial or full
  masking instead.
- **Display-only**: masking can never modify your `.env` files, vault, or
  config — it is a read-time transform.
- **Per-instance**: the default path resolves under `$HERMES_HOME`, so
  profiles and relocated installs each get their own file (no cross-instance
  leakage, no silent no-op under a remapped home).
- **Boundary (honest)**: the pattern file is *inside* the agent's trust
  envelope — 0600 protects it from other OS users; nothing in-process can
  protect it from the agent itself (OS isolation is the hard boundary per
  Hermes' own model; a SANITIZE-only daemon is the v2 direction).
- **Coverage gap (documented)**: `key_patterns` masks `KEY=`, `KEY:`, and
  JSON key forms. XML-style tags (`<ApiKey>value</ApiKey>`) are NOT covered
  by key patterns — register those values as exact literals instead
  (literals mask anywhere, including inside XML).

## The `.env` grammar (what `info-guard build` parses)

Lines are `KEY=value`; anything after the first `=` is the value:

- keys must match `[A-Za-z_][A-Za-z0-9_]*` (other lines are skipped)
- surrounding single or double quotes are stripped from the value
- trailing `# comments` are stripped only when preceded by whitespace
  (a `#` inside the value is part of the value)
- `export KEY=...` prefixes are not supported
- non-secret keys (hosts, URLs, usernames, flags, schedules, ports, …) are
  excluded via a curated list (the matcher's `_is_non_secret_key`);
  secret-shaped keys become key patterns, and values ≥ 8 chars become
  exact literals
- values shorter than 8 chars are not registered as literals (precision
  floor), but their KEY still becomes a key pattern — so `PIN=1234` masks
  even though the value is unregistered

## Custom literals (the PII workflow)

`<state>/custom_literals.json` — hand-edited, survives rebuilds, masking only
(never part of detection):

```json
{"literals": ["someone@example.com", {"value": "anything-you-want", "mask": "full"}]}
```

Edit it, then run `info-guard build` — live within seconds, no restarts.

## Version notes

- Requires Hermes Agent **v0.20.0+**. One version-tolerant patch: apply-checked
  and 20/20 test suite against v0.20.0 (2026.8.3), v0.20.1 (2026.8.13), and
  v0.20.2 (2026.8.16) — 0.20.2 drifted `hermes_cli/main.py` (dotenv loading
  rework) and the patch context was rebased to cover all three.
- `install.sh` / `uninstall.sh` fail loudly if the patch doesn't apply after
  a `hermes update` — never silently.
- `security.redact_patterns` may print "not a recognized config key" on the
  CLI — it is read by the entry-point bridge anyway; the warning is cosmetic.
- The `patterns` (regex) section is v2 (planned) — format-based redaction
  (any email/phone/SSN shape) on top of the exact-value engine. See
  `docs/full-stack.md`.
