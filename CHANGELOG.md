# Changelog

All notable changes to Info Guard are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [SemVer](https://semver.org/).

> Convention: micro-version fixes within the same workstream are consolidated into the latest entry of that release, not captured per tag.

## [v0.9.2] - 2026-08-24

Documentation and verification hardening release.

### Changed
- **README overhaul** — rewritten as the product's presentation surface:
  exact-value pitch, defaults at a glance, command surface table,
  masked-viewer (no-dump) doctrine, profiles & multi-instance guidance,
  and upgrade ordering.
- **`docs/full-stack.md` rewritten as the five-layer build blueprint** —
  Layer 1 (redaction) through Layer 5 (watchdogs and hygiene): each layer
  names the shipped commands (`build`, `status`, `pipe`, `view`, `env`,
  `literals`, `setup`, `preflight`, `watch`, `discover`,
  `rotate-candidates`, `check`, `update`), with surface/mechanism tables,
  per-layer agent guardrails, known silent-fail classes, and a building
  order for new deployments.
- **Supported-version range single-sourced** — the CLI constants
  `_SUPPORTED_MIN`/`_SUPPORTED_MAX` are the single source of truth; README,
  `docs/format-spec.md`, and the CI matrix must carry the same bounds or the
  battery fails (new `battery.release.supported_range_single_source` check).
- **Install verification hardened** — the install/uninstall battery check
  now runs against a scratch Hermes checkout (tagged, artifact applied)
  instead of the live agent tree, carrying the full agent import chain the
  smoke test requires.

### Fixed
- **Help-string and doc hygiene** — internal process references removed
  from CLI help text and `docs/format-spec.md`; consumer-facing surfaces
  carry product language only.

## [v0.9.1] - 2026-08-24

Secret rotation as an identity lifecycle: a read-only rotation-candidate
view, an atomic `literals rotate` registry transaction with lineage, and
additive watch metadata.

### Added
- **`info-guard rotate-candidates [--json]`** — read-only rotation-candidate
  view over the existing scan corpus (exits 0 clean / 1 candidates / 2
  error; JSON envelope `info-guard/rotate/v1`). One row per distinct
  exact value: registered detected (`rotate-now`), retired detected
  (`critical`), unregistered environment-verified (`rotate-now`, `env`),
  unregistered scan detection (`review`), and registered undetected
  (`idle`). Deterministic ordering; baseline `first_seen`/`last_seen`
  joins by exact value; honeytokens, key-name mentions, and already-masked
  findings are excluded; active/retired duplicate-value conflicts fail
  closed as `registry_conflict`. The view is fully read-only: no registry,
  baseline, state, or matcher writes; no output-file mode.
- **`info-guard literals rotate <value_id> [--json]`** — atomic identity
  rotation: retires the old entry (retained in the registry), establishes
  a fresh entry with a new random id, records bidirectional lineage
  (`rotated_from`/`rotated_at` on the new entry; `retired`,
  `retired_at`, `rotated_to` on the old), and preserves the old entry's
  mask style, kind, and unknown fields — all in one canonical registry
  write. The replacement value arrives **through stdin only** (strict
  UTF-8, one line) and never crosses argv. Failures exit 2 with
  value-free diagnostics and unchanged registry bytes.
- **Watch `retired` field** — protected rows matching a retired registry
  entry carry `retired: true` (the machine-readable old-FAILS signal);
  watch exits and delta semantics are unchanged.
- **Baseline `last_seen`** — watch baseline value rows record the last
  watch run in which the value was present; absent values are still
  dropped and `first_seen` is still union-kept.
- **`docs/rotate-schema.md`** — the `info-guard/rotate/v1` schema: row
  fields and omission rules, priority derivation, deterministic ordering,
  text TSV format and escaping, exit tables, registry lineage fields,
  error classes, the deployment driver sequence, and consumer
  obligations.

### Changed
- `info-guard build` remains the explicit regeneration step after rotation
  (rotation never rebuilds patterns or touches derived artifacts).
- Honeytokens are not rotation candidates; canary lifecycle remains
  remove + replant.

## [v0.9.0] - 2026-08-23

Discovery: `discover` enumerates unregistered secrets from operator-named
source paths (read-only, pointer-only), and `literals add --from` enrolls
one source value by key.

### Added
- **`info-guard discover [PATH ...] [--json]`** — scans operator-named
  source paths (or the `discover.dirs` list in `custom_literals.json`;
  CLI paths completely override configuration) for key-shaped values that
  are not yet registered, and emits candidate pointers — key, source,
  line, shape class, matched pattern — never values. Exit 0 = clean,
  1 = candidates, 2 = error (JSON envelope `info-guard/discover/v1`).
  Read-only: the registry is never written, no candidate state is
  persisted, and no implicit path (cwd, installation, repository,
  deployment) is ever scanned. Traversal is anchored and bounded (depth
  32 excluding the root, 10,000 files total, 10 MiB per file — exact
  boundary inclusive), never follows symlinks (any symlink fails closed),
  and skips binary files. Unknown flags are usage errors; stderr is empty
  for every JSON result.
- **`info-guard literals add --from SOURCE:KEY [--json]`** — the sole
  enrollment bridge for discovered candidates: re-reads the named source
  through a single anchored no-follow open, parses the record with the
  shared `.env` grammar, fingerprints the complete file, revalidates the
  opened handle and the original path binding (rename or symlink
  substitution after open fails closed, exit 2, registry untouched), and
  registers the value atomically. Duplicate values return the existing id
  without rewriting (`{"added": [], "duplicates": [...]}`). `--from`
  accepts `--from SOURCE:KEY`, `--from=SOURCE:KEY`, and
  `--from -- SOURCE:KEY`; it is mutually exclusive with positional
  values, `--file`, `--mask`, and `--kind`. Selectors split at the last
  colon, so colon-containing paths work.
- Candidate pointers are exactly five fields and include only enrollable
  records: same-file duplicate keys, colon-form records, dashed keys,
  `export`-prefixed lines, bare token-prefix values, and registered
  values are never emitted. Values are suppressed from output by
  internal digest comparison only.

## [v0.8.0] - 2026-08-23

Self-maintenance: `update` (check/apply/rollback), patch heal
(`check --heal`), a seven-check masking smoke and the sandboxed battery in
`check`, the cron-install offering, and masked viewers (`pipe`/`view`/`env`).

### Added
- **`info-guard update [--check] [--json] [--rollback]`** — updates the
  package from the configured HTTPS origin (strict `vX.Y.Z` tags only,
  origin-qualified selection, checkout by commit id, verified install via
  install.sh, version-source agreement). `--check` is read-only and exits
  1 when a newer release exists (regardless of `--json`); `--rollback`
  returns to the last verified release by commit id (no local tag
  required) and is mutually exclusive with `--check`. JSON envelope
  `info-guard/update/v1` documents every outcome (stdout carries only the
  envelope in `--json` mode).
- **`check --heal`** — explicit engine repair (never automatic): restores
  and reapplies a half-reverted patch, replaces a stale applied patch in
  place, applies a missing one. Exit 0 healed / 1 attempted-and-failed /
  2 could-not-attempt.
- **Seven-check smoke in `check`** — the health verdict proves the engine
  actually masks (exact-value/full/short/key-pattern masking, broken- and
  missing-pattern fail-safes, file-read sentinel); a failing smoke names
  the check and exits 1.
- **`check --battery`** — runs the full sandboxed battery (scratch home +
  scratch checkout, bounded timeout, byte-no-mutation of the real state).
- **ACTIVE-by-upstream** — a Hermes whose HEAD already carries the patch
  (upstream merge) is accepted only when markers are in HEAD, both
  apply-checks fail, and the behavioral battery passes; marker-compatible
  but behaviorally wrong engines fail closed ("compatibility review
  required").
- **Install manifest transaction** — `install.json` gains
  `previous_version`/`previous_commit` and a transient `pending` record
  (crash-recovered by the next update/rollback); a durable
  `refs/info-guard/previous` ref protects rollback from reflog expiry.
  Ordinary installs preserve the records.
- **`install.sh --cron [SCHEDULE]` / `--no-cron`** — opt-in managed cron
  line running `check` (default `0 6 * * *`; strict five-field schedule
  grammar; `%`/control characters rejected at serialization; managed-line
  ownership marker; unrelated crontab entries preserved; uninstall
  removes only managed lines; `--no-cron` on every internal invocation).
- **Stale-cron probe in `check`** — read-only warning when a managed line
  points at a missing or version-stale binary (warning is exit 0 — not a
  health verdict; documented limitation).
- **`info-guard pipe`** — masks any stdin stream against
  the registry. **Fail-closed:** a missing/unreadable pattern file exits
  2 with `masking: unavailable (no pattern file — run install.sh +
  build)` and emits nothing (no passthrough); an empty registry is
  masking established (exit 0). Input is read as UTF-8 with replacement;
  exact literals honor per-entry `mask` style and the file's default
  head/tail/floor; `key_patterns` values are masked in `KEY=value`,
  `KEY: value`, and JSON forms.
- **`info-guard view <surface> <arg>`** — masked viewers
  for `systemd-unit <name>` (system then `--user` fallback),
  `docker-env <container>`, `compose-config <path>`, and `file <path>`.
  Child processes are invoked by argument vector only (never a shell
  string); child stdout is masked before emission; child stderr is never
  forwarded raw — fixed value-free diagnostics (`source: not found` /
  `source: failed` / `masking: unavailable`) carry no child output and
  never echo the operator's argument.
- **`info-guard env [FILE] [--check|--keys]`** — keys +
  lengths only, never values (`KEY = <N chars>`, code-point counts;
  blank lines preserved; comments and malformed lines dropped).
  `--check` is a **non-executing** grammar validation sharing `build`'s
  parser (nothing is sourced or evaluated; reports line numbers + safe
  key names; exit 1 on malformed lines — including command
  substitution/backtick/redirect/source constructs, classified as
  violations). `--keys` emits bare sorted unique key names. `--check`
  and `--keys` are mutually exclusive (usage exit 2).
- **No-dump doctrine** — "prefer masked viewers over raw dumps" is now
  product doctrine (README + format-spec); the house API-target wrappers
  stay house-side.

### Changed
- **`install.sh`** — lock-first target-safety sequence (snapshot →
  inspect → revalidate → restore); PARTIAL engines restore-and-reapply
  instead of dying; dirty patched files in the attribution-exact
  MISSING/PARTIAL states are refused (exit 2, file preserved);
  ACTIVE-mismatch remains replace-in-place (attribution limitation
  documented); exit 2 = operational/could-not-attempt, 1 =
  attempted-and-failed.
- **`check`** — unreadable pattern file is now operational (exit 2);
  invalid JSON content remains a broken verdict (exit 1) with a recovery
  message.
- **`uninstall.sh`** — removes this package's managed cron lines
  (unrelated entries untouched).

### Fixed
- (The preflight/watch 0–4 ladder is untouched; the
  update/heal/cron contracts are additive.)


## [v0.7.0] - 2026-08-22

Honeytokens, normative exit 4, and `review_list`.

### Added
- **Honeytoken plant** — `literals add --kind honeytoken [VALUE]`:
  generates `ht-` + 24 CSPRNG hex chars when no VALUE is given (explicit
  values allowed, never echoed in full); `mask: full` forced; rejects
  `--file`/`--mask`/control-char/empty/whitespace-only values and any
  `--kind` other than `honeytoken` (usage exit 2, no mutation).
- **Canary-touch detection** — registry-exact pass (independent of
  gitleaks) on preflight + watch; new `HONEYTOKEN` finding tier (the top
  tier — wins over KNOWN/shape/key-name/already-masked); `known: false`
  per the shipped derived-flag contract; `value_id` join always present.
- **Exit 4 normative** — a canary at rest → exit 4 on preflight;
  canary new/increased → exit 4 on watch (dominates 1); a baselined
  canary (`delta: "unchanged"`) never alarms; operational failure (2)
  is never overridden (partial rows may still serialize).
- **`literals remove <id>`** — the replant prerequisite; idempotent
  (unknown id → exit 0 + `removed: false`); canonical atomic
  0600-preserving writer.
- **`review_list` + `review_list_complete` (watch/v1)** — report-only
  SUSPICIOUS (gitleaks generic-api-key) rows, never an alert;
  completeness flag gates interpretation under engine degradation;
  canary-represented values excluded (one event).
- **Registry `kind`** — per-entry metadata (`honeytoken` is the only
  explicit value); unknown kinds → normal literal + one escaped warning
  per load; dedup stays by value; hand-edit transitions supported.
- **README onboarding overhaul** — canonical install location
  `~/.info-guard`, defaults table, download → preflight →
  install → build step renumbering, example-report placement.

### Changed
- Exit ladder in `docs/format-spec.md`: 4 is now normative (was
  reserved); the watch reduction gains watch-side 4; consumer obligations
  updated (codes > 4 remain unexpected).
- Honeytoken watch deltas: `decreased` is now NORMATIVE — a
  still-present baselined canary with fewer occurrences serializes
  `delta: "decreased"` + `count_before`, exit 0 (informational; matches
  the general protected-value contract).
- `literals list` shows `kind` for honeytokens (2+2 masked display —
  the `mask: full` directive is redaction-surface-only, never a CLI
  rendering directive).
- **Hermes supported range bumped to v0.20.5 (2026.8.19)** — the
  version-tolerant patch applies
  cleanly across all six release tags + origin/main (6/6 matrix); fix is
  the tested-range claim in the four sites (`_SUPPORTED_MAX`,
  README ×2, format-spec, CI matrix ref list + all-five→all-six).

### Fixed
- **Version-identity defect (v0.8.1)** — the v0.8.0 tag shipped
  `_PACKAGE_VERSION = "0.7.0"` (the bump chain broke at the release step);
  `--version` and the preflight header printed the wrong version and
  `update --check` always reported an update available (constant 0.7.0 vs
  v0.8.0 remote). The constant is now bumped to "0.8.1" (identity-only;
  the code itself is v0.8.0 behaviorally). Release checklist hardened with
  a pre-tag assertion that `_PACKAGE_VERSION` equals the intended tag.
- **README path-consistency pass** — every user-facing invocation now uses
  the absolute `~/.info-guard/...` form (works from any cwd; matches the
  canonical install location and the cron example); stale counts removed
  ("15/15" → CI-matrix framing; the battery count is dropped so it can't
  drift); the defaults-table exit code says "4 canary at rest (honeytoken)
  — preflight + watch" (normative since v0.7.0); supported-versions
  paragraph tidied to the v0.20.0–v0.20.5 range statement.

## [v0.6.1] - 2026-08-21

Audit-response patch release (external audit, 2026-08-21; the audit
material itself stays private).

### Fixed
- **`uninstall.sh` engine-integrity check** — now uses the same
  5-marker check as `install.sh` and `check`: a partial install (e.g. a
  half-reverted `hermes update`) is refused loudly instead of reporting
  "nothing to reverse" and leaving 4 files patched behind. Regression
  tests added (battery at tag 294/294; expanded post-release to 304/304
  on main: install→uninstall round-trip, drifted-5/5 fail-loud,
  idempotent re-run, state-dir move/`--keep-state`, 3-way marker-list
  consistency).
- **`install.sh` manifest version extraction** — dropped the
  GNU-only `grep -oP`; BSD grep (macOS) previously recorded
  `"version": "unknown"` in `install.json`.
- **README `literals add` example** — `--file` is now the documented
  default with a warning on the argv form (shell-history / process-list
  exposure).

## [v0.6.0] - 2026-08-21

### Added
- **Watch `.env` integration** (v0.6.0): watch and setup
  now run the KNOWN exact-value pass — env-matched values join the
  watch population regardless of shape class, with additive
  `source` / `source_key` / `value_id` annotations on watch rows
  (`new_values`, `changed_values`, `protected_values`). Precedence:
  `literal` wins on env+literal collision, but `source_key` is present
  whenever an env match exists. Rows carry `value_id` iff the value is
  registered (absent, never null).
- **Setup self-fill** — identity-verified KNOWN `.env` candidates get
  ONE default-accept group prompt (masked value + source_key + proposed
  mask style + plaintext-persistence disclosure); accepting registers
  them through the canonical registry writer. Mask styles are
  shape-based: token-format or <12-char values → `full`, else default
  2+2.
- **`value_id` on preflight KNOWN rows** — registered KNOWN rows carry
  the registry id (read-only annotation; never affects matching).
- **Contract foundation** — JSON surface versioning doctrine
  (major = compatibility generation, minor = additive), two-part
  consumer contract (syntactic tolerance + semantic preserve/report of
  security-significant unknown values), schema-string parsing rule,
  complete nullable-field list, cross-surface seams, and `literals --json`
  now carries the `info-guard/literals/v1` envelope.
- **Exit-code ladder** — preflight: 0 clean / 1 credential-
  shaped / 2 usage or operational / **3 KNOWN present (dominates)**;
  exit 4 reserved for honeytoken-grade escalation (never emitted).
  Watch: 2 on operational failure (engine unavailable / scan failure),
  1 on new values / degradation / protected alarm.
- **Mandatory first-run upgrade re-baseline** — the first v0.6.0 watch
  run against a v0.5.x baseline must re-baseline (`watch --reset`);
  previously-excluded env-matched values would otherwise false-alarm as
  `new_values`.

### Changed
- Preflight known-only runs exit **3** (was 1 under the v0.5.0
  single-predicate). Consumers routing on exit codes: 3 is the
  at-rest KNOWN verdict; 1 now means credential-shaped findings only.

## [v0.5.1] - 2026-08-21

### Fixed
- **Preflight no longer reports clean on a degraded run.** When the
  gitleaks engine is unavailable (or an internal scan failure occurs),
  preflight exits **2 (operational failure)** instead of 0 — a partially
  degraded scan never masquerades as a clean bill of health, and a failed
  scan is never misreported as "findings" (exit 1). JSON output is
  unchanged and still carries `engine.installed`. Exit-code docs updated
  (format-spec); the severity ladder in a later release adopts this widened
  exit-2 semantics unchanged.

## [v0.5.0] - 2026-08-20

### Added
- **KNOWN tier — `.env` exact-value detection**. Preflight
  now checks whether values currently in your own `.env` files appear in
  sessions, logs, or cron output — the zero-config differentiator, no
  registration, no config:
  1. **Exact-value pass** — reads the default `.env` sources
     (`$HERMES_HOME/.env`, `./.env`), builds an in-memory
     `sha256(value) → [keys...]` index of eligible values (non-secret
     keys excluded, ≥8 chars, non-trivial), and intersects it with
     value-like candidate runs in the scan. Matches are **KNOWN** rows:
     masked 2+2, `known: true`, `source_key` (alphabetically first key),
     `type: "KNOWN"`; `count` preserves per-occurrence hits. The pass
     never reports its own `.env` sources (path + inode self-match
     exclusion) and is **preflight-only** — `watch` and `setup` are
     unchanged.
  2. **New tier, partition updated** — `findings = known +
     raw_detections + key_name_mentions + already_masked` (row-level
     partition; `totals.known` = distinct values, `totals.known_rows` =
     row count). KNOWN rows appear in `top_values`, families, locations
     and affected_files (additive `known` counts). JSON is the stable
     fact surface; diagnostics (one masked line per unreadable/malformed
     source) are text-only.
  3. **`status.confirmed_active` activated in place** — `true` when ≥1
     KNOWN row, `null` otherwise (null = pass disabled OR active with
     no matches — documented). No `false` state in v0.5.0.
  4. **Exit-code extension (single predicate)** — preflight exits
     `1` iff `known > 0 OR credential_shaped > 0` (documented extension;
     the 0/1/2/3 severity ladder is deferred to a later release as one
     packaged contract change).
  5. **Non-disclosure hard boundary** — the pass never puts raw values
     in logs, exceptions, tracebacks or diagnostics (sanitized adapter,
     typed internal error codes, CLI-level generic error path); battery
     A6 injects failures at every boundary with a raw sentinel and
     asserts absence everywhere.
  6. **Docs + battery** — format-spec gains the published candidate
     grammar + exclusions (quotes delimit runs; interior quotes,
     whitespace, Unicode, commas, brackets, backslashes, shell escapes,
     multi-line never match), source-state matrix, and exit semantics;
     assessment-schema gains `known`/`known_rows`/`known` counts and
     KNOWN row rules; README's ".env values" claim is now literal.
     Battery A1–A18 (57 new checks) incl. the v0.4.2-era consumer probe
     (`tests/consumers/v0.4.2-json-probe.py`) and pinned perf protocol
     (baseline `30eb783`, 5k + 50k trees, ≤10% or ≤5 s).

## [v0.4.2] - 2026-08-20

### Added
- **Opaque alert identity (`value_id`)** — consumers can now join a watch alert to the
  exact registered value:
  1. **`value_id` on watch JSON** — `exposure.protected_values[]` rows
     carry the matched registry entry's opaque 16-hex id, and the
     overlaid `new_values[]`/`changed_values[]` row carries the **same**
     id (one event, one id). Unregistered rows have no
     `value_id` key; `resolved_values` rows never carry one. The
     terminal, baseline, and error paths never show ids (surface rule).
     `value_id` is a **registration identity** — same persisted
     registry entry → same id across runs/rebuilds/reorder; delete +
     re-add = new id. Not a security token, not a leak verdict.
  2. **Registry v2** — `custom_literals.json` gains a `version` marker
     and an `id` field on each entry, assigned by the app through a
     single canonical loader (`_load_registry()` — one reader for
     setup/build/watch/preflight/status/literals). Lazy one-time
     migration on first load (stderr note, idempotent, add-only:
     unknown fields, non-string entries, and unknown top-level keys are
     preserved; duplicate values collapse; duplicate ids repaired with
     a masked warning; unreadable files are never overwritten;
     `version > 2` loads read-only). **Downgrade-compatible by verified
     reader behavior**: the battery runs the actual v0.4.1 binary
     against a migrated registry.
  3. **`literals` CLI** — `literals add VALUE... [--mask STYLE]
     [--file FILE] [--json]` (prints the assigned id per value;
     duplicates return the existing id; `--mask` applies to every value
     in the invocation; `--file` = line-delimited bulk) and `literals
     list [--json]` (id + masked value, sorted by value). Every mutation
     goes through the canonical loader/writer — no second
     implementation. CLI rules: `--help` → usage exit 0; unknown flags
     → verbatim warning + continue; usage errors → exit 2.
  4. **Battery +31 (177 → 208)** — migration idempotence, entry-id
     stability across reorder, duplicate repair/preservation, 0600
     preservation, real-v0.4.1-reader downgrade probe, JSON stdout
     purity on the post-upgrade first run, `literals` contract, build
     migration, plus fixes pinned from the audit pass:
     top-level keys survive `literals add`/`setup` writes, no-op adds
     never rewrite, empty values rejected, full-mask entries list as
     `***`. CI checkout now fetches full history + tags
     (`fetch-depth: 0`) so the downgrade probe always runs.
- **Docs** — `docs/watch-schema.md` gains the `value_id` contract
  (definition, join path, duplicate semantics, resolved-rows note);
  `docs/format-spec.md` documents registry v2 + the `literals` command;
  README "Add your own secrets" leads with `literals add`; the example
  registry file is v2-shaped; the preflight demo is re-pinned to
  v0.4.2.

## [v0.4.1] - 2026-08-20

### Added
- **`watch` protected-value matching**:
  1. **Registry matching** — scan values whose exact sha256 matches a
     `custom_literals.json` entry (the app's known-value registry) are
     classified as **protected values** and reported in a new
     `exposure.protected_values` array (additive; schema stays
     `watch/v1`). Live-registry semantics: declaring a literal takes
     effect on the next run — no `--reset` needed.
  2. **Exit-code fix (the substantive gap)** — a protected value whose
     occurrences increase since baseline (`delta: increased`) or appears
     for the first time (`delta: new`) is now a 🔴 **PROTECTED VALUE
     RE-DETECTED** event → **exit 1**. Previously such a reappearance
     landed in `changed_values` with exit 0 — exactly what the house's
     leak_scan CONFIRMED tier alerts on. `decreased`/`unchanged` stay
     informational (exit 0); a value moving files with unchanged total
     count produces no event (value-level monitor, documented).
  3. **Terminology contract** — "protected value" (user-declared via the
     registry) · "detection" · "increased"; watch never claims
     "confirmed leak". Matching is exact-value only and limited to the
     credential-shaped scan domain (PII-only literals never match, by
     design).
- **Per-subcommand `--help`** — every subcommand prints its usage line and
  exits 0.
- **Unknown-flag warnings** — unknown `--*` flags on `watch`/`preflight`
  are still tolerated but never silent: stderr
  `Warning: unknown option '--foo'` (a typo like `--jason` is now visible
  in cron logs).
- Battery: +26 checks (151 → 177): protected-value matrix (new /
  increased / decreased / unchanged / live-registry), overlay rule,
  surface audit (raw values + sha256 absent from every surface), CLI
  contract (incl. positional --help).

## [v0.4.0] - 2026-08-20

### Added
- **`watch` v2 — three-track delta monitoring** (external design guidance):
  1. **Exposure deltas** — beyond new values: `resolved_values`
     (informational — "No longer detected in the current scan scope.
     This does not confirm that the credential is dead or revoked"),
     `changed_values` (±occurrences), family rollups, and per-file count
     changes. New values still exit 1.
  2. **Protection configuration deltas** — custom literals / key
     patterns added/removed (fingerprint-set diffs, duplicates = one),
     redact_patterns fingerprint change, mask-policy change. Counts and
     fingerprints ONLY — raw literals never appear, not even masked.
     Wording contract: configuration deltas, never effectiveness.
  3. **Engine state transitions** — `active` / `partial` / `none` with
     explicit blocks (installed / restored / degraded / removed).
- **Explicit exit-code contract** — NEW values = 1 · `active→partial`
  (degraded) = 1 · `active→none` (engine removed) = 1 · `none→active` /
  `partial→active` = 0 · config-only / resolved / changed = 0 ·
  usage = 2. `partial` is never ambiguous — degraded protection alerts
  exactly like removal (matches `check`).
- **`watch --json` / `--json-out`** — the delta object (schema
  `info-guard/watch/v1`, new `docs/watch-schema.md`): exposure rows
  masked 2+2 (no `value_sha256` — public surface), protection counts
  only, engine transition facts. JSON mode keeps stdout pure JSON;
  `--json-out` writes atomically 0600; missing path = usage error 2.
- **Baseline v2** (`watch-baseline/v2`, 0600) — values + protection
  fingerprint snapshot + assessment totals (incl. per-file counts).
  v1 baselines migrate in place, **delta-free** (values reconciled
  against the current scan). **Refresh-on-delta:** the baseline is
  rewritten after any run that observed a delta — every delta alerts
  exactly once; clean runs leave it untouched.
- **`setup` stamping** — setup refreshes the protection/assessment
  snapshot in an existing baseline (values preserved), so a deliberate
  config change after setup doesn't alarm on the next watch.
- Battery: 149 checks (was 104; +45: baseline v2 + migration matrix
  (fresh/stale v1), exposure deltas (resolved/changed/families/files),
  protection deltas (literals/key-patterns/mask, build→build stability),
  engine transition matrix + exit codes, watch JSON (schema, no-raw/no-
  sha greps, 0600, usage=2), setup stamping).
- Demo re-pinned from actual output (v0.4.0 header + timestamps).

## [v0.3.1] - 2026-08-19

### Fixed
- **Detection gaps (external review approved 2026-08-19, one release):**
  1. **`Authorization` headers are now key-shape findings** — `auth\b`
     never matched "Authorization" (no word boundary), so every
     `Authorization: ***` / `Authorization: Bearer …` line was silently
     skipped. `Authorization: ***` counts already-masked (protected);
     `Authorization: Bearer <jwt>` becomes actionable via the JWT rule.
  2. **Dot-structured bare-JWT detection** — JWTs under keys with no
     keyword (e.g. `NEW_JWT=eyJ…`) now fire: `eyJ` header (≥8 chars) +
     `.` + payload (≥2). The canonical jwt.io header (no dot) and
     masked-looking short forms never fire. The value classifier already
     knew JWT — the detector now matches it.
- Battery: 104 checks (was 99; +5 explicit positive/negative gap matrix:
  bare JWT under a non-keyword key → detected; jwt.io header without dot
  → NOT detected; masked-looking short `eyJ…` → NOT detected; Bearer JWT
  → detected; `Authorization: ***` → protected).
- Demo re-pinned from actual output (raw 16→21, masked 2→4, findings
  18→25, +"Authorization" protected family; candidate rows and distinct
  values unchanged at 10/6).
- format-spec: detection-coverage note (Authorization + JWT rules).

## [v0.3.0] - 2026-08-19

### Added
- **`preflight --json`** — the assessment object (schema
  `info-guard/assessment/v1`, documented in `docs/assessment-schema.md`)
  printed to stdout: pure JSON, no chatter (the object's `tool` block
  carries engine state), exit codes unchanged. The text report is its
  render — one object, two surfaces, never a second implementation.
  `preflight --json-out FILE` writes the same object atomically (temp +
  fsync + rename, 0600) and implies JSON mode.
- **`preflight watch`** — cron-friendly drift detection: re-runs the scan
  and reports NEW credential-shaped values since a baseline
  (`<state>/info-guard/watch-baseline.json`, schema
  `info-guard/watch-baseline/v1`, **value sha256 only**, 0600). First run
  (or `--reset`) creates the baseline; later runs exit 1 on new values
  (masked 2+2 · type · family · count), 0 on no-new. The baseline is
  **union-kept** across tool/gitleaks version changes (known values never
  re-alert) with a printed notice; a broken baseline is rebuilt, never a
  crash. The state dir is not in the default scan set — Info Guard never
  scans its own artifacts.
- **`examples/` demo report** — `preflight-demo.txt` + `preflight-demo.json`
  generated from a synthetic 4-file fixture (10 candidate rows, 6 distinct
  values, shared-value daggers, protected families); regenerate with
  `examples/gen-demo.sh` (fixture values are synthetic and
  runtime-constructed — no secrets in the committed examples).
- `status.confirmed_active: null` — reserved for a future validation
  step, so the field never drifts.
- `scan.generated` is now ISO-8601 UTC; the text renderer reformats for
  display (renderer owns language).

### Changed
- `families` in the assessment object is now the wrapper
  `{total_with_values, complete, items}` (friend-review point: make
  sampled/complete data explicit). Text report output is byte-identical.
- format-spec: `--json`/`watch` contract section; the taxonomy partition
  formula corrected for the v0.2.8 dedup semantics — `findings =
  raw_detections + key_name_mentions + already_masked` holds over RAW
  hits; `credential_shaped` is the deduplicated row count of that class.
- Battery: 99 checks (was 72; +27: JSON validity/schema/chatter,
  no-raw-value greps over JSON output and the watch baseline, totals
  reconciliation, JSON↔text number parity, watch lifecycle
  first-run/no-new/new-value/`--reset`/version-union).

### Fixed
- Battery watch-probe value is now runtime-constructed (a literal
  `sk-newprobe…` tripped the CI gitleaks scan — token-shaped literals
  must never appear in test files).
- CI: hermes-agent clone step retries on GitHub HTTP 429 (rate-limited
  blobless clones under 5-way matrix concurrency — two consecutive
  v0.3.0 runs failed legs on it).

## [v0.2.8] - 2026-08-19

### Changed
- External review round 2 (3 points — the friend's review of the
  v0.2.4–v0.2.7 demo report); all three confirmed against the demo fixture
  and fixed:
  1. **One counting semantics everywhere.** "Credential-shaped candidate"
     is now defined as one unique `file:line:value` row; the headline,
     family, location and affected-file tables all reconcile to it exactly
     (demo: 10 everywhere — was 16 vs 10). New totals fields:
     `raw_detections` (detector fires before dedup) and `distinct_values`
     (the rotate list); the EXECUTIVE SUMMARY states all three and names
     the collapsed duplicate hits. Affected-file rows now read
     "N findings (M candidates)".
  2. **Same-value visibility.** Family-table rows whose masked value also
     appears under another family carry a dagger (†) with a footnote
     naming the other families (one credential caught under multiple key
     names — e.g. an API key as both header and env var). A
     **DISTINCT VALUES — THE ROTATE LIST** block in the main report lists
     each distinct value once (mask 2+2 · type · count · dominant family);
     RECOMMENDED ACTIONS #1 now references the distinct-value count.
  3. **Family naming.** Literal generic key names render quoted
     (`"token"` — the key is literally named token, not a credential
     class); the synthetic prefix-only family renders as
     `(no key context)`. Data/JSON family names are unchanged.
- Battery: 72 checks (was 70; +2 reconciliation checks; the locations
  status check pinned to the area-status contract it already rendered).

## [v0.2.4] - 2026-08-19

### Changed
- `preflight` report v3 — from findings list to security assessment (external
  review signed off 08-19; 6 contract fixes incorporated): header + SCOPE line,
  STATUS, EXECUTIVE SUMMARY (metric cards with the family-attributed ·
  unattributed reconciliation), CREDENTIAL EXPOSURE BY FAMILY with the
  `VALUES — MATCH AGAINST YOUR CURRENT CREDENTIALS` proof list (2+2 masked,
  top 15, `--full` for all), EXPOSURE LOCATIONS (absolute candidate counts per
  area, session-timestamp date ranges, qualified pattern observation), REDACTION
  EFFECTIVENESS (family or area scope), WHY AM I SEEING THIS, RECOMMENDED
  ACTIONS, and appendices (detection telemetry + finding ledger).
- Tier taxonomy is now an explicit partition (credential-shaped / key-name
  mention / already-masked), stated in the report; family counts are exact at
  scan time; protected-only families and VALUES carry "top N of M" notes.
- No charts (owner decision 08-19) — totals are the fact; a visual chart stays
  a renderer-only add later (the assessment object carries the counts).

### Refinements (v0.2.5, same release — owner review of the shipped report)
- **Engine line** in the header: install state + installed version (new
  `state/info-guard/install.json` manifest written by install.sh) — or
  NOT INSTALLED for the decide step.
- **VALUES + REDACTION EFFECTIVENESS merged** into one CREDENTIAL EXPOSURE BY
  FAMILY table: Family · Type · Qty · Value (masked 2+2) · Status circle
  (Exposed/Mixed/Protected), sorted by status group then alphabetically;
  the per-value list lives in `--full` ("+N more" hint per family).
- **EXPOSURE LOCATIONS expanded**: masked counts + area status per area
  (the former area-scope rows moved here — one home for area-level data).
- **Table headings** on every table (terminal and PDF).
- **WHY AM I SEEING THIS**: Status now shows the redaction status (matching
  the merged table); "active status unknown" moved into the Action line.
- **Appendix A (telemetry) removed from the main report** — `--full` only
  (forensic mode; the main report is the assessment).
- Fixed: literal `<br>` rendering between the exec-summary card lines in the
  styled PDF renderer; "1 occurrences" pluralization in redaction notes.

### Refinements (v0.2.6, same release — second owner review)
- **WHY AM I SEEING THIS removed** — redundant with the merged table's
  status column (the facts stay in the assessment object).
- **Appendix renumbering**: the finding ledger is now **APPENDIX A** in the
  main report (and the complete-ledger form in `--full`); detection
  telemetry moves to **APPENDIX B** (`--full` only).
- **Ledger rows slimmed**: the context line (…`KEY=***`…) is dropped from
  appendix items — file:line + the 2+2 masked value only.
- Fixed (styled PDF renderer): the body was built by interpolating a Python
  *list* into the HTML template, so the list repr (`['…', '\n…']` fragments)
  rendered as stray characters between sections since v0.2.3 — now joined
  properly; the EXECUTIVE SUMMARY cards get inline SVG icon badges (red/
  orange circles, key, shield) instead of plain dots.

### Refinements (v0.2.7, same release — third owner review)
- **EXECUTIVE SUMMARY cards**: SVG pictograms reverted to distinct color
  dots (the PDF font stack lacks emoji glyphs, so dots are the reliable
  badge) — red / orange / blue / green per card.
- **Table Status columns de-duplicated**: the small dots were redundant
  with the card dots — status columns are text-only now.
- **EXPOSURE LOCATIONS status semantics**: masked is the share of the
  area's *candidates* already redacted — all masked → 🟢 Protected (was
  "Mostly masked" even at 1 of 1), ≥ half → Mostly masked, some → Mixed,
  none → Exposed.
- **APPENDIX A title**: the "(sample — one per family; …)" hint moved to a
  smaller subtitle under the title.
- Fixed (styled PDF renderer): after the B→A renumbering, the ledger
  section fell through to the raw `<pre>` renderer (its handler still
  matched APPENDIX B) — the styled ledger cards are back; the ledger
  handler now owns APPENDIX A and the telemetry handler owns APPENDIX B.

## [v0.2.3] - 2026-08-18

### Changed
- `preflight` report refinements (covers v0.2.1–v0.2.3):
  - DETAILS: one-example-per-family value sampler, with `--full` escape hatch for the complete listing.
  - NEXT STEPS: re-run checklist replaced with the install/rotate decision fork; re-run expectation corrected (rotation does not clear existing rows).

## [v0.2.0] - 2026-08-18

### Changed
- `preflight` v2.1 report: structured, human-readable output with a leak pointer (bottom-line totals, tier counts, top token-format values, secret-family aggregation, next-steps checklist, deduped ledger).

## Initial release - 2026-08-16 (untagged)

### Added
- Info Guard v1: exact-value redaction layer for Hermes Agent (redactor patch + installer + uninstaller).
- `preflight`: zero-config leak scan of Hermes' own data (gitleaks up-front check, optional install).
- `setup`: interactive bootstrap wizard.
- Test battery (`test.sh`) and CI matrix covering supported Hermes versions.
- Docs: format spec, examples.

[Unreleased]: https://github.com/db3-studio/info-guard/compare/v0.4.0...HEAD
[v0.4.0]: https://github.com/db3-studio/info-guard/compare/v0.3.1...v0.4.0
[v0.3.1]: https://github.com/db3-studio/info-guard/compare/v0.3.0...v0.3.1
[v0.3.0]: https://github.com/db3-studio/info-guard/compare/v0.2.8...v0.3.0
[v0.2.8]: https://github.com/db3-studio/info-guard/compare/v0.2.7...v0.2.8
[v0.2.7]: https://github.com/db3-studio/info-guard/compare/v0.2.6...v0.2.7
[v0.2.6]: https://github.com/db3-studio/info-guard/compare/v0.2.5...v0.2.6
[v0.2.5]: https://github.com/db3-studio/info-guard/compare/v0.2.4...v0.2.5
[v0.2.4]: https://github.com/db3-studio/info-guard/compare/v0.2.3...v0.2.4
[v0.2.3]: https://github.com/db3-studio/info-guard/compare/v0.2.0...v0.2.3
[v0.2.0]: https://github.com/db3-studio/info-guard/compare/9aee07b...v0.2.0
