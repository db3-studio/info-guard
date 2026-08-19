# Changelog

All notable changes to Info Guard are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [SemVer](https://semver.org/).

> Convention: micro-version fixes within the same workstream are consolidated into the latest entry of that wave, not captured per tag.

## [Unreleased]

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

[Unreleased]: https://github.com/db3-studio/info-guard/compare/v0.2.4...HEAD
[v0.2.4]: https://github.com/db3-studio/info-guard/compare/v0.2.3...v0.2.4
[v0.2.3]: https://github.com/db3-studio/info-guard/compare/v0.2.0...v0.2.3
[v0.2.0]: https://github.com/db3-studio/info-guard/compare/9aee07b...v0.2.0
