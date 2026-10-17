# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Vigie console (Tauri 2, Windows and Android): device pairing, authenticated read API and incident acknowledgement (3a6922d)
- Cross-cutting foundation: single SQLite writer, uniform API errors with `X-Request-Id`, injectable clock, gitleaks, static musl build and TLS dependency guard in CI (#9, 624569f)
- `LogSource` contract: normalized `Entry`, combined log splitter, timezone handling and shared fixtures (#7, b45372c)
- Two-axis site typology (CMS kind filters checks, runtime filters commands) and the closed command list (#2, 3477886)
- Signed command channel `/r/v1/commands` with a hash-chained, signed audit log and its CLI (#10, 58bfa82)
- PHP agent 0.2.0: signed pull, verified responses, `ping` and `rotate-key`, end-to-end test against the real watcher in CI (#6, 4fe9ba9)
- Log analyzer wired into `tick`: bot catalogue, bounded path globs and declarative rules, incremental folding into persisted aggregates, IP suspicion score and load ported from the module, structured analysis snapshots, bounded `logs` findings, and robot user-agent signatures shared across sites without any IP (#8)
- Alwaysdata log adapter: `/r/v1/logs` signed batches with high-water-mark idempotence, PHP agent 0.3.0 incremental reading across gz rotation, normalized entries only, 30-day purge, `AlwaysdataSource` (#1)
- Vigie console: device token in the Windows Credential Manager (local persistence) and in Android `no_backup` storage with backup and device transfer disabled, migration from 0.1.1, security guards locked by tests (#12 phase 1)
- `.htaccess` recommendations from the log analysis (#13): graded proposals (robots.txt, then user-agent, then time-limited IP rule), never against search engines, browsers, social previews or Vigie itself; closed `# BEGIN vigie` block grammar validated identically by the watcher and the PHP agent 0.4.0 (shared vectors and differential fuzz); `htaccess-apply` and `htaccess-rollback` through the signed command channel with differential sandbox, Apache clock probes, compare-and-swap, private backup, smoke test and automatic rollback; `vigie site recommend`
- Single capability registry (#4): checks, heartbeat, integrity, agent families, logs and typology warnings declare their required site typology in one place, used by tick, report ingestion, the API and the CLI; unknown agent families are dropped and counted, closures say "no longer watched" instead of "restored"; agent keys only on php sites; critical-path audit (`vigie/docs/audit-chemin-critique.md`) and the CI musl binary published with its SHA-256
- Vigie console 0.2.0 (#12): Trafic view (visitors, blocks, load) fed by the logs API, paginated lists, typed API errors, write actions shown as non-executable proposals; publication requires #5, #8 and #13 deployed on the VPS
- Console API security (#5): per-device and per-IP (/64) rate limits with 429 and `Retry-After`, call log without tokens or raw paths, strict headers and no CORS, 415 only for typed bodies, sanitized log text, JSON key snapshot test, keyset pagination (`limit`, `cursor`, `next_cursor`), `GET /api/v1/sites/{id}/logs` and `/logs/ips` (medium and high verdicts only, 48 h), 200 sites at most

## [v1.11.2] - 2026-10-16

### Added
- UptimeRobot probe recorded in the decision registry: no inbound webhook in V1, and the requirements a future webhook must meet (672fa0c)

## [v1.11.1] - 2026-10-16

### Added
- Dated product decision registry `vigie/docs/decisions.md`: every point left open by the 2026-10-15 brainstorm is settled, and the Vigie name is final (fc162a9)

## [v1.11.0] - 2026-10-16

Adds Vigie, a multi-site watcher living in `vigie/`, independent of the PrestaShop module, which is unchanged (`v1.10.0..cb90a9d`).

### Added
- Vigie watcher skeleton (Rust, axum, SQLite) and VPS provisioning (1e26a20)
- External checks and e-mail alerts (2b55edd)
- Signed agent reports (ed25519) and agent silence detection (4932d34)
- PHP agent and critical file integrity checks (208a73d)
- Local replay of the 2026-09-07 incident as an acceptance test (b1e1161)
- Module deployment script with lock and SSH validations (aaff9db)
- Vigie console mockups and design handoff (c17e4ce)
- Repository rule: no real production data in this public repository (46b2ad9)

### Changed
- Project renamed Vigie: `monitor/` becomes `vigie/` (1a9de67)

### Fixed
- VPS installation through `git archive`, LF line endings under `autocrlf` (f9b9604)
- `/health` proof taken outside the deployment lock (8b6a642)
- OOM priority of `tick` aligned with `serve` (c874f74)

## [v1.10.0] - 2026-09-26

First tagged release; covers the full history since the initial scaffold (`5ecd249..1f171d0`).

### Added
- Bot/scraper analytics in traffic stats (`requests_scrapers`), AI bot catalog, IP suspicion scoring, load diagnostic, htaccess doctor and robots.txt tools with admin tabs (1f171d0)
- Resources monitoring, sampling and 500 tracing (b7bdc53)
- Unified tab system with stats/conversion views and cron config (706a9ae)
- Stats endpoints switched to POST, `errors_500_pages` added (df99891)
- Stats: DailyStat entity, HTTP log parser, nightly cron with token auth, stats and conversion UI tabs (86f70b3, fde7328, cf9897b, d172019)
- Log viewer: crawlers, PHP errors, htaccess block/unblock (647c1a6)
- Initial module scaffold — log viewer & analyser (5ecd249)

### Changed
- Nightly cron guarded by a MySQL lock against parallel runs (409 `running`), sargable order date range, compiled bot regex with per-UA cache, capped 500 checkout detail (1f171d0)

### Fixed
- Funnel scope in conversion stats (df99891)
- Cron `run()` renamed to `processCron()` to avoid ControllerCore visibility conflict (9968b14)
- Container compile: removed `controller.service_arguments` tag, service ID in routes.yml (ae5ab75, 492f07b)
- Autoload fallback when `vendor/` is absent (d6d0703)
- CSRF on block and settings forms, htaccess overwrite guard, install order, `fclose` in `finally` (3bc1a2b, 00ecb53)
