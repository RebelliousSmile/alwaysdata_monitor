# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security
- Cron front controllers accept the token in an `X-Cron-Token` header (checked first) as well as the `token` query parameter, which stays accepted so scheduled URLs keep working; the header keeps the secret out of access logs and `Referer` values (`CronTokenGuard`)
- `rustls-webpki` 0.103.16, `webpki-roots` and `webpki-root-certs` 1.0.10 in `vigie/Cargo.lock` and `vigie/app/src-tauri/Cargo.lock` (RUSTSEC-2026-0381, -0382, -0383)

### Added
- PHPUnit 10.5 as a dev dependency of the module (`composer.lock` resolved against PHP 8.1) and a `module` workflow running the suite on PHP 8.1 and 8.4, plus a php-cs-fixer style check (`src/` reformatted to match `.php-cs-fixer.dist.php`)
- Matching inventories against known vulnerabilities (#21): `tick` matches each site's latest inventories (agent and CI) against the vulnerability base in bounded, resumable runs (global sequence, cursor compare-and-swap, budget with a reserve kept for sending alerts) on a read-only connection, groups advisories by alias (union-find), assesses each group with the F4 severity rule (KEV, EPSS) and writes one `vulns` finding per (site, component, group) with per-source provenance, a stale-inventory warning per source and a matching-error finding; migration file `0021.sql` adds runs, state, components, items, provenance, keys and waivers; audited waivers (90 days at most, reason required, SHA-256 of the reason in the signed `_veilleur` audit chain) through `vigie site vulns-ack` with a dry-run preview; grouped emails above five new findings, closed findings masked after 30 days; `vigie site components | vulns` and `vigie vulns report`; API routes `GET /api/v1/sites/{id}/components`, `/sites/{id}/vulns` and `/vulns/sources` paginated on a pinned run; console Failles and Sources de failles screens; volume test (#[ignore], release) and fictional fixtures only
- Known-vulnerability prioritisation (#18): CISA KEV (official `cisagov/kev-data` mirror, cisa.gov as fallback) and FIRST EPSS (daily gzip CSV, streamed) are declared automatically with the first vulnerability source and synced after them through the F2 engine (same lease, rate window, drop threshold, shrink guard and `vulns-sync` finding); generation-based `WITHOUT ROWID` tables swapped atomically in 5,000-row batches (migration `0019.sql`); validators bound to the URL that served them; a KEV catalogue older than the active one is refused (`stale_count`), a shrunk or failing mirror falls back to cisa.gov; EPSS `Content-Encoding: gzip` kept raw, scores in truncated integer millionths; the single F0 severity rule in `vulns/severity.rs` (`assess`, `assess_group`, `assess_unknown`, no floats, truth table and exhaustive-grid properties) read through `StoreTables` on a read-only connection; `vigie vulns sources` shows datasets and warns about a KEV catalogue older than 14 days, `vigie vulns show` explains KEV, EPSS and the resulting severity
- CMS vulnerability sources (#17): Wordfence Intelligence v3 (`production` feed, WordPress plugins, themes and core) and Friends-Of-Presta (PrestaShop modules and core) plug into the #16 sync framework; the Wordfence feed is read entry by entry (`RawValue`, 4 MiB per value) with strict identity fields and per-field fallbacks, bounds mapped to OSV events, scores read as text into integer tenths, `copyrights` kept in a stable order or replaced by a counted fixed notice; Wordfence stays locked behind a two-key terms review (binary constant checked against `failles.md`, plus `[vulns.wordfence] terms_reviewed`), re-checked right before the request, with its token in a verified 0600 file (`secret.rs`, shared with the command keys), a sensitive `Bearer` header sent to `www.wordfence.com` only, and one request per 30 minutes; Friends-Of-Presta is read from the repository `.tar.gz` by an in-house bounded tar reader and a closed YAML front-matter parser, with a closed grammar for free-text affected releases (anything else stays "range unknown", never "not affected"); audited, append-only range corrections (`vigie vulns correct`, `vigie vulns corrections --audit --verify`, migration 18) signed in the `_veilleur` audit chain and applied at read time; per-source redistribution level (`registry::redistribution`) for #21; fictional fixtures only
- `vigie-inventory` tool (#20): a second binary of the `vigie` crate reads `composer.lock`, `package-lock.json` v2/v3, `pnpm-lock.yaml` 6.0/9.0, `yarn.lock` v1 and berry (metadata 6, 8, 10) and `Cargo.lock` 3/4 with bounded readers and no new dependency, builds the same whitelisted CycloneDX 1.7 inventory as the agent (shared purl grammar, off-registry dependencies counted, required-before-dev truncation, self-revalidation), and writes it (`sbom`) or signs it with a dedicated inventory key and pushes it (`push`, no proxy, https only, no redirects, exit codes 0/1/2); the watcher accepts `[sites.inventory] sources = ["agent-php", "ci"]`, picks the source from the key that verifies, stores, rate-limits and expires inventories per (site, source) (7 days agent, 35 days ci), registers a public key only once across agent and inventory keys (`vigie site inventory-key`), and migration file 0020 adds the inventory keys and the source column; fixtures produced by the real tools, schema checked by `cyclonedx-cli` in CI, `inventory-release` workflow (pinned runners and zig, reproducible musl build, `SHA256SUMS`) and CI examples with a weekly re-send of the last successful deployment
- Component inventory from the PHP agent (#19): agent 0.5.0 reads WordPress (core, plugins, mu-plugins, themes), PrestaShop (core, modules, `$this->version` first) and `composer.lock` / `package-lock.json` read-only, never executing or parsing site code as XML, and pushes a signed CycloneDX 1.7 inventory (`vigie-inventory-v1`) to `POST /r/v1/inventory` when it changes and at least daily; the watcher opens the route only for sites declaring `[sites.inventory]`, checks before reading the body, enforces a strict whitelist with the shared purl grammar, keeps the last inventory and 30 days of history (migration 16), never treats it as a sign of life, and exposes batch reads for the matching step (#21); `--inventory` dry view; `npm-alias.json` vectors shared with the inventory tool (#20)
- Known-vulnerability sync (#16): daily `vigie vulns sync` (its own systemd timer, never `tick`) loads the OSV.dev Packagist, npm and crates.io exports declared in `[vulns] sources`; HTTPS to hard-coded origins only, conditional requests, per-source size, entry and time caps, a strict in-house zip reader (ZIP64 end, no data descriptors, overlap and CRC checks, nothing extracted to disk) checked against Python's `zipfile` in CI; an unchanged dump (304 or same SHA-256) writes no generation, a failed, hostile, too lossy (> 1 % dropped) or shrunk (< 80 % of recent loads, `--accept-shrink`) dump keeps the previous base; lease before any request, per-source rate window and `Retry-After`; a `vulns-sync` warning on the reserved `_veilleur` pseudo-site after 3 days without a successful sync, declared in the capability registry; framework (`VulnSource`, bounded `Download`, `finish_unchanged`, closed source registry) ready for #17 and #18
- Known-vulnerability model (#15): per-ecosystem version comparators (Composer `VersionParser` then `version_compare`, strict semver for npm and Cargo, PHP `version_compare` for WordPress and PrestaShop) proven by vectors, fixed-seed fuzz and a differential test against PHP 8.1 in CI; the single shared purl module; a validated OSV 1.9 subset with measured bounds, per-record licence and attribution, CVSS 3.x scores in integer tenths; SQLite storage by reserved generations under lease, swapped atomically; read-only `vigie vulns sources | show | match` (no source wired yet)
- Known-vulnerability groundwork (#14): verified sources (OSV.dev, GitHub Advisory, Wordfence v3, Friends-Of-Presta, CISA KEV, FIRST EPSS) and excluded ones, purl / CycloneDX 1.7 / OSV standards and conventions, severity, exemptions and confidentiality rules (`vigie/docs/failles.md`)
- `osv-scanner` job in `garde-fous` (#22): Vigie's own Cargo, pnpm and Composer lockfiles scanned on every push and weekly, pinned binary checked by SHA-256, dated per-folder exceptions enforced by a script; `rqrr` 0.11 removes RUSTSEC-2026-0253
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
