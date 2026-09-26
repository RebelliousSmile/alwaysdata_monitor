# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
