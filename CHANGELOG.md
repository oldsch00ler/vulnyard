# Changelog

All notable changes to Vulnyard are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/). Entries are generated from the
commit history by `scripts/release.py`.

## [0.3.2] – 2026-10-23

### Changed

- Stop counting findings of a project's first scan as new threats

### Fixed

- Fix EPSS missing for findings reported under a GHSA or OSV id

## [0.3.1] – 2026-10-23

Maintenance release without user-visible changes.

## [0.3.0] – 2026-10-23

### Added

- Add a save button to the notification settings and show actions as buttons
- Add a Threats page with exploited, likely and new serious vulnerabilities
- Add a read-only MCP endpoint for coding agents

### Changed

- Show actions across the app as buttons with a hover state
- Show the previous-page control on the vulnerabilities page as a button

### Fixed

- Fix the app failing to connect to the bundled database with a custom POSTGRES_PASSWORD
- Fix scan concurrency set in the UI being ignored
- Fix chat notifications reading metrics before Dependency-Track recomputed them

## [0.2.0] – 2026-10-20

### Added

- Add release container images published to GitHub Container Registry

## [0.1.0] – 2026-10-01

First public release – see the README for everything Vulnyard does.
