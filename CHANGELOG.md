# Changelog

All notable changes follow [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and semantic versioning.

## [Unreleased]

## [0.1.1] - 2026-09-22

### Added

- Parallel filesystem scanning with configurable worker count and live Rich progress.
- Compact Chinese terminal dashboard with capped, severity-sorted findings.
- Per-rule per-file finding limits for noisy generated content.

### Changed

- Reduced entropy noise from lockfiles, source maps, SSH host keys, smali bytecode, XML resources, and generated asset tables.
- Added keyword prefilters and lazy context construction to avoid unnecessary regular-expression work.
- Added cache and site-packages defaults to directory ignores.

## [0.1.0] - 2026-09-22

### Added

- Local filesystem, Git worktree, staged-line, and bounded-history scanning.
- Built-in credential rules plus conservative Shannon-entropy detection.
- Masked terminal, JSON, and SARIF reports.
- YAML/TOML configuration, ignores, allowlists, custom rules, and baselines.
- pre-commit hook, GitHub Actions, tests, and PyPI-ready packaging.

[Unreleased]: https://github.com/aidileide/SecretScanner/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/aidileide/SecretScanner/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/aidileide/SecretScanner/releases/tag/v0.1.0
