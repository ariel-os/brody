# Changelog

All notable changes to `brody` are documented in this file.

## [0.1.1] - 2026-10-09

### Fixed

- Bug fix - COSE_Sign1 does not attach the digest payload following the draft-ietf-suit-manifest-37 specification

## [0.1.0] - 2026-09-21

- Initial implementation

## [Unreleased]

### Added

- `docs/DESIGN.md`: design documentation covering architecture, the `SUIT_Envelope`/
  `COSE_Sign1` pipeline, key handling, error model, and deliberate non-goals.
- Doc comments for previously undocumented items in `src/main.rs` (`Args`, `parse_args`,
  `load_signer`, `run`).
- `repository` field in `Cargo.toml`, required for crates.io publishing.
- Change package name to `brody`

### Fixed

- README status link pointed at a removed `docs/PLAN.md`; now points at
  `docs/DESIGN.md`.
- Restored dual MIT/Apache-2.0 licensing to match `Cargo.toml`'s
  `license = "MIT OR Apache-2.0"`: split the single `LICENSE.md` into
  `LICENSE-MIT` and a new `LICENSE-APACHE`, and fixed the README's license
  section (previously MIT-only with a dead link).
