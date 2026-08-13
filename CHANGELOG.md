# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Implemented KDL v2 multi-line strings (`"""` and `#"""`), including auto-dedentation and newline normalization (#46)
- Declared a minimum supported Rust version of 1.93, which is required by edition 2024 and is now covered by CI (#53)

### Changed

- Changed the parser to use a single span type internally; the parse functions are no longer generic over the span type, but custom span types can still be obtained via conversion (#44)
- Migrated the parser from `chumsky` v0.9.3 to v0.13 (#45)

## [3.4.0] - 2026-06-21

### Added

- Added support for parsing named enum fields (#31)

### Fixed

- Boxed one grammar node (`prop_or_arg`) so the longest monomorphized symbol names stay under the macOS 4096-byte limit. This removes the need for a custom linker (`rust-lld`) when building or `cargo install`ing on macOS, with no measurable parsing-performance impact (#49)

## [3.3.1] - 2025-04-30

### Added

- Implemented common `std` library traits for all public types (#5)

### Changed

- Made the fields of `knus::ast::Integer` and `knus::ast::Decimal` public (#1)
- Changed `parse_*` functions to take `file_name: impl AsRef<str>` to match `miette` (#18)

### Fixed
- Upgraded to `miette` v7.6.0, fixing several graphical bugs when reporting errors (#3)
- Improved macro hygiene to avoid clashing with imported `Result` aliases (#19)

## [3.2.0] - 2024-10-24

The beginning of time — this version is identical to [`knuffel` v3.2.0](https://crates.io/crates/knuffel/3.2.0).

[unreleased]: https://github.com/TheLostLambda/knus/compare/v3.4.0...HEAD
[3.4.0]: https://github.com/TheLostLambda/knus/compare/v3.3.1...v3.4.0
[3.3.1]: https://github.com/TheLostLambda/knus/compare/v3.2.0...v3.3.1
[3.2.0]: https://github.com/TheLostLambda/knus/releases/tag/v3.2.0
