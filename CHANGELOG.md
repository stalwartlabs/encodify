# Change Log

All notable changes to this project will be documented in this file. This project adheres to [Semantic Versioning](https://semver.org/).

## [1.0.1] - 2026-09-29

### Fixed
- `--cfg encodify_scalar` now forces the portable fallbacks: the build script read `CARGO_CFG_encodify_SCALAR`, but cargo exports cfg names uppercased (`CARGO_CFG_ENCODIFY_SCALAR`), so the SIMD kernels stayed enabled.

## [1.0.0] - 2026-09-28

### Added
- Initial release.

### Changed

### Fixed
