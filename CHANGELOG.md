# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `ExFPE` facade over the FFX family, with `new/2,3`, `encrypt/3`, `decrypt/3`
  and raising `!` variants.
- **FF1** mode ([SP 800-38Gr1
  2pd](https://csrc.nist.gov/pubs/sp/800/38/g/r1/2pd)), the default and only
  NIST-approved mode. Variable-length tweak; verified against the official NIST
  sample vectors.
- **FF3-1** mode ([SP 800-38G Rev. 1 first
  draft](https://csrc.nist.gov/pubs/sp/800/38/g/r1/ipd)), fixed 7-byte tweak.
  Provided for interoperability only — NIST removed the FF3 family and it is
  not approved.
- Alphabets: a built-in radix 2–36 alphabet (`0-9a-z`, case-insensitive) and
  custom Unicode alphabets up to radix 65535, plus a symbol-less raw integer
  mode (`{:raw_only, radix}` with `ExFPE.raw_encrypt/4`/`raw_decrypt/4`).
- `use ExFPE` for keeping a context under a supervision tree
- Structured `{:error, reason}` tuples and an exception hierarchy
  (`ExFPE.ArgumentError`, `ExFPE.InputError`, `ExFPE.NotStartedError`).

[Unreleased]: https://github.com/g-andrade/ex_fpe/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/g-andrade/ex_fpe/releases/tag/v0.1.0
