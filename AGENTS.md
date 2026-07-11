# AGENTS.md

Guidance for AI agents working in this repo. Keep it current when structure or conventions change.

## Overview

`ff3_1` is an Elixir library implementing **FF3-1 format-preserving encryption**
([NIST SP 800-38G Rev. 1 draft](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38Gr1-draft.pdf)).
It encrypts a string over a given alphabet into another string of the **same length over the same alphabet**.

- Min Elixir `~> 1.14`; developed on Elixir 1.20 / OTP 28. CI matrix runs 1.14–1.20.
- Runtime deps: none beyond `:crypto` (stdlib). Dev/test tooling only (see below).

## Commands

```sh
mix test                 # fast; the primary loop
mix test --cover         # with coverage (CI gate; threshold 85.71% in mix.exs)
mix format               # REQUIRED before commit — see Styler gotcha below
mix format --check-formatted
mix credo --strict       # CI gate
mix dialyzer             # CI gate (slow first run)
```

CI (`.github/workflows/ci.yml`) runs: `format --check-formatted`, `credo --strict`,
`dialyzer`, `test --cover`, and deps hygiene. Green locally on all of these ≈ green CI.

## Architecture

Public API → algorithm → per-alphabet codec:

- **`FF3_1`** (`lib/ff3_1.ex`) — public API: `new_ctx/2`, `encrypt!/3`, `decrypt!/3`, etc.
  Holds the ctx record and dispatches a radix / alphabet / codec into a concrete codec.
- **`FF3_1.FFX`** (`lib/ff3_1/ffx.ex`) — the FF3-1/FFX reference algorithm, and the
  **`FF3_1.FFX.Codec` protocol**: `radix/1`, `normalize_input/2`,
  `split_numerical_string_at/3`, `numerical_string_to_int/2`,
  `int_to_padded_numerical_string/3`, `concat_numerical_strings/3`.
- **Codec implementations** (`lib/ff3_1/ffx/codec/`):
  - `Builtin` — radix 2..36 over ASCII `0-9a-z`, case-insensitive. Numerical string = binary.
  - `Custom` — arbitrary alphabets, **one Unicode scalar per symbol**, heavily validated.
    Numerical string = NFC codepoint list. Most recent work lives here.
  - `NoSymbols` — integers tagged with a length (`%NumString{}`), no string alphabet.
- **`FF3_1.FFX.IntermediateForm`** (private) — record with radix/mask/bits-per-symbol for the arithmetic.
- **`FF3_1.Setup` / `FF3_1.Setup.Server`** — macro + GenServer for reusable named ctx setups
  (used by tests via `test/helper/setup_modules.ex`).

## The Custom codec (read its moduledoc first)

`lib/ff3_1/ffx/codec/custom.ex` is the subtle part. Each symbol is a single Unicode scalar
that is validated to **stand alone as exactly one grapheme cluster**. This yields two guarantees:

- **Round-trip**: ensured forever for any accepted alphabet (codepoint tokenization + NFC, which
  is frozen for assigned characters by Unicode's stability policy).
- **Visual-unit preservation** (visual out = visual in): ensured per Unicode version; grapheme
  segmentation has no formal stability policy, so it could in principle drift — but data still
  decrypts if it ever does. ASCII is the formally-frozen subset.

Validation rejects, per codepoint: category `:other` (unassigned/control/format/surrogate/private),
combining class ≠ 0, conjoining Hangul jamo, non-NFC forms, and anything that merges with an
adjacent symbol. It uses **undocumented OTP internals** (`:unicode_util.lookup/1` for
category+ccc, `:unicode_util.gc/1` for the standalone probe) to avoid an ex_unicode dependency —
there is a pin test guarding the `lookup/1` map shape.

## Conventions

- **Module names** in the `FF3_1`/`FFX` namespace trip Credo's `Readability.ModuleNames`; every
  file disables it with a leading `# credo:disable-for-this-file Credo.Check.Readability.ModuleNames`.
  Match that in new files.
- **Return shapes**: `{:ok, _} | {:error, reason}` with structured reason tuples; `!` variants raise.
- **Codec unit discipline**: each codec defines its own `numerical_string` representation.
  `normalize_input/2` is the single normalization boundary — keep length, split, and decode in the
  **same unit** (this was the source of a real round-trip bug; don't mix graphemes/codepoints/NFC).
- Dev/test compile with `warnings_as_errors` (see `elixirc_options/1` in `mix.exs`).

## Gotchas

- **`mix format` runs the Styler plugin** — it restructures code (aliases, pipes, casing), not just
  whitespace. Expect edits beyond what you wrote; always run it before committing so CI's
  `--check-formatted` passes. Formatter inputs include `test/data/**`.
- **Large-alphabet test fixtures** (`test/data/alphabet_*.txt`) are generated, not hand-edited:
  `mix run test/data/generate_alphabet.exs <count> <output_path>`. The generator gates each
  candidate through `Custom.new/1`, so fixtures can't drift from the codec's acceptance rules.
- **No official FF3-1 test vectors exist**; the `ubiq-go` vectors are copied into the test suite.
- Git workflow here is commit-directly-to-`main` (solo library); commit only when asked.
