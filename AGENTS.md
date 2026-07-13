# AGENTS.md

Guidance for AI agents working in this repo. Keep it current when structure or conventions change.

## Overview

`fpe` is an Elixir library for **format-preserving encryption (FPE)**. It encrypts a
numerical string into another string of the **same length over the same alphabet**.
It implements two FFX modes:

- **FF3-1** ([NIST SP 800-38G Rev. 1 draft](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38Gr1-draft.pdf)) — fixed **7-byte** tweak.
- **FF1** ([NIST SP 800-38G](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38G.pdf)) — variable-length tweak.

Both sit behind the single `FPE` facade; `FPE.FF1` is the default algorithm.

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

CI (`.github/workflows/ci.yml`) runs: deps hygiene, `format --check-formatted`,
`credo --strict`, `test --cover`, and `dialyzer`. Green locally on all of these ≈ green CI.

## Architecture

Facade → algorithm → per-alphabet codec:

- **`FPE`** (`lib/fpe.ex`) — public API and struct (`%FPE{algorithm, codec}`):
  `new/3`, `new!/3`, `encrypt/3`, `encrypt!/3`, `decrypt/3`, `decrypt!/3`. `new/3` takes
  `(key, mode \\ :ff1, radix_or_alphabet_or_codec)` where **`mode` is an atom** (`:ff1` |
  `:ff3_1`, not a module). It resolves the codec (`init_codec/1`) then the algorithm
  (`init_algorithm/3`, which maps the atom to `FF1.new_ctx` / `FF3_1.new_ctx` and returns
  `{:error, {:unknown_mode, mode}}` otherwise). This module holds the **full how-to-use
  guide** in its moduledoc (contexts, alphabets, tweaks), plus the **`use FPE`** macro
  (see below).
- **`FPE.Algorithm`** (`lib/fpe/algorithm.ex`) — a one-function protocol,
  `do_encrypt_or_decrypt(t, tweak, input, encrypt?)`. Each mode implements it via a
  `defimpl ... for: __MODULE__` inside its own file.
- **Algorithm modules**:
  - **`FPE.FF3_1`** (`lib/fpe/ff3_1.ex`) — FF3-1 mode. Fixed 7-byte tweak; uses
    `IntermediateForm` for the REV/left-pad arithmetic. Public helpers: `new_ctx/2`,
    `codec/1`, `constraints/1`.
  - **`FPE.FF1`** (`lib/fpe/ff1.ex`) — FF1 mode (`@moduledoc false`). Variable-length
    tweak; does **not** use `IntermediateForm`.
- **`FPE.FFX`** (`lib/fpe/ffx.ex`) — shared FFX byte-string primitives (`num/1`,
  `revb/1`) and the nested **`FPE.FFX.Codec` protocol**: `radix/1`, `normalize_input/2`,
  `split_numerical_string_at/3`, `numerical_string_to_int/2`,
  `int_to_padded_numerical_string/3`, `concat_numerical_strings/3`.
- **Codec implementations** (`lib/fpe/ffx/codec/`):
  - `Builtin` — radix 2..36 over ASCII `0-9a-z`, case-insensitive. Numerical string =
    binary. Built via `maybe_new/1` (returns `nil` on non-match, so the facade can fall
    through to `Custom`).
  - `Custom` — arbitrary alphabets, **one Unicode scalar per symbol**, heavily validated.
    Numerical string = NFC codepoint list. Most recent work lives here.
  - `NoSymbols` — integers tagged with a length (`%NumString{}`), no string alphabet;
    radix up to 65535.
- **`FPE.FFX.IntermediateForm`** (private) — record with radix/mask/bits-per-symbol for
  FF3-1's arithmetic.

## Supervised context: `use FPE` + `FPE.Agent`

For callers who don't want to thread a `%FPE{}` through every call, `use FPE` generates a
module that keeps its context under a supervision tree (mirroring `sqids`):

- **`use FPE`** (macro in `lib/fpe.ex`) generates `child_spec/2,3`, `start_link/3`,
  `encrypt/2`, `encrypt!/2`, `decrypt/2`, `decrypt!/2`, `constraints/0`, `codec/0`, `fpe/0`,
  and requires the caller to implement the **`child_spec/0` callback** (`@callback` on `FPE`)
  declaring `child_spec(key, mode, radix_or_alphabet_or_codec)`. Config is supplied at
  **runtime** in that callback — never baked into `use` — which keeps the AES **key** out
  of the build artifact. There is deliberately **no compile-time (`@ctx`) mode**: unlike
  sqids' non-secret config, an FPE context embeds a secret key.
- **`FPE.Agent`** (`lib/fpe/agent.ex`, `@moduledoc false`) — a near-direct port of
  `Sqids.Agent`: `:proc_lib` + `:gen_server.enter_loop` + `:hibernate`, storing the
  `%FPE{}` in a per-module `:persistent_term` (`{FPE.Agent, module}`). `get/1` returns
  `{:ok, fpe} | {:error, {:ctx_not_found_for_module, module}}`; `terminate/2` erases the
  term only on healthy exits (`:normal`/`:shutdown`) to avoid GC churn on crash-restart
  loops. Holds an opaque `%FPE{}`, so it knows nothing about keys or codecs.
- Tests exercise this via `test/helper/setup_modules.ex` (`use FPE` modules) and start them
  the way a supervisor would — through the child spec's MFA (`start_setup_module/1` in
  `test/ff3_1_test.exs`).

> Superseded the old `FPE.FF3_1.Setup` / `Setup.Server` (single supervised mode, mis-homed
> under `FF3_1`, three nested structs). Don't reintroduce that shape.

## The Custom codec (read its moduledoc first)

`lib/fpe/ffx/codec/custom.ex` is the subtle part. Each symbol is a single Unicode scalar
that is validated to **stand alone as exactly one grapheme cluster**. This yields two guarantees:

- **Round-trip**: ensured forever for any accepted alphabet (codepoint tokenization + NFC, which
  is frozen for assigned characters by Unicode's stability policy).
- **Visual-unit preservation** (visual out = visual in): ensured per Unicode version; grapheme
  segmentation has no formal stability policy, so it could in principle drift — but data still
  decrypts if it ever does. ASCII is the formally-frozen subset.

Validation rejects, per codepoint: category `:other` (unassigned/control/format/surrogate/private),
combining class ≠ 0, conjoining Hangul jamo, whitespace/separators, non-NFC forms, and anything that
merges with an adjacent symbol. It uses **undocumented OTP internals**
(`:unicode_util.lookup/1` for category+ccc, `:unicode_util.gc/1` for the standalone probe) to avoid
an ex_unicode dependency — there is a pin test guarding the `lookup/1` map shape.

## Conventions

- **Module names** in the `FPE.FF3_1`/`FF1`/`FFX` namespaces trip Credo's
  `Readability.ModuleNames`; every such file disables it with a leading
  `# credo:disable-for-this-file Credo.Check.Readability.ModuleNames` (and often
  `Readability.VariableNames`, since the code follows the spec's `vX`/`vA` naming).
  Match that in new files.
- **Return shapes**: `{:ok, _} | {:error, reason}` with structured reason tuples; `!` variants raise.
- **Codec unit discipline**: each codec defines its own `numerical_string` representation.
  `normalize_input/2` is the single normalization boundary — keep length, split, and decode in the
  **same unit** (this was the source of a real round-trip bug; don't mix graphemes/codepoints/NFC).
- Dev/test compile with `warnings_as_errors` (see `elixirc_options/1` in `mix.exs`).

## Tests

- `test/fpe_test.exs` — `doctest FPE` (exercises the how-to-use guide's examples).
- `test/ff1_test.exs` — **official NIST FF1 sample vectors**, cross-checked against
  capitalone/fpe.
- `test/ff3_1_test.exs` — no official FF3-1 vectors exist; the `ubiq-fpe-go` vectors are
  copied in. Also `doctest FPE.FF3_1`.

## Gotchas

- **`mix format` runs the Styler plugin** — it restructures code (aliases, pipes, casing), not just
  whitespace. Expect edits beyond what you wrote; always run it before committing so CI's
  `--check-formatted` passes. Formatter inputs include `test/data/**`.
- **Large-alphabet test fixtures** (`test/data/alphabet_*.txt`) are generated, not hand-edited:
  `mix run test/data/generate_alphabet.exs <count> <output_path>`. The generator gates each
  candidate through `Custom.new/1`, so fixtures can't drift from the codec's acceptance rules.
- **`new!/1` and `encrypt!`/`decrypt!` raise with a TODO placeholder exception** (`raise "TODO
  proper exception: ..."`) in `lib/fpe.ex` — proper exception types are not yet defined.
- Git workflow here is commit-directly-to-`main` (solo library); commit only when asked.
