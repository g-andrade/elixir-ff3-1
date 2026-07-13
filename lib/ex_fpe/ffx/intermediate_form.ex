# credo:disable-for-this-file Credo.Check.Readability.ModuleNames
defmodule ExFPE.FFX.IntermediateForm do
  @moduledoc false

  # FF3-1's Feistel rounds carry each half around as an *integer* (its
  # `NUM_radix` value), not as a numeral string. But the spec repeatedly needs
  # `NUM_radix(REV(X))` — the integer you get by reversing the numeral string
  # *before* interpreting it (see steps 4.ii, 4.v and 4.vi of the encrypt /
  # decrypt loops in `ExFPE.FF3_1`). The obvious way to compute that is to
  # render the integer as an `m`-symbol string, reverse the symbols, and
  # re-parse — which allocates a list and walks it several times on every one
  # of the 8 rounds.
  #
  # This module fuses "left-pad to `m` symbols", "reverse", and "NUM_radix"
  # into a single arithmetic pass over the integer, never materializing the
  # numeral string. Reversing an `m`-symbol numeral string just means emitting
  # its base-`radix` digits least-significant-first; the digits that were
  # *leading* zeros in `X` become *trailing* zeros in `REV(X)`, which is where
  # `tail_padding` comes in.
  #
  # `new_ctx/1` precomputes, once per radix, the constants the hot path needs.
  # When `radix` is a power of two each symbol occupies a whole number of bits,
  # so peeling and re-packing symbols collapses to shifts and masks — the
  # `perfect_fit` fast path. Otherwise we fall back to `div` / `rem` /
  # `Integer.pow` arithmetic.

  import Bitwise

  require Record

  Record.defrecordp(:ctx, [
    # the base we work in
    :radix,
    # `2^bits_per_symbol - 1`; isolates one symbol in the power-of-two path
    :mask,
    # bits to hold one symbol: `ceil(log2(radix))`
    :bits_per_symbol,
    # true iff `radix` is an exact power of two (enables the shift/mask path)
    :perfect_fit
  ])

  @opaque ctx ::
            record(:ctx,
              radix: ExFPE.FFX.radix(),
              mask: pos_integer,
              bits_per_symbol: pos_integer,
              perfect_fit: boolean
            )

  @spec new_ctx(ExFPE.FFX.radix()) :: ctx()
  def new_ctx(radix) do
    # `ceil` so a non-power-of-two radix still gets enough bits to hold a
    # symbol; when the log2 is already integral the radix is a power of two and
    # the bit tricks apply exactly (no wasted codepoints in the bit range).
    precise_bits_per_symbol = :math.log2(radix)
    bits_per_symbol = ceil(precise_bits_per_symbol)

    ctx(
      radix: radix,
      mask: (1 <<< bits_per_symbol) - 1,
      bits_per_symbol: bits_per_symbol,
      perfect_fit: bits_per_symbol == precise_bits_per_symbol
    )
  end

  # Returns `NUM_radix(REV(X))`, where `X` is `number` written as a
  # `tail_padding`-symbol numeral string. Equivalent to left-padding `number`
  # to `tail_padding` symbols, reversing the numeral string, and reinterpreting
  # it — but computed directly on the integer, in one pass.
  @spec left_pad_and_revert(ctx, non_neg_integer, non_neg_integer) :: non_neg_integer
  def left_pad_and_revert(ctx, number, tail_padding) do
    if ctx(ctx, :perfect_fit) do
      # power-of-two radix: extract and re-pack symbols with shifts and masks
      perfect_lpr_recur(
        ctx(ctx, :mask),
        ctx(ctx, :bits_per_symbol),
        tail_padding,
        number,
        _acc = 0,
        _iter = 0
      )
    else
      # general radix: extract and re-pack symbols with div / rem / pow
      imperfect_lpr_recur(
        ctx(ctx, :radix),
        tail_padding,
        number,
        _acc = 0,
        _iter = 0
      )
    end
  end

  ## Internal

  # Peel the least-significant symbol off `number` — that's the *first* symbol
  # of `REV(X)` — and re-accumulate it most-significant-first into `acc`.
  # `iter` counts symbols consumed; the `tail_padding` symbols we never reached
  # were leading zeros in `X`, so they land as trailing zeros in `REV(X)` — the
  # closing multiply by `radix^padding_needed`.
  defp imperfect_lpr_recur(radix, tail_padding, number, acc, iter) do
    if number == 0 do
      padding_needed = max(0, tail_padding - iter)
      acc * Integer.pow(radix, padding_needed)
    else
      weight = rem(number, radix)
      number = div(number, radix)
      acc = acc * radix + weight
      iter = iter + 1
      imperfect_lpr_recur(radix, tail_padding, number, acc, iter)
    end
  end

  # Same as `imperfect_lpr_recur/5`, but for a power-of-two radix: `rem`/`div`
  # by `radix` become `&&&`/`>>>` on `bits_per_symbol`, and the multiply-and-add
  # accumulation becomes a shift-and-`bor`.
  defp perfect_lpr_recur(mask, bits_per_symbol, tail_padding, number, acc, iter) do
    if number == 0 do
      padding_needed = max(0, tail_padding - iter)
      acc <<< (padding_needed * bits_per_symbol)
    else
      weight = number &&& mask
      number = number >>> bits_per_symbol
      acc = bor(acc <<< bits_per_symbol, weight)
      iter = iter + 1
      perfect_lpr_recur(mask, bits_per_symbol, tail_padding, number, acc, iter)
    end
  end
end
