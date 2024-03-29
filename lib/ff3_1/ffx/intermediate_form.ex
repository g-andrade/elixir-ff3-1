# credo:disable-for-this-file Credo.Check.Readability.ModuleNames
defmodule FF3_1.FFX.IntermediateForm do
  @moduledoc false
  import Bitwise

  require Record

  Record.defrecordp(:ctx, [
    :radix,
    :mask,
    :bits_per_symbol,
    :perfect_fit
  ])

  @opaque ctx ::
            record(:ctx,
              radix: FF3_1.FFX.radix(),
              mask: pos_integer,
              bits_per_symbol: pos_integer,
              perfect_fit: boolean
            )

  @spec new_ctx(FF3_1.FFX.radix()) :: ctx()
  def new_ctx(radix) do
    precise_bits_per_symbol = :math.log2(radix)
    bits_per_symbol = ceil(precise_bits_per_symbol)

    ctx(
      radix: radix,
      mask: (1 <<< bits_per_symbol) - 1,
      bits_per_symbol: bits_per_symbol,
      perfect_fit: bits_per_symbol == precise_bits_per_symbol
    )
  end

  @spec left_pad_and_revert(ctx, non_neg_integer, non_neg_integer) :: non_neg_integer
  def left_pad_and_revert(ctx, number, tail_padding) do
    if ctx(ctx, :perfect_fit) do
      perfect_lpr_recur(
        ctx(ctx, :mask),
        ctx(ctx, :bits_per_symbol),
        tail_padding,
        number,
        _acc = 0,
        _iter = 0
      )
    else
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

  defp imperfect_lpr_recur(radix, tail_padding, number, acc, iter) do
    if number != 0 do
      weight = rem(number, radix)
      number = div(number, radix)
      acc = acc * radix + weight
      iter = iter + 1
      imperfect_lpr_recur(radix, tail_padding, number, acc, iter)
    else
      padding_needed = max(0, tail_padding - iter)
      acc * Integer.pow(radix, padding_needed)
    end
  end

  defp perfect_lpr_recur(mask, bits_per_symbol, tail_padding, number, acc, iter) do
    if number != 0 do
      weight = number &&& mask
      number = number >>> bits_per_symbol
      acc = bor(acc <<< bits_per_symbol, weight)
      iter = iter + 1
      perfect_lpr_recur(mask, bits_per_symbol, tail_padding, number, acc, iter)
    else
      padding_needed = max(0, tail_padding - iter)
      acc <<< (padding_needed * bits_per_symbol)
    end
  end
end
