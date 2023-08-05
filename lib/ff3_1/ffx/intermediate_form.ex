# credo:disable-for-this-file Credo.Check.Readability.ModuleNames
defmodule FF3_1.FFX.IntermediateForm do
  @moduledoc false
  import Bitwise

  @enforce_keys [:radix, :mask, :bits_per_symbol, :perfect_fit]
  defstruct [:radix, :mask, :bits_per_symbol, :perfect_fit]

  @opaque ctx :: %__MODULE__{
            radix: FF3_1.FFX.radix(),
            mask: pos_integer,
            bits_per_symbol: pos_integer,
            perfect_fit: boolean
          }

  @spec new_ctx(FF3_1.FFX.radix()) :: ctx()
  def new_ctx(radix) do
    precise_bits_per_symbol = :math.log2(radix)
    bits_per_symbol = ceil(precise_bits_per_symbol)

    %__MODULE__{
      radix: radix,
      mask: (1 <<< bits_per_symbol) - 1,
      bits_per_symbol: bits_per_symbol,
      perfect_fit: bits_per_symbol == precise_bits_per_symbol
    }
  end

  @spec left_pad_and_revert(ctx, non_neg_integer, non_neg_integer) :: non_neg_integer
  def left_pad_and_revert(ctx, number, tail_padding) do
    case ctx.perfect_fit do
      false ->
        imperfect_lpr_recur(
          ctx.radix,
          tail_padding,
          number,
          _acc = 0,
          _iter = 0
        )

      true ->
        perfect_lpr_recur(
          ctx.mask,
          ctx.bits_per_symbol,
          tail_padding,
          number,
          _acc = 0,
          _iter = 0
        )
    end
  end

  ## Internal

  defp imperfect_lpr_recur(radix, tail_padding, number, acc, iter) do
    case number != 0 do
      true ->
        weight = rem(number, radix)
        number = div(number, radix)
        acc = acc * radix + weight
        iter = iter + 1
        imperfect_lpr_recur(radix, tail_padding, number, acc, iter)

      false ->
        padding_needed = max(0, tail_padding - iter)
        acc * Integer.pow(radix, padding_needed)
    end
  end

  defp perfect_lpr_recur(mask, bits_per_symbol, tail_padding, number, acc, iter) do
    case number != 0 do
      true ->
        weight = number &&& mask
        number = number >>> bits_per_symbol
        acc = bor(acc <<< bits_per_symbol, weight)
        iter = iter + 1
        perfect_lpr_recur(mask, bits_per_symbol, tail_padding, number, acc, iter)

      false ->
        padding_needed = max(0, tail_padding - iter)
        acc <<< (padding_needed * bits_per_symbol)
    end
  end
end
