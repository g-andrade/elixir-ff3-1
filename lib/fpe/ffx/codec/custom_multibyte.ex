defmodule FPE.FFX.Codec.CustomMultibyte do
  @moduledoc false

  @enforce_keys [:symbol_to_amount, :amount_to_symbol]
  defstruct [:symbol_to_amount, :amount_to_symbol]

  @opaque t :: %__MODULE__{
            symbol_to_amount: %{String.grapheme() => non_neg_integer},
            amount_to_symbol: tuple()
          }

  @spec new([String.grapheme(), ...]) :: t
  def new(ordered_graphemes) do
    %__MODULE__{
      symbol_to_amount: ordered_graphemes |> Enum.with_index() |> Map.new(),
      amount_to_symbol: ordered_graphemes |> List.to_tuple()
    }
  end

  defimpl FPE.FFX.Codec, for: __MODULE__ do
    ## API

    def radix(codec), do: tuple_size(codec.amount_to_symbol)

    def string_to_int(codec, string) when byte_size(string) > 0 do
      symbol_to_amount = codec.symbol_to_amount
      radix = map_size(symbol_to_amount)
      string_to_int_recur(string, symbol_to_amount, radix, _acc0 = 0)
    end

    def string_to_int(_codec, string) do
      raise ArgumentError, "Not a non-empty string: #{inspect(string)}"
    end

    def int_to_padded_string(codec, m, int) when is_integer(int) and int >= 0 do
      amount_to_symbol = codec.amount_to_symbol
      radix = tuple_size(amount_to_symbol)
      zero_symbol = elem(amount_to_symbol, 0)

      int_to_padded_string_recur(int, amount_to_symbol, radix, _acc0 = [])
      |> String.pad_leading(m, zero_symbol)
    end

    ## Private

    defp string_to_int_recur(string, symbol_to_amount, radix, acc) do
      case String.next_grapheme(string) do
        {symbol, remaining_string} ->
          try do
            Map.fetch!(symbol_to_amount, symbol)
          rescue
            KeyError ->
              reraise ArgumentError, "Unrecognized symbol: #{inspect(symbol)}"
          else
            amount ->
              acc = acc * radix + amount
              string_to_int_recur(remaining_string, symbol_to_amount, radix, acc)
          end

        nil ->
          acc
      end
    end

    defp int_to_padded_string_recur(int, amount_to_symbol, radix, acc) do
      remainder = rem(int, radix)
      symbol = elem(amount_to_symbol, remainder)
      acc = [symbol | acc]

      case div(int, radix) do
        0 ->
          List.to_string(acc)

        int ->
          int_to_padded_string_recur(int, amount_to_symbol, radix, acc)
      end
    end
  end

  defimpl FPE.FFX.Codec.Reversible, for: __MODULE__ do
    def reverse_string(_codec, vX), do: String.reverse(vX)
  end
end
