defprotocol FPE.FFX.CustomCodec do
  @moduledoc false

  @spec to_integer(t, String.t) :: non_neg_integer
  def to_integer(codec, string)

  @spec to_string(t, non_neg_integer) :: String.t
  def to_string(codec, int)
end

defmodule FPE.FFX.MultibyteCodec do
  @moduledoc false

  @enforce_keys [:symbol_to_amount, :amount_to_symbol]
  defstruct [:symbol_to_amount, :amount_to_symbol]

  @type t :: %__MODULE__{
    symbol_to_amount: %{String.grapheme => non_neg_integer},
    amount_to_symbol: tuple()
  }

  @spec new([String.grapheme, ...]) :: t
  def new(ordered_graphemes) do
    %__MODULE__{
      symbol_to_amount: ordered_graphemes |> Enum.with_index |> Map.new,
      amount_to_symbol: ordered_graphemes |> List.to_tuple
    }
  end

  defimpl FPE.FFX.CustomCodec, for: FPE.FFX.MultibyteCodec do
    alias FPE.FFX.MultibyteCodec

    @spec to_integer(MultibyteCodec.t, String.t) :: non_neg_integer
    def to_integer(codec, string) when byte_size(string) > 0 do
      symbol_to_amount = codec.symbol_to_amount
      radix = map_size(symbol_to_amount)
      to_integer_recur(string, symbol_to_amount, radix, _acc0 = 0)
    end

    @spec to_string(MultibyteCodec.t, non_neg_integer) :: String.t
    def to_string(codec, int) when is_integer(int) and int >= 0 do
      amount_to_symbol = codec.amount_to_symbol
      radix = tuple_size(amount_to_symbol)
      to_string_recur(int, amount_to_symbol, radix, _acc0 = [])
    end

    defp to_integer_recur(string, symbol_to_amount, radix, acc) do
      case String.next_grapheme(string) do
        {symbol, remaining_string} ->
          try do
            Map.fetch!(symbol_to_amount, symbol)
          rescue
            KeyError ->
              raise ArgumentError, "Unrecognized symbol: #{inspect symbol}"
          else
            amount ->
              acc = (acc * radix) + amount
              to_integer_recur(remaining_string, symbol_to_amount, radix, acc)
          end
        nil ->
          acc
      end
    end

    defp to_string_recur(int, amount_to_symbol, radix, acc) do
      remainder = rem(int, radix)
      symbol = elem(amount_to_symbol, remainder)
      acc = [symbol | acc]

      case div(int, radix) do
        0 ->
          List.to_string(acc)
        int ->
          to_string_recur(int, amount_to_symbol, radix, acc)
      end
    end
  end
end
