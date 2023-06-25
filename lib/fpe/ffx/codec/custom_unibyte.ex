defmodule FPE.FFX.Codec.CustomUnibyte do
  @moduledoc false
  @derive [FPE.FFX.Reversible]

  @enforce_keys [:symbol_to_amount, :amount_to_symbol]
  defstruct [:symbol_to_amount, :amount_to_symbol]

  @type t :: %__MODULE__{
          symbol_to_amount: %{byte => non_neg_integer},
          amount_to_symbol: tuple()
        }

  @spec new([String.grapheme(), ...]) :: t
  def new(ordered_graphemes) do
    ordered_bytes = ordered_graphemes |> Enum.map(fn <<byte>> -> byte end)

    %__MODULE__{
      symbol_to_amount: ordered_bytes |> Enum.with_index() |> Map.new(),
      amount_to_symbol: ordered_bytes |> List.to_tuple()
    }
  end

  defimpl FPE.FFX.Codec, for: __MODULE__ do
    def num_radix(codec, string) when byte_size(string) > 0 do
      symbol_to_amount = codec.symbol_to_amount
      radix = map_size(symbol_to_amount)
      num_radix_recur(string, symbol_to_amount, radix, _acc0 = 0)
    end

    def str_m_radix(codec, m, int) when is_integer(int) and int >= 0 do
      amount_to_symbol = codec.amount_to_symbol
      radix = tuple_size(amount_to_symbol)
      zero_symbol = elem(amount_to_symbol, 0)

      str_m_radix_recur(int, amount_to_symbol, radix, _acc0 = [])
      |> String.pad_leading(m, <<zero_symbol>>)
    end

    defp num_radix_recur(<<symbol, remaining_string::bytes>>, symbol_to_amount, radix, acc) do
      try do
        Map.fetch!(symbol_to_amount, symbol)
      rescue
        KeyError ->
          raise ArgumentError, "Unrecognized symbol: #{inspect(<<symbol>>)}"
      else
        amount ->
          acc = acc * radix + amount
          num_radix_recur(remaining_string, symbol_to_amount, radix, acc)
      end
    end

    defp num_radix_recur(<<>>, _symbol_to_amount, _radix, acc), do: acc

    defp str_m_radix_recur(int, amount_to_symbol, radix, acc) do
      remainder = rem(int, radix)
      symbol = elem(amount_to_symbol, remainder)
      acc = [symbol | acc]

      case div(int, radix) do
        0 ->
          :erlang.list_to_binary(acc)

        int ->
          str_m_radix_recur(int, amount_to_symbol, radix, acc)
      end
    end
  end
end
