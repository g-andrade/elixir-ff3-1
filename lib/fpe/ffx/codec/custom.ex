defmodule FPE.FFX.Codec.Custom do
  @moduledoc false

  alias FPE.FFX.Codec

  @enforce_keys [
    :canonized_symbols,
    :symbol_to_amount,
    :amount_to_symbol,
    :input_opts
  ]
  defstruct [
    :canonized_symbols,
    :symbol_to_amount,
    :amount_to_symbol,
    :input_opts
  ]

  @opaque t :: %__MODULE__{
            canonized_symbols: %{String.grapheme() => String.grapheme()},
            symbol_to_amount: %{String.grapheme() => non_neg_integer},
            amount_to_symbol: tuple(),
            input_opts: Codec.InputOpts.t()
          }

  @spec new([String.grapheme(), ...], Codec.InputOpts.t()) :: {:ok, t()} | {:error, term}
  def new(ordered_graphemes, input_opts) do
    with {:ok, canon_graphemes} <- maybe_validate_case(ordered_graphemes, input_opts),
         {:ok, canon_graphemes} <- maybe_validate_norm(canon_graphemes, input_opts) do
      {:ok,
       %__MODULE__{
         canonized_symbols:
           Map.new(
             Enum.zip(canon_graphemes, ordered_graphemes)
             |> Enum.filter(fn {canon, original} -> canon != original end)
           ),
         symbol_to_amount: ordered_graphemes |> Enum.with_index() |> Map.new(),
         amount_to_symbol: ordered_graphemes |> List.to_tuple(),
         input_opts: input_opts
       }}
    else
      {:error, _} = error ->
        error
    end
  end

  def normalize_string!(string) do
    {:ok, normalized} = normalize_string(string)
    normalized
  end

  defp maybe_validate_case(graphemes, input_opts) when input_opts.case_insensitive do
    case validate_insensitiveness(graphemes, &:string.casefold/1) do
      {:ok, _} = success ->
        success

      {:error, ambiguous_symbols} ->
        {:error, {:case_insensitive_alphabet_has_ambiguous_symbols, ambiguous_symbols}}
    end
  end

  defp maybe_validate_case(graphemes, _input_opts) do
    {:ok, graphemes}
  end

  defp maybe_validate_norm(graphemes, input_opts) when input_opts.norm_insensitive do
    case validate_insensitiveness(graphemes, &normalize_string!/1) do
      {:ok, _} = success ->
        success

      {:error, ambiguous_symbols} ->
        {:error, {:norm_insensitive_alphabet_has_ambiguous_symbols, ambiguous_symbols}}
    end
  end

  defp maybe_validate_norm(graphemes, _input_opts) do
    {:ok, graphemes}
  end

  defp validate_insensitiveness(graphemes, desensitize_fun) do
    desensitized = graphemes |> Enum.map(desensitize_fun)
    desensitized_len = length(desensitized)
    uniq = Enum.uniq(desensitized)
    uniq_len = length(uniq)

    case uniq_len != desensitized_len do
      true ->
        ambiguous = desensitized -- uniq
        {:error, ambiguous}

      false ->
        {:ok, desensitized}
    end
  end

  defp normalize_string(string) do
    case :unicode.characters_to_nfkc_binary(string) do
      <<normalized::bytes>> ->
        {:ok, normalized}

      {:error, string, rest} ->
        {:error, {string, rest}}
    end
  end

  defimpl Codec, for: __MODULE__ do
    alias FPE.FFX.Codec.Custom

    ## API

    def prepare_input_string(codec, string) do
      case codec.canonized_symbols do
        empty when map_size(empty) == 0 ->
          string

        canonized_symbols ->
          prepare_input_string_recur(string, canonized_symbols, codec.input_opts)
      end
    end

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

    def output_string(_codec, string) do
      string
    end

    ## Private

    defp string_to_int_recur(string, symbol_to_amount, radix, acc) do
      case String.next_grapheme(string) do
        {symbol, remaining_string} ->
          try do
            Map.fetch!(symbol_to_amount, symbol)
          rescue
            KeyError ->
              # credo:disable-for-next-line Credo.Check.Warning.RaiseInsideRescue
              raise ArgumentError, "Unrecognized symbol: #{inspect(symbol)}"
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

    defp prepare_input_string_recur(string, canonized_symbols, input_opts) do
      case String.next_grapheme(string) do
        {symbol, remaining_string} ->
          canon_symbol = canon_symbol(symbol, input_opts)
          mapped_symbol = Map.get(canonized_symbols, canon_symbol, symbol)

          <<
            mapped_symbol::bytes,
            prepare_input_string_recur(remaining_string, canonized_symbols, input_opts)::bytes
          >>

        nil ->
          <<>>
      end
    end

    defp canon_symbol(symbol, input_opts) do
      symbol =
        case input_opts.case_insensitive do
          true -> :string.casefold(symbol)
          false -> symbol
        end

      case input_opts.norm_insensitive do
        true -> Custom.normalize_string!(symbol)
        false -> symbol
      end
    end
  end

  defimpl FPE.FFX.Codec.Reversible, for: __MODULE__ do
    def reverse_string(_codec, vX), do: String.reverse(vX)
  end
end
