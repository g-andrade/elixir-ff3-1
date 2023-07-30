defmodule FPE.FFX.Codec.Custom do
  @moduledoc false

  alias FPE.FFX.Codec

  @enforce_keys [
    :symbol_to_amount,
    :amount_to_symbol,
    :input_opts
  ]
  defstruct [
    :symbol_to_amount,
    :amount_to_symbol,
    :input_opts
  ]

  @opaque t :: %__MODULE__{
            symbol_to_amount: %{String.grapheme() => non_neg_integer},
            amount_to_symbol: tuple(),
            input_opts: Codec.InputOpts.t()
          }

  @spec new([String.grapheme(), ...], Codec.InputOpts.t()) :: {:ok, t()} | {:error, term}
  def new(ordered_graphemes, input_opts) do
    with {:ok, maybe_canon_graphemes} <- maybe_validate_case(ordered_graphemes, input_opts),
         {:ok, maybe_canon_graphemes} <- maybe_validate_norm(maybe_canon_graphemes, input_opts) do
      {:ok,
       %__MODULE__{
         symbol_to_amount: maybe_canon_graphemes |> Enum.with_index() |> Map.new(),
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
      maybe_canon = prepare_input_for_case!(codec, string)
      maybe_canon = prepare_input_for_norm!(codec, maybe_canon)

      case check_input_string_symbols(codec, maybe_canon) do
        :ok ->
          {:ok, maybe_canon}
        {:error, _} = error ->
          error
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

    ## Private

    defp prepare_input_for_case!(codec, string) do
      case codec.input_opts.case_insensitive do
        true -> String.downcase(string)
        false -> string
      end
    end

    defp prepare_input_for_norm!(codec, string) do
      case codec.input_opts.norm_insensitive do
        true -> Custom.normalize_string!(string)
        false -> string
      end
    end

    defp check_input_string_symbols(codec, string) do
      case String.graphemes(string)
           |> Enum.find(&(not is_map_key(codec.symbol_to_amount, &1))) do
        nil ->
          :ok

        unknown_symbol ->
          {:error, {:unknown_symbol, unknown_symbol}}
      end
    end

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
  end
end
