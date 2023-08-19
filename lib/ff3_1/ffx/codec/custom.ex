# credo:disable-for-this-file Credo.Check.Readability.ModuleNames
defmodule FF3_1.FFX.Codec.Custom do
  @moduledoc """
  An implementation of `FF3_1.FFX.Codec` that handles alphabets other than the
  ones supported by `FF3_1.FFX.Codec.Builtin`.

  Each [grapheme
  cluster](https://hexdocs.pm/elixir/1.15/String.html#module-grapheme-clusters)
  represents a visual symbol.

  It's **case sensitive** (unlike `FF3_1.FFX.Codec.Builtin`), but [norm
  insensitive](https://hexdocs.pm/elixir/1.15/String.html#normalize/2). This is
  because:
  * There are
  [multiple](https://hexdocs.pm/elixir/1.15/String.html#downcase/2),
  [ways](https://www.erlang.org/doc/man/string#casefold-1) of making a string
  case agnostic;
  * Case sensitivity makes sense in some cases (think base64) but not in
  others;
  * What if an alphabet has multiple casings of the same symbol but single
  casings of others? Things can get real weird, real fast.

  At the same time, it's hard to imagine different Unicode norms of the same
  symbol within the same alphabet ever being a real use case.

  If you wish to handle case agnostically, you'll need to pick what best fits
  your use case, and handle it before invoking `FF3_1` encryption and
  decryption functions.
  """

  alias FF3_1.FFX.Codec

  # require Logger

  @enforce_keys [
    :symbol_to_amount,
    :amount_to_symbol
  ]
  defstruct [
    :symbol_to_amount,
    :amount_to_symbol
  ]

  @opaque t :: %__MODULE__{
            symbol_to_amount: %{String.grapheme() => non_neg_integer},
            amount_to_symbol: tuple()
          }

  @spec new([String.grapheme(), ...]) :: {:ok, t()} | {:error, term}
  @doc false
  def new(ordered_graphemes) do
    with {:ok, maybe_canon_graphemes} <- validate_norm(ordered_graphemes),
         :ok <- validate_ambiguity(maybe_canon_graphemes) do
      {:ok,
       %__MODULE__{
         symbol_to_amount: maybe_canon_graphemes |> Enum.with_index() |> Map.new(),
         amount_to_symbol: List.to_tuple(ordered_graphemes)
       }}
    else
      {:error, _} = error ->
        error
    end
  end

  @doc false
  def normalize_string!(string) do
    {:ok, normalized} = normalize_string(string)
    normalized
  end

  defp validate_norm(graphemes) do
    case validate_canonicalization(graphemes, &normalize_string!/1) do
      {:ok, _} = success ->
        success

      {:error, ambiguous_symbols} ->
        {:error, {:alphabet_has_ambiguous_symbols, ambiguous_symbols}}
    end
  end

  defp validate_canonicalization(graphemes, canonize_fun) do
    canonized = Enum.map(graphemes, canonize_fun)
    canonized_len = length(canonized)
    uniq = Enum.uniq(canonized)
    uniq_len = length(uniq)

    if uniq_len != canonized_len do
      ambiguous = canonized -- uniq
      {:error, ambiguous}
    else
      {:ok, canonized}
    end
  end

  defp validate_ambiguity(graphemes) do
    problematic =
      Enum.filter(
        graphemes,
        &(Unicode.GraphemeClusterBreak.grapheme_break(&1) != [:other])
      )

    case Enum.find_value(problematic, &find_symbol_ambiguity(&1, graphemes)) do
      nil ->
        :ok

      {first, second, reclustered} ->
        {:error,
         {:alphabet_has_symbols_reclustering_when_next_to_each_other,
          [
            first: first,
            second: second,
            reclustered_into: reclustered
          ]}}
    end
  end

  defp find_symbol_ambiguity(grapheme, [other | next]) do
    case {
      String.graphemes(grapheme <> other),
      String.graphemes(other <> grapheme)
    } do
      {[^grapheme, ^other], [^other, grapheme]} ->
        find_symbol_ambiguity(grapheme, next)

      {[^grapheme, ^other], reclustered} ->
        {other, grapheme, reclustered}

      {reclustered, _} ->
        {grapheme, other, reclustered}
    end
  end

  defp find_symbol_ambiguity(_grapheme, []), do: nil

  @doc false
  def normalize_string(string) do
    case :unicode.characters_to_nfc_binary(string) do
      <<normalized::bytes>> ->
        {:ok, normalized}

      {:error, string, rest} ->
        {:error, {string, rest}}
    end
  end

  defimpl Codec, for: __MODULE__ do
    @moduledoc false
    alias FF3_1.FFX.Codec.Custom

    ## API

    def radix(codec), do: tuple_size(codec.amount_to_symbol)

    def string_to_int(codec, string) when byte_size(string) !== 0 do
      case Custom.normalize_string(string) do
        {:ok, canon_string} ->
          symbol_to_amount = codec.symbol_to_amount
          radix = map_size(symbol_to_amount)
          string_to_int_recur(canon_string, symbol_to_amount, radix, _acc0 = 0)

        {:error, reason} ->
          {:error, {:invalid_encoding, reason}}
      end
    end

    def int_to_padded_string(codec, int, pad_count) when is_integer(int) and int >= 0 do
      amount_to_symbol = codec.amount_to_symbol
      radix = tuple_size(amount_to_symbol)
      zero_symbol = elem(amount_to_symbol, 0)

      int
      |> int_to_padded_string_recur(amount_to_symbol, radix, _acc0 = [])
      |> String.pad_leading(pad_count, zero_symbol)
    end

    defp string_to_int_recur(string, symbol_to_amount, radix, acc) do
      case String.next_grapheme(string) do
        {symbol, remaining_string} ->
          string_to_int_step(symbol, remaining_string, symbol_to_amount, radix, acc)

        nil ->
          {:ok, acc}
      end
    end

    defp string_to_int_step(symbol, remaining_string, symbol_to_amount, radix, acc) do
      Map.fetch!(symbol_to_amount, symbol)
    rescue
      KeyError ->
        {:error, {:unknown_symbol, symbol}}
    else
      amount ->
        acc = acc * radix + amount
        string_to_int_recur(remaining_string, symbol_to_amount, radix, acc)
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
