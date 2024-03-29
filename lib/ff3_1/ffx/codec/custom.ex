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

  @max_radix_we_will_validate_by_brute_force 500

  @enforce_keys [
    :symbol_to_amount,
    :amount_to_symbol
  ]
  defstruct [
    :symbol_to_amount,
    :amount_to_symbol
  ]

  @type numerical_string :: String.t()

  @opaque t :: %__MODULE__{
            symbol_to_amount: %{String.grapheme() => non_neg_integer},
            amount_to_symbol: tuple()
          }

  ## API

  @spec new(String.t()) :: {:ok, t()} | {:error, term}
  def new(alphabet) do
    ordered_graphemes = String.graphemes(alphabet)

    with :ok <- validate_uniqueness(ordered_graphemes),
         {:ok, maybe_canon_graphemes} <- validate_norm(ordered_graphemes),
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

  ## Internal

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

  defp validate_uniqueness(graphemes) do
    unique = Enum.uniq(graphemes)

    if length(unique) != length(graphemes) do
      repeated_symbols = graphemes -- unique
      {:error, {:alphabet_has_repeated_symbols, repeated_symbols}}
    else
      :ok
    end
  end

  defp validate_ambiguity(graphemes) do
    case potentially_problematic_graphemes(graphemes) do
      {:ok, potentially_problematic} ->
        validate_ambiguity(graphemes, potentially_problematic)

      {:error, _} = error ->
        error
    end
  end

  defp validate_ambiguity(graphemes, potentially_problematic) do
    potentially_problematic_set = MapSet.new(potentially_problematic)

    case Enum.find_value(
           potentially_problematic,
           &find_symbol_ambiguity(&1, potentially_problematic_set, graphemes)
         ) do
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

  defp potentially_problematic_graphemes(graphemes) do
    Enum.filter(
      graphemes,
      &(Kernel.apply(Unicode.GraphemeClusterBreak, :grapheme_break, [&1]) != [:other])
    )
  catch
    :error, :undef when length(graphemes) <= @max_radix_we_will_validate_by_brute_force ->
      false = Kernel.function_exported?(Unicode.GraphemeClusterBreak, :module_info, 0)
      {:ok, graphemes}

    :error, :undef ->
      # Brute-force comparison would take too long
      {:error, "You need the optional Unicode dep for such a large alphabet"}
  else
    potentially_problematic ->
      {:ok, potentially_problematic}
  end

  defp find_symbol_ambiguity(grapheme, potentially_problematic_set, [other | next]) do
    case find_reclustering(grapheme, potentially_problematic_set, other) do
      nil ->
        find_symbol_ambiguity(grapheme, potentially_problematic_set, next)

      ambiguity ->
        ambiguity
    end
  end

  defp find_symbol_ambiguity(_grapheme, _potentially_problematic_set, []), do: nil

  defp find_reclustering(grapheme, potentially_problematic_set, other) do
    if MapSet.member?(potentially_problematic_set, other) do
      # We'll do reverse comparison later
      case String.graphemes(grapheme <> other) do
        [^grapheme, ^other] ->
          nil

        reclustered ->
          {grapheme, other, reclustered}
      end
    else
      case {
        String.graphemes(grapheme <> other),
        String.graphemes(other <> grapheme)
      } do
        {[^grapheme, ^other], [^other, ^grapheme]} ->
          nil

        {[^grapheme, ^other], reclustered} ->
          {other, grapheme, reclustered}

        {reclustered, _} ->
          {grapheme, other, reclustered}
      end
    end
  end

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

    def numerical_string_length(_codec, string) when is_binary(string) do
      {:ok, String.length(string)}
    end

    def numerical_string_length(_codec, string) do
      {:error, {:not_a_numerical_string, string}}
    end

    def split_numerical_string_at(_codec, string, n), do: String.split_at(string, n)

    def numerical_string_to_int(codec, string) do
      case Custom.normalize_string(string) do
        {:ok, canon_string} ->
          symbol_to_amount = codec.symbol_to_amount
          radix = map_size(symbol_to_amount)
          string_to_int_recur(canon_string, symbol_to_amount, radix, _acc0 = 0)

        {:error, reason} ->
          {:error, {:invalid_encoding, reason}}
      end
    end

    def concat_numerical_strings(_codec, left, right), do: left <> right

    def int_to_padded_numerical_string(codec, int, pad_count) when is_integer(int) and int >= 0 do
      amount_to_symbol = codec.amount_to_symbol
      radix = tuple_size(amount_to_symbol)
      zero_symbol = elem(amount_to_symbol, 0)

      int
      |> int_to_padded_string_recur(amount_to_symbol, radix, _acc0 = [])
      |> String.pad_leading(pad_count, zero_symbol)
    end

    ## Internal

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
