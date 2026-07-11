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

  @unicode_combining_class_not_reordered 0

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
            symbol_to_amount: %{char() => non_neg_integer},
            amount_to_symbol: tuple()
          }

  ## API

  @spec new(String.t()) :: {:ok, t()} | {:error, term}
  def new(alphabet) do
    with :ok <- validate_string(alphabet),
         codepoints = String.to_charlist(alphabet),
         :ok <- validate_codepoints(codepoints),
         :ok <- validate_uniqueness(codepoints) do
      {:ok,
       %__MODULE__{
         symbol_to_amount: codepoints |> Enum.with_index() |> Map.new(),
         amount_to_symbol: List.to_tuple(codepoints)
       }}
    else
      {:error, _} = error ->
        error
    end
  end

  ## Internal

  @doc false
  def normalize_string(string) do
    case :unicode.characters_to_nfc_binary(string) do
      <<normalized::bytes>> ->
        {:ok, normalized}

      {:error, string, rest} ->
        {:error, {string, rest}}
    end
  end

  defp validate_string(alphabet) do
    if String.valid?(alphabet) do
      :ok
    else
      {:error, {:alphabet_not_valid_utf8, alphabet}}
    end
  end

  defp validate_codepoints(ordered_codepoints) do
    case :lists.filtermap(&filtermap_codepoint_rejection/1, ordered_codepoints) do
      [] ->
        :ok

      invalid_entries ->
        {:error, {:invalid_codepoints, invalid_entries}}
    end
  end

  # `:unicode.category/1` type (OTP 29):
  #
  #          {letter, uppercase | lowercase | titlecase | modifier | other} |
  #          {mark, non_spacing | spacing_combining | enclosing} |
  #          {number, decimal | letter | other} |
  #          {separator, space | line | paragraph} |
  #          {other, control | format | surrogate | private | not_assigned} |
  #          {punctuation, connector | dash | open | close | initial | final | other} |
  #          {symbol, math | currency | modifier | other}.
  #

  defp filtermap_codepoint_rejection(codepoint) do
    reason = codepoint_rejection_reason(codepoint)

    if reason === nil do
      false
    else
      codepoint_string = <<codepoint::utf8>>
      {true, {codepoint_string, reason}}
    end
  end

  defp codepoint_rejection_reason(codepoint) do
    # - 3a. No invisible/undefined category. Reject if Unicode.category(cp) is
    # in {:Cn, :Cc, :Cf, :Cs, :Co} — unassigned, control, format (this is what
    # kills ZWJ/ZWNJ/BOM/bidi controls), surrogate, private-use. This subsumes
    # the "assigned?" check we discussed and closes the ZWJ hole from your old
    # reclustering test.

    # - 3b. Starter only (combining class 0). Reject if combining_class(cp) !=
    # 0. A trailing combining mark would otherwise compose leftward onto the
    # previous symbol under NFC and break the round-trip — the scalar-level
    # version of reclustering.

    # - 3c. Not a conjoining Hangul jamo. Reject if Hangul_Syllable_Type(cp) ∈
    # {L, V, T}. These are the only ccc-0 characters that canonically compose
    # starter-onto-starter (V onto L, T onto LV). Precomposed syllables (LV,
    # LVT) stay allowed and are safe once the jamo are gone.

    # - 3d. NFC-stable in isolation. Reject if
    # :unicode.characters_to_nfc_binary(<<cp::utf8>>) != <<cp::utf8>>.

    %{
      category: {principal_category, _} = category,
      ccc: combining_class
    } = :unicode_util.lookup(codepoint)

    cond do
      principal_category === :other ->
        {:invalid_category, category}

      combining_class !== @unicode_combining_class_not_reordered ->
        {:invalid_combining_class, combining_class}

      conjoining_jamo?(codepoint) ->
        :conjoining_hangul_jamo

      :unicode.characters_to_nfc_list([codepoint]) !== [codepoint] ->
        :not_in_nfc_norm

      true ->
        nil
    end
  end

  # Conjoining Hangul jamo (Hangul_Syllable_Type L/V/T) compose
  # starter-onto-starter under NFC (L+V→LV, LV+T→LVT), so a pair of
  # them as separate symbols would merge and break round-tripping.
  # These blocks are frozen by the Unicode stability policy.
  defp conjoining_jamo?(cp) do
    # Hangul Jamo            (L, V, T)
    # Hangul Jamo Extended-A (L)
    # Hangul Jamo Extended-B (V, T)
    cp in 0x1100..0x11FF or
      cp in 0xA960..0xA97F or
      cp in 0xD7B0..0xD7FF
  end

  defp validate_uniqueness(ordered_codepoints) do
    unique = Enum.uniq(ordered_codepoints)

    if length(unique) === length(ordered_codepoints) do
      :ok
    else
      repeated_symbols = ordered_codepoints -- unique
      repeated_symbol_strings = Enum.map(repeated_symbols, &(<<&1::utf8>>))
      {:error, {:alphabet_has_repeated_symbols, repeated_symbol_strings}}
    end
  end

  defimpl Codec, for: __MODULE__ do
    @moduledoc false

    ## API

    def radix(codec), do: tuple_size(codec.amount_to_symbol)

    def numerical_string_length(_codec, string) when is_binary(string) do
      {:ok, String.length(string)}
    end

    def numerical_string_length(_codec, string) do
      {:error, {:not_a_numerical_string, string}}
    end

    def split_numerical_string_at(_codec, string, n) do
      tail_size = string_split_codepoints_tail_size(string, n)
      prefix_size = byte_size(string) - tail_size
      <<prefix::bytes-size(^prefix_size), tail::bytes>> = string
      {prefix, tail}
    end

    def numerical_string_to_int(codec, string) do
      case :unicode.characters_to_nfc_list(string) do
        codepoints when is_list(codepoints) ->
          symbol_to_amount = codec.symbol_to_amount
          radix = map_size(symbol_to_amount)
          string_to_int_recur(codepoints, symbol_to_amount, radix, _acc0 = 0)

        {:error, codepoints, rest} ->
          {:error, {:invalid_encoding, {codepoints, rest}}}
      end
    end

    def concat_numerical_strings(_codec, left, right), do: left <> right

    def int_to_padded_numerical_string(codec, int, pad_count) when is_integer(int) and int >= 0 do
      amount_to_symbol = codec.amount_to_symbol
      radix = tuple_size(amount_to_symbol)
      zero_symbol = elem(amount_to_symbol, 0)

      int
      |> int_to_charlist_recur(amount_to_symbol, radix, _acc0 = [])
      |> charlist_pad_leading(pad_count, zero_symbol)
      |> List.to_string()
    end

    ## Internal

    defp string_split_codepoints_tail_size(<<_::utf8, next::bytes>>, n) when n > 0 do
      string_split_codepoints_tail_size(next, n - 1)
    end

    defp string_split_codepoints_tail_size(<<tail::bytes>>, 0) do
      byte_size(tail)
    end

    defp string_to_int_recur([codepoint | next], symbol_to_amount, radix, acc) do
      Map.fetch!(symbol_to_amount, codepoint)
    rescue
      KeyError ->
        {:error, {:unknown_symbol, <<codepoint::utf8>>}}
    else
      amount ->
        acc = acc * radix + amount
        string_to_int_recur(next, symbol_to_amount, radix, acc)
    end

    defp string_to_int_recur([], _symbol_to_amount, _radix, acc) do
      {:ok, acc}
    end

    defp int_to_charlist_recur(int, amount_to_symbol, radix, acc) do
      remainder = rem(int, radix)
      symbol = elem(amount_to_symbol, remainder)
      acc = [symbol | acc]

      case div(int, radix) do
        0 ->
          acc

        int ->
          int_to_charlist_recur(int, amount_to_symbol, radix, acc)
      end
    end

    defp charlist_pad_leading(charlist, pad_count, zero_symbol) do
      pad_size = pad_count - length(charlist)
      charlist_pad_leading_recur(charlist, pad_size, zero_symbol)
    end

    defp charlist_pad_leading_recur(charlist, pad_size, zero_symbol) when pad_size > 0 do
      [zero_symbol | charlist_pad_leading_recur(charlist, pad_size - 1, zero_symbol)]
    end

    defp charlist_pad_leading_recur(charlist, 0, _zero_symbol) do
      charlist
    end
  end
end
