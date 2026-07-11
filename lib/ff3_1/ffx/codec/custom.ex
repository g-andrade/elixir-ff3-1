# credo:disable-for-this-file Credo.Check.Readability.ModuleNames
defmodule FF3_1.FFX.Codec.Custom do
  @moduledoc """
  An implementation of `FF3_1.FFX.Codec` that handles alphabets other than the
  ones supported by `FF3_1.FFX.Codec.Builtin`.

  Each symbol is a single Unicode scalar (codepoint) that is guaranteed to
  stand on its own as one visual unit — a [grapheme
  cluster](https://hexdocs.pm/elixir/1.20/String.html#module-grapheme-clusters).
  Alphabets are restricted at construction so this holds: codepoints that are
  unassigned, control/format/surrogate/private-use, combining marks, conjoining
  Hangul jamo, not in NFC form, or that would merge with an adjacent symbol
  (emoji modifiers, regional indicators, prepending marks, ...) are rejected.

  This buys two guarantees of different strength:

  * **Round-tripping** is ensured for any accepted alphabet, forever. Input is
    tokenized by codepoint and matched after NFC normalization, and NFC is
    frozen for assigned characters by the Unicode stability policy — so
    ciphertext stays decryptable across Unicode/OTP upgrades.
  * **Visual-unit preservation** (visual units out = visual units in) holds
    under any given Unicode version, because every symbol occupies exactly one
    grapheme cluster. Unlike normalization, grapheme segmentation has no formal
    stability policy; a future Unicode version could in principle re-segment an
    exotic symbol. If that ever happened the data would still decrypt (the
    round-trip guarantee is independent of segmentation) — only the visual
    count could drift. Restrict to ASCII for a formally frozen visual guarantee.

  It's **case sensitive** (unlike `FF3_1.FFX.Codec.Builtin`), but [norm
  insensitive](https://hexdocs.pm/elixir/1.20/String.html#normalize/2). This is
  because:
  * There are
  [multiple](https://hexdocs.pm/elixir/1.20/String.html#downcase/2),
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

  # Representative neighbors covering every grapheme-cluster-joining vector:
  # a plain base (Extend/SpacingMark), a pictographic (emoji modifier/ZWJ/VS16),
  # and a regional indicator (flag pairing). Prepend/Hangul-L are caught by the
  # reverse-order probe in `standalone_grapheme?/1`.
  @grapheme_probe_neighbors [?a, 0x1F64C, 0x1F1E6]

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

    # - 3e. Stands alone as a grapheme cluster. Reject if the codepoint would
    # merge with an adjacent symbol under Unicode segmentation (emoji modifiers,
    # regional indicators, prepending marks, ...). This is what guarantees
    # "visual units out = visual units in". It subsumes 3b (combining marks
    # always merge with a preceding base), but 3b is kept as a cheaper, more
    # specific pre-filter, and 3c is still needed because the probe neighbors
    # don't include a Hangul V/T.

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

      not standalone_grapheme?(codepoint) ->
        :merges_with_adjacent_symbols

      true ->
        nil
    end
  end

  # A symbol stands alone iff it never merges with a representative neighbor on
  # either side. Since every *other* accepted symbol is itself standalone, a
  # merge can only occur if this codepoint is a joiner — so probing a fixed set
  # of neighbors is sufficient to rule out merging against any accepted symbol.
  defp standalone_grapheme?(codepoint) do
    Enum.all?(@grapheme_probe_neighbors, fn neighbor ->
      not grapheme_merges?(neighbor, codepoint) and
        not grapheme_merges?(codepoint, neighbor)
    end)
  end

  # `:unicode_util.gc/1` returns `[grapheme_cluster | rest]`; a cluster spanning
  # more than one codepoint comes back as a list head, a lone codepoint as an
  # integer head. A list head therefore means the two codepoints merged.
  defp grapheme_merges?(left, right) do
    case :unicode_util.gc([left, right]) do
      [first | _] when is_list(first) ->
        true

      _ ->
        false
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
      repeated_symbol_strings = Enum.map(repeated_symbols, &<<&1::utf8>>)
      {:error, {:alphabet_has_repeated_symbols, repeated_symbol_strings}}
    end
  end

  defimpl Codec, for: __MODULE__ do
    @moduledoc false

    ## API

    def radix(codec), do: tuple_size(codec.amount_to_symbol)

    def normalize_input(_codec, string) when is_binary(string) do
      case :unicode.characters_to_nfc_list(string) do
        normalized when is_list(normalized) ->
          len = length(normalized)
          {:ok, len, normalized}

        {:error, codepoints, chardata} ->
          {:error, {:bad_utf8, codepoints, chardata}}
      end
    end

    def normalize_input(_codec, string) do
      {:error, {:not_a_numerical_string, string}}
    end

    def split_numerical_string_at(_codec, codepoints, n) do
      :lists.split(n, codepoints)
    end

    def numerical_string_to_int(codec, codepoints) do
      symbol_to_amount = codec.symbol_to_amount
      radix = map_size(symbol_to_amount)
      string_to_int_recur(codepoints, symbol_to_amount, radix, _acc0 = 0)
    end

    def concat_numerical_strings(_codec, left, right), do: :unicode.characters_to_binary([left, right])

    def int_to_padded_numerical_string(codec, int, pad_count) when is_integer(int) and int >= 0 do
      amount_to_symbol = codec.amount_to_symbol
      radix = tuple_size(amount_to_symbol)
      zero_symbol = elem(amount_to_symbol, 0)

      int
      |> int_to_charlist_recur(amount_to_symbol, radix, _acc0 = [])
      |> charlist_pad_leading(pad_count, zero_symbol)
    end

    ## Internal

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
