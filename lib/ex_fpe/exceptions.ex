# credo:disable-for-this-file Credo.Check.Readability.ModuleNames
defmodule ExFPE.Error do
  @moduledoc false
  # Turns the structured `{:error, reason}` tuples returned across `ExFPE` into
  # human-readable messages, shared by the `ExFPE` exceptions below.

  @spec humanize(term) :: String.t()
  def humanize(reason)

  ## Key

  def humanize({:key_not_a_binary, value}), do: "key must be a binary, got: #{inspect(value)}"

  def humanize({:key_has_invalid_size, size}),
    do: "key must be 16, 24, or 32 bytes long (for AES-128/192/256), got #{size} bytes"

  ## Mode / radix

  def humanize({:unknown_mode, mode}), do: "unknown mode #{inspect(mode)} (expected :ff1 or :ff3_1)"

  def humanize({:bad_radix, {radix, :less_than_minimum, min}}),
    do: "radix #{inspect(radix)} is below the minimum of #{min}"

  def humanize({:bad_radix, {radix, :more_than_maximum, max}}),
    do: "radix #{inspect(radix)} is above the maximum of #{max}"

  def humanize({:bad_radix, {radix, :need_alphabet_or_codec}}),
    do: "radix #{inspect(radix)} needs an alphabet or a codec to map symbols to numerals"

  def humanize({:bad_radix, {radix, :not_a_valid_radix}}), do: "radix must be an integer >= 2, got: #{inspect(radix)}"

  ## Alphabet (Custom codec) — the inner reasons come from `Codec.Custom.new/1`,
  ## wrapped in `:bad_alphabet` by `ExFPE.new/3` when an alphabet is passed.

  def humanize({:bad_alphabet, reason}), do: "invalid alphabet — #{humanize(reason)}"

  def humanize({:not_valid_utf8, value}), do: "not valid UTF-8: #{inspect(value)}"

  def humanize({:repeated_symbols, symbols}), do: "repeated symbols: #{inspect(symbols)}"

  def humanize({:invalid_codepoints, entries}) do
    details = Enum.map_join(entries, "; ", fn {symbol, reason} -> "#{inspect(symbol)}: #{humanize(reason)}" end)
    "invalid symbols — #{details}"
  end

  def humanize({:invalid_category, {:other, sub}}),
    do: "unassigned, control, format, surrogate, or private-use character (#{sub})"

  def humanize({:invalid_category, {:separator, sub}}), do: "whitespace or separator character (#{sub})"

  def humanize({:invalid_combining_class, class}), do: "combining character (canonical combining class #{class})"

  def humanize(:conjoining_hangul_jamo), do: "conjoining Hangul jamo"

  def humanize(:merges_with_adjacent_symbols), do: "merges with an adjacent symbol into one grapheme"

  ## Tweak

  def humanize({:invalid_tweak, {:too_large, size, max}}), do: "tweak is too large: #{size} bytes (maximum #{max})"

  def humanize({:invalid_tweak, {:invalid_bit_size, bits, expected}}),
    do: "tweak must be #{expected} bits long, got #{bits} bits"

  def humanize({:invalid_tweak, {:not_a_binary, value}}), do: "tweak must be a binary, got: #{inspect(value)}"

  def humanize({:invalid_tweak, {:not_a_bitstring, value}}), do: "tweak must be a bitstring, got: #{inspect(value)}"

  ## Input

  def humanize({:invalid_input, {:length_out_of_bounds, length, {min, max}}}),
    do: "input is #{length} symbols long, but must be between #{min} and #{max}"

  def humanize({:invalid_input, reason}), do: "invalid input: #{humanize(reason)}"

  def humanize({:not_a_numerical_string, value}), do: "not a numerical string: #{inspect(value)}"

  def humanize({:unknown_symbol, symbol}), do: "unknown symbol for this alphabet: #{inspect(symbol)}"

  def humanize({:bad_utf8, _codepoints, chardata}), do: "not valid UTF-8: #{inspect(chardata)}"

  def humanize({:negative_value, value}), do: "value must be non-negative, got: #{inspect(value)}"

  def humanize({:value_is_larger_than_declared_length}), do: "value does not fit in its declared length"

  ## Supervised context

  def humanize({:ctx_not_found_for_module, module}) do
    "ExFPE context for #{inspect(module)} was not found; is it started under your supervision tree?"
  end

  ## Fallback

  def humanize(reason), do: inspect(reason)
end

defmodule ExFPE.ArgumentError do
  @moduledoc """
  Raised by `ExFPE.new!/3` when a context cannot be built — an invalid key, mode,
  radix, alphabet, or codec.

  The structured `:reason` is the same term `ExFPE.new/3` would return under
  `{:error, reason}`.
  """
  defexception [:reason]

  @type t :: %__MODULE__{reason: term}

  @impl true
  def message(%__MODULE__{reason: reason}), do: "invalid ExFPE argument — " <> ExFPE.Error.humanize(reason)
end

defmodule ExFPE.InputError do
  @moduledoc """
  Raised by `ExFPE.encrypt!/3` and `ExFPE.decrypt!/3` when the tweak or the input
  numerical string is invalid.

  The structured `:reason` is the same term `ExFPE.encrypt/3` / `ExFPE.decrypt/3`
  would return under `{:error, reason}`.
  """
  defexception [:reason]

  @type t :: %__MODULE__{reason: term}

  @impl true
  def message(%__MODULE__{reason: reason}), do: "invalid ExFPE input — " <> ExFPE.Error.humanize(reason)
end

defmodule ExFPE.NotStartedError do
  @moduledoc """
  Raised by a `use ExFPE` module's generated functions when its context is not
  running — usually because it is missing from the supervision tree, or the
  application is stopped.
  """
  defexception [:reason]

  @type t :: %__MODULE__{reason: term}

  @impl true
  def message(%__MODULE__{reason: reason}), do: ExFPE.Error.humanize(reason)
end
