# credo:disable-for-this-file Credo.Check.Readability.ModuleNames
defmodule ExFPE.Codec.NoSymbols do
  @moduledoc """
  An implementation of `ExFPE.Codec` that skips the symbol alphabet entirely:
  you hand it integers and it hands integers back, leaving the mapping between
  those integers and whatever symbols they stand for up to you.

  Other codecs (`ExFPE.Codec.Builtin`, `ExFPE.Codec.Custom`) exist to translate
  a *string* of symbols into the integer FFX actually permutes, and back.
  `NoSymbols` is for when you'd rather own that translation — because your
  symbols aren't a single Unicode scalar each (so `Custom` can't accept them),
  because the value already lives as an integer in your system, or because you
  want to avoid string encoding on a hot path.

  Because there's no alphabet, the radix isn't tied to any set of symbols. This
  codec accepts any radix `>= 2`; the usable ceiling is set by the FFX mode, not
  by this codec (FF1 allows up to 65536 — see `ExFPE.FF1` and `ExFPE.FF3_1`).

  ## Numerical strings are `Numeral` structs

  Inputs and outputs are `#{inspect(__MODULE__)}.Numeral` structs rather than
  binaries. A plain integer isn't enough, because **length is significant** in
  FPE (a leading zero is a real symbol): the value `1234567` could be a 7-symbol
  string or a 10-symbol one padded with leading zeroes, and those encrypt
  differently. So each numerical string pairs a non-negative `value` with the
  `length` (symbol count) it's meant to occupy:

      %ExFPE.Codec.NoSymbols.Numeral{value: 1234567, length: 10}

  The value is interpreted as `length` digits in the codec's radix, most
  significant first. It must fit — that is, `0 <= value < radix ** length` —
  otherwise `normalize_input/2` returns `{:error, {:negative_value, value}}` or
  `{:error, {:value_is_larger_than_declared_length}}`. Encryption preserves the
  `length`, so a ciphertext `Numeral` always carries the same `length` as its
  plaintext.

  ## Example

      iex> alias ExFPE.Codec.NoSymbols
      iex> key = :crypto.strong_rand_bytes(32)
      iex> codec = NoSymbols.new!(_radix = 10)
      iex> ctx = ExFPE.new!(key, codec)
      iex> tweak = <<0::56>>
      iex> plaintext = %NoSymbols.Numeral{value: 1234567, length: 10}
      iex> ciphertext = ExFPE.encrypt!(ctx, tweak, plaintext)
      iex> %NoSymbols.Numeral{length: 10} = ciphertext
      iex> ^plaintext = ExFPE.decrypt!(ctx, tweak, ciphertext)
      %NoSymbols.Numeral{value: 1234567, length: 10}

  See the `ExFPE` guide's "No alphabet" section for more examples across radixes.
  """

  alias ExFPE.Codec
  alias ExFPE.FFX

  ## Types

  @enforce_keys [:radix]
  defstruct [:radix]

  @opaque t :: %__MODULE__{radix: radix}
  @type radix :: FFX.radix()

  defmodule Numeral do
    @moduledoc """
    A numerical string for `ExFPE.Codec.NoSymbols`, encoded as an integer
    `value` interpreted as `length` symbols (most significant first) in the
    codec's radix.

    `length` is carried explicitly because it can't be recovered from `value`
    alone: FPE treats leading zeroes as real symbols, so `value: 42, length: 2`
    ("42") and `value: 42, length: 5` ("00042") are different numerical strings.

    Valid values satisfy `0 <= value < radix ** length`.
    """
    @enforce_keys [:value, :length]
    defstruct [:value, :length]

    @type t :: %__MODULE__{value: non_neg_integer, length: pos_integer}
  end

  @type numerical_string :: Numeral.t()

  @spec new!(term) :: t()
  def new!(radix) do
    case new(radix) do
      {:ok, codec} -> codec
      {:error, reason} -> raise ExFPE.ArgumentError, reason: reason
    end
  end

  @spec new(term) :: {:ok, t()} | {:error, term}
  def new(radix) when is_integer(radix) and radix >= 2 do
    {:ok, %__MODULE__{radix: radix}}
  end

  def new(radix) do
    {:error, {:bad_radix, {radix, :not_a_valid_radix}}}
  end

  defimpl Codec, for: __MODULE__ do
    @moduledoc false

    ## API

    def radix(codec), do: codec.radix

    def normalize_input(codec, %Numeral{value: value, length: length} = input) do
      max_value = Integer.pow(codec.radix, length) - 1

      cond do
        value < 0 ->
          {:error, {:negative_value, value}}

        value > max_value ->
          {:error, {:value_is_larger_than_declared_length}}

        true ->
          normalized = input
          {:ok, length, normalized}
      end
    end

    def normalize_input(_codec, invalid) do
      {:error, {:not_a_numerical_string, invalid}}
    end

    def split_numerical_string_at(codec, num_string, n) do
      %Numeral{value: value, length: length} = num_string

      left_length = n
      right_length = length - n
      left_multiplier = Integer.pow(codec.radix, right_length)
      left_value = div(value, left_multiplier)
      right_value = rem(value, left_multiplier)

      left = %Numeral{value: left_value, length: left_length}
      right = %Numeral{value: right_value, length: right_length}
      {left, right}
    end

    def numerical_string_to_int(_codec, %Numeral{value: value}), do: {:ok, value}

    def int_to_padded_numerical_string(_codec, int, pad_count) when int >= 0 do
      %Numeral{value: int, length: pad_count}
    end

    def concat_numerical_strings(codec, left, right) do
      %Numeral{value: left_value, length: left_length} = left
      %Numeral{value: right_value, length: right_length} = right

      left_multiplier = Integer.pow(codec.radix, right_length)
      concat_value = left_value * left_multiplier + right_value
      concat_length = left_length + right_length
      %Numeral{value: concat_value, length: concat_length}
    end
  end
end
