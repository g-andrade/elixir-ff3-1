# credo:disable-for-this-file Credo.Check.Readability.ModuleNames
defmodule FF3_1.FFX.Codec.Builtin do
  @moduledoc """
  An implementation of `FF3_1.FFX.Codec` that handles alphabets made up of digits
  0 to 9 and letters a to z, in that order, with all letters of equal casing,
  encompassing radixes from 2 and up to 36.

  In other words: whatever `String.to_integer/2` can handle (except mixed
  case), this module will be a wrap of.

  If you specify a radix, the output will be upper case. If you'd like lower
  case outputs, you'll need to specify the corresponding alphabet.

  Inputs are case insensitive, unlike `FF3_1.FFX.Codec.Custom`.
  """

  alias FF3_1.FFX.Codec

  ## Types

  @enforce_keys [:radix, :lower_case]
  defstruct [:radix, :lower_case]

  @type numerical_string :: String.t()

  @opaque t :: %__MODULE__{radix: radix, lower_case: boolean}
  @type radix :: 2..36

  @broadest_upper_version "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
  @broadest_lower_version String.downcase(@broadest_upper_version, :ascii)

  ## API Functions

  @spec maybe_new(term) :: {:ok, t()} | nil
  def maybe_new(radix) when is_integer(radix) do
    if radix in 2..36 do
      {:ok,
       %__MODULE__{
         radix: radix,
         lower_case: false
       }}
    end
  end

  def maybe_new(alphabet) when byte_size(alphabet) >= 2 do
    matches_upper = String.starts_with?(@broadest_upper_version, alphabet)
    matches_lower = not matches_upper and String.starts_with?(@broadest_lower_version, alphabet)

    if matches_upper or matches_lower do
      radix = byte_size(alphabet)

      {:ok,
       %__MODULE__{
         radix: radix,
         lower_case: matches_lower
       }}
    end
  end

  def maybe_new(_alphabet), do: nil

  defimpl Codec, for: __MODULE__ do
    @moduledoc false
    def radix(codec), do: codec.radix

    def numerical_string_length(_codec, string) when is_binary(string) do
      {:ok, String.length(string)}
    end

    def numerical_string_length(_codec, string) do
      {:error, {:not_a_numerical_string, string}}
    end

    def split_numerical_string_at(_codec, string, n), do: String.split_at(string, n)

    def numerical_string_to_int(codec, string) when byte_size(string) !== 0 do
      {:ok, String.to_integer(string, codec.radix)}
    rescue
      ArgumentError ->
        {:error, :unknown_symbol}
    end

    def int_to_padded_numerical_string(codec, int, pad_count) when int >= 0 do
      encoded = :erlang.integer_to_binary(int, codec.radix)

      case_result =
        if codec.lower_case do
          String.downcase(encoded, :ascii)
        else
          encoded
        end

      String.pad_leading(case_result, pad_count, "0")
    end

    def concat_numerical_strings(_codec, left, right), do: left <> right
  end
end
