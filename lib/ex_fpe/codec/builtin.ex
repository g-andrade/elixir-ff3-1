# credo:disable-for-this-file Credo.Check.Readability.ModuleNames
defmodule ExFPE.Codec.Builtin do
  @moduledoc """
  An implementation of `ExFPE.Codec` that handles alphabets made up of digits
  0 to 9 and letters a to z, in that order, with all letters of equal casing,
  encompassing radixes from 2 and up to 36.

  In other words: whatever `String.to_integer/2` can handle (or
  `String.to_integer/2` + `String.downcase/1`), this module will be a wrapper
  of.

  If you specify a radix, the output will be upper case. If you'd like lower
  case outputs, you'll need to specify the corresponding alphabet.

  Inputs are **case insensitive**, unlike `ExFPE.Codec.Custom`.
  """

  alias ExFPE.Codec

  ## Types

  @enforce_keys [:radix, :lower_case?]
  defstruct [:radix, :lower_case?]

  @type numerical_string :: String.t()

  @opaque t :: %__MODULE__{radix: radix, lower_case?: boolean}
  @type radix :: 2..36

  @broadest_upper_version "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
  @broadest_lower_version String.downcase(@broadest_upper_version, :ascii)

  ## API Functions

  @doc """
  Succeeds if the radix or alphabet can be handled by `Integer.to_string/2`.

  Returns `{:ok, t()}` if `term` is either:
  * a valid radix;
  * an upper case alphabet matching that of `Integer.to_string/2`;
  * a lower case alphabet matching that of `Integer.to_string/2` + `String.downcase/1`.

  Returns `nil` otherwise.
  """
  @spec maybe_new(term) :: {:ok, t()} | nil
  def maybe_new(radix_or_alphabet) when is_integer(radix_or_alphabet) do
    radix = radix_or_alphabet

    if radix in 2..36 do
      {:ok,
       %__MODULE__{
         radix: radix,
         lower_case?: false
       }}
    end
  end

  def maybe_new(radix_or_alphabet) when byte_size(radix_or_alphabet) >= 2 do
    alphabet = radix_or_alphabet
    matches_upper = String.starts_with?(@broadest_upper_version, alphabet)
    matches_lower = not matches_upper and String.starts_with?(@broadest_lower_version, alphabet)

    if matches_upper or matches_lower do
      radix = byte_size(alphabet)

      {:ok,
       %__MODULE__{
         radix: radix,
         lower_case?: matches_lower
       }}
    end
  end

  def maybe_new(_alphabet), do: nil

  defimpl Codec, for: __MODULE__ do
    @moduledoc false
    def radix(codec), do: codec.radix

    def normalize_input(_codec, string) when byte_size(string) !== 0 do
      normalized = string
      len = byte_size(normalized)
      {:ok, len, string}
    end

    def normalize_input(_codec, string) do
      {:error, {:not_a_numerical_string, string}}
    end

    def split_numerical_string_at(_codec, string, n), do: String.split_at(string, n)

    def numerical_string_to_int(codec, string) do
      String.to_integer(string, codec.radix)
    rescue
      ArgumentError ->
        {:error, {:not_a_numerical_string, string}}
    else
      int ->
        {:ok, int}
    end

    def int_to_padded_numerical_string(codec, int, pad_count) when int >= 0 do
      encoded = :erlang.integer_to_binary(int, codec.radix)

      case_result =
        if codec.lower_case? do
          String.downcase(encoded, :ascii)
        else
          encoded
        end

      String.pad_leading(case_result, pad_count, "0")
    end

    def concat_numerical_strings(_codec, left, right), do: left <> right
  end
end
