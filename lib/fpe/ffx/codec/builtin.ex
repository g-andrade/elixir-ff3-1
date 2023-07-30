defmodule FPE.FFX.Codec.Builtin do
  @moduledoc false

  alias FPE.FFX.Codec

  ## Types

  @enforce_keys [:radix, :case_insensitive, :lower_case]
  defstruct [:radix, :case_insensitive, :lower_case]

  @opaque t :: %__MODULE__{radix: radix, case_insensitive: boolean, lower_case: boolean}
  @type radix :: 2..36

  @broadest_upper_version "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
  @broadest_lower_version String.downcase(@broadest_upper_version, :ascii)

  ## API Functions

  @spec maybe_new(non_neg_integer | String.t(), Codec.InputOpts.t()) :: {:ok, t()} | nil
  def maybe_new(radix, input_opts) when is_integer(radix) do
    case radix in 2..36 do
      true ->
        {:ok,
         %__MODULE__{
           radix: radix,
           case_insensitive: input_opts.case_insensitive,
           lower_case: false
         }}

      false ->
        nil
    end
  end

  def maybe_new(alphabet, input_opts) when byte_size(alphabet) >= 2 do
    matches_upper = @broadest_upper_version |> String.starts_with?(alphabet)
    matches_lower = not matches_upper and @broadest_lower_version |> String.starts_with?(alphabet)

    case matches_upper or matches_lower do
      true ->
        radix = byte_size(alphabet)

        {:ok,
         %__MODULE__{
           radix: radix,
           case_insensitive: input_opts.case_insensitive,
           lower_case: matches_lower
         }}

      false ->
        nil
    end
  end

  defimpl Codec, for: __MODULE__ do
    def prepare_input_string(codec, string) when codec.case_insensitive do
      {:ok, string}
    end

    def prepare_input_string(codec, string) when codec.lower_case do
      case string == String.downcase(string, :ascii) do
        true ->
          {:ok, string}

        false ->
          {:error, :string_not_in_downcase}
      end
    end

    def prepare_input_string(_codec, string) do
      case string == String.upcase(string, :ascii) do
        true ->
          {:ok, string}

        false ->
          {:error, :string_not_in_upcase}
      end
    end

    def radix(codec), do: codec.radix

    def string_to_int(codec, string) do
      :erlang.binary_to_integer(string, codec.radix)
    end

    def int_to_padded_string(codec, count, int) when int >= 0 do
      encoded = :erlang.integer_to_binary(int, codec.radix)

      case codec.lower_case do
        true ->
          String.downcase(encoded, :ascii)

        false ->
          encoded
      end
      |> String.pad_leading(count, "0")
    end
  end
end
