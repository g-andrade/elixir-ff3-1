defmodule FPE.FFX.Codec.BuiltinLower do
  @moduledoc false
  @derive [FPE.FFX.Codec.Reversible]

  ## Types

  @enforce_keys [:radix]
  defstruct [:radix]

  @opaque t :: %__MODULE__{radix: radix}
  @type radix :: 11..36

  @broadest_version "0123456789abcdefghijklmnopqrstuvwxyz"

  ## API Functions

  @spec maybe_new(non_neg_integer | String.t()) :: {:ok, t()} | nil
  def maybe_new(radix) when is_integer(radix) do
    case radix in 2..36 do
      true when radix < 11 ->
        # Otherwise we'd unnecessarily call String.downcase/1
        raise "Call Builtin.maybe_new/1 first"

      true ->
        {:ok, %__MODULE__{radix: radix}}

      false ->
        nil
    end
  end

  def maybe_new(alphabet) do
    radix = byte_size(alphabet)

    case String.starts_with?(@broadest_version, alphabet) do
      true when radix < 11 ->
        # Otherwise we'd unnecessarily call String.downcase/1
        raise "Call Builtin.maybe_new/1 first"

      true ->
        {:ok, %__MODULE__{radix: byte_size(alphabet)}}

      false ->
        nil
    end
  end

  defimpl FPE.FFX.Codec, for: __MODULE__ do
    def radix(codec), do: codec.radix

    def string_to_int(codec, string) do
      # FIXME should we refuse upper-cased strings here?
      :erlang.binary_to_integer(string, codec.radix)
    end

    def int_to_padded_string(codec, count, int) when int >= 0 do
      :erlang.integer_to_binary(int, codec.radix)
      |> String.downcase()
      |> String.pad_leading(count, "0")
    end
  end
end
