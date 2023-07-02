defmodule FPE.FFX.Codec.Builtin do
  @moduledoc false
  @derive [FPE.FFX.Reversible]

  ## Types

  @enforce_keys [:radix]
  defstruct [:radix]

  @opaque t :: %__MODULE__{radix: radix}
  @type radix :: 2..36

  @broadest_version "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"

  ## API Functions

  @spec maybe_new(non_neg_integer | String.t()) :: {:ok, t()} | :error
  def maybe_new(radix) when is_integer(radix) do
    case radix in 2..36 do
      true ->
        {:ok, %__MODULE__{radix: radix}}

      false ->
        :error
    end
  end

  def maybe_new(alphabet) when byte_size(alphabet) >= 2 do
    case @broadest_version |> String.starts_with?(alphabet) do
      true ->
        radix = byte_size(alphabet)
        {:ok, %__MODULE__{radix: radix}}

      false ->
        :error
    end
  end

  defimpl FPE.FFX.Codec, for: __MODULE__ do
    def radix(codec), do: codec.radix

    def string_to_int(codec, string) do
      :erlang.binary_to_integer(string, codec.radix)
    end

    def int_to_padded_string(codec, count, int) when int >= 0 do
      :erlang.integer_to_binary(int, codec.radix)
      |> String.pad_leading(count, "0")
    end
  end
end
