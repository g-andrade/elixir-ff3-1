defmodule FPE.FFX.Codec.Builtin do
  @moduledoc false
  @derive [FPE.FFX.Reversible]

  ## Types

  @enforce_keys [:radix]
  defstruct [:radix]

  @type t :: %__MODULE__{radix: radix}
  @type radix :: 2..36

  @broadest_version "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"

  ## API Functions

  @spec maybe_new(non_neg_integer | String.t()) :: {radix, t()} | nil
  def maybe_new(radix) when is_integer(radix) do
    case radix in 2..36 do
      true ->
        {radix, %__MODULE__{radix: radix}}

      false ->
        nil
    end
  end

  def maybe_new(alphabet) when byte_size(alphabet) >= 2 do
    radix = byte_size(alphabet)

    case @broadest_version |> String.starts_with?(alphabet) do
      true ->
        {radix, %__MODULE__{radix: radix}}

      false ->
        nil
    end
  end

  defimpl FPE.FFX.Codec, for: __MODULE__ do
    def num_radix(codec, string) do
      :erlang.binary_to_integer(string, codec.radix)
    end

    def str_m_radix(codec, m, int) when int >= 0 do
      :erlang.integer_to_binary(int, codec.radix)
      |> String.pad_leading(m, "0")
    end

    def strip_leading_zeroes(codec, string) do
      case string do
        <<?0, rest::bytes>> when byte_size(rest) != 0 ->
          strip_leading_zeroes(codec, rest)

        stripped ->
          stripped
      end
    end
  end
end
