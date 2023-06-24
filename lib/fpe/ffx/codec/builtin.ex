defmodule FPE.FFX.Codec.Builtin do
  @moduledoc false

  ## Types

  @enforce_keys [:radix]
  defstruct [:radix]

  @type t :: %__MODULE__{radix: radix}
  @type radix :: 2..36

  @largest "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"

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

    case @largest |> String.starts_with?(alphabet) do
      true ->
        {radix, %__MODULE__{radix: radix}}
      false ->
        nil
    end
  end

  defimpl FPE.FFX.Codec, for: __MODULE__ do
    alias FPE.FFX.Codec.Builtin

    @spec num_radix(Builtin.t(), String.t()) :: non_neg_integer
    def num_radix(codec, string) do
      :erlang.binary_to_integer(string, codec.radix)
    end

    @spec str_m_radix(Builtin.t(), pos_integer, non_neg_integer) :: String.t
    def str_m_radix(codec, m, int) when int >= 0 do
      :erlang.integer_to_binary(int, codec.radix)
      |> String.pad_leading(m, "0")
    end
  end
end
