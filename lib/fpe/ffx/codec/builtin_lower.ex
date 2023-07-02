defmodule FPE.FFX.Codec.BuiltinLower do
  @moduledoc false
  @derive [FPE.FFX.Reversible]

  ## Types

  @enforce_keys [:radix]
  defstruct [:radix]

  @type t :: %__MODULE__{radix: radix}
  @type radix :: 11..36

  @broadest_version "0123456789abcdefghijklmnopqrstuvwxyz"

  ## API Functions

  @spec maybe_new(non_neg_integer | String.t()) :: {radix, t()} | nil
  def maybe_new(radix) when is_integer(radix) do
    case radix in 2..36 do
      true when radix < 11 ->
        # Otherwise we'd unnecessarily call String.downcase/1
        raise "Call Builtin.maybe_new/1 first"

      true ->
        {radix, %__MODULE__{radix: radix}}

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
        {radix, %__MODULE__{radix: byte_size(alphabet)}}

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
      |> String.downcase()
      |> String.pad_leading(m, "0")
    end
  end
end
