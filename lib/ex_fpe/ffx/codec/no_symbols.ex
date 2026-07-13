# credo:disable-for-this-file Credo.Check.Readability.ModuleNames
defmodule ExFPE.FFX.Codec.NoSymbols do
  @moduledoc """
  An implementation of `ExFPE.FFX.Codec` that handles tagged integers, the tag
  being the value length.
  """

  alias ExFPE.FFX
  alias ExFPE.FFX.Codec

  ## Types

  @enforce_keys [:radix]
  defstruct [:radix]

  @opaque t :: %__MODULE__{radix: radix}
  @type radix :: FFX.radix()

  defmodule NumString do
    @moduledoc "A numerical string encoded as an integer"
    @enforce_keys [:value, :length]
    defstruct [:value, :length]

    @type t :: %__MODULE__{value: non_neg_integer, length: pos_integer}
  end

  @type numerical_string :: NumString.t()

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

    def normalize_input(codec, %NumString{value: value, length: length} = input) do
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
      %NumString{value: value, length: length} = num_string

      left_length = n
      right_length = length - n
      left_multiplier = Integer.pow(codec.radix, right_length)
      left_value = div(value, left_multiplier)
      right_value = rem(value, left_multiplier)

      left = %NumString{value: left_value, length: left_length}
      right = %NumString{value: right_value, length: right_length}
      {left, right}
    end

    def numerical_string_to_int(_codec, %NumString{value: value}), do: {:ok, value}

    def int_to_padded_numerical_string(_codec, int, pad_count) when int >= 0 do
      %NumString{value: int, length: pad_count}
    end

    def concat_numerical_strings(codec, left, right) do
      %NumString{value: left_value, length: left_length} = left
      %NumString{value: right_value, length: right_length} = right

      left_multiplier = Integer.pow(codec.radix, right_length)
      concat_value = left_value * left_multiplier + right_value
      concat_length = left_length + right_length
      %NumString{value: concat_value, length: concat_length}
    end
  end
end
