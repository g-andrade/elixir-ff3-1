defprotocol ExFPE.Codec do
  @moduledoc """
  FFX reference functions, among others, required to encode and decode
  integers to and from the numerical strings that represent them, given a
  particular alphabet or radix.
  """
  alias ExFPE.FFX

  @spec radix(t()) :: FFX.radix()
  def radix(codec)

  @spec normalize_input(t(), vX) :: {:ok, numerical_string_length, vX} | {:error, reason}
        when vX: FFX.numerical_string(), numerical_string_length: non_neg_integer, reason: term
  def normalize_input(codec, s)

  @spec split_numerical_string_at(t(), vX, pos_integer) :: {vA, vB}
        when vX: FFX.numerical_string(), vA: FFX.numerical_string(), vB: FFX.numerical_string()
  def split_numerical_string_at(codec, vX, n)

  @doc """
  4.5, Algorithm 1: NUM_radix(X) -> x
  """
  @spec numerical_string_to_int(t(), vX) :: {:ok, x} | {:error, reason}
        when vX: FFX.numerical_string(), x: non_neg_integer, reason: term
  def numerical_string_to_int(codec, vX)

  @doc """
  4.5, Algorithm 3: STR_m_radix(x) -> X
  """
  @spec int_to_padded_numerical_string(t(), non_neg_integer, pad_count) :: vX
        when pad_count: non_neg_integer, vX: FFX.numerical_string()
  def int_to_padded_numerical_string(codec, int, pad_count)

  @spec concat_numerical_strings(t(), vA, vB) :: vX
        when vA: FFX.numerical_string(), vB: FFX.numerical_string(), vX: FFX.numerical_string() | String.t()
  def concat_numerical_strings(codec, left, right)
end
