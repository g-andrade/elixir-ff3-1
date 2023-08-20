# credo:disable-for-this-file Credo.Check.Readability.ModuleNames
# credo:disable-for-this-file Credo.Check.Readability.VariableNames
defmodule FF3_1.FFX do
  @moduledoc """
  FFX reference functions required to manipulate byte strings.
  """

  # https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38Gr1-draft.pdf

  ## Types

  @type key :: <<_::128>> | <<_::192>> | <<_::256>>
  @type radix :: pos_integer

  # Definition below is up to `Codec`
  @type numerical_string :: term()

  @type byte_string :: <<_::8, _::_*8>>
  @type codec :: FF3_1.FFX.Codec.t()

  ## Internal API

  @doc """
  4.5, Algorithm 2: NUM(X) -> x
  """
  @spec num(vX) :: x
        when vX: byte_string, x: non_neg_integer
  def num(vX) do
    <<x::integer-size(byte_size(vX))-unit(8)>> = vX
    x
  end

  @doc """
  4.5, Algorithm 5: REVB(X) -> Y
  """
  @spec revb(vX) :: vY
        when vX: byte_string, vY: byte_string
  def revb(vX) do
    size = byte_size(vX)
    <<integer::big-integer-size(size)-unit(8)>> = vX
    <<integer::little-integer-size(size)-unit(8)>>
  end

  defprotocol Codec do
    @moduledoc """
    FFX reference functions, among others, required to encode and decode
    integers to and from the numerical strings that represent them, given a
    particular alphabet or radix.
    """
    alias FF3_1.FFX

    @spec radix(t()) :: FFX.radix()
    def radix(codec)

    @spec numerical_string_length(t(), vX) :: {:ok, non_neg_integer} | {:error, term}
          when vX: FFX.numerical_string()
    def numerical_string_length(codec, vX)

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
          when vA: FFX.numerical_string(), vB: FFX.numerical_string(), vX: FFX.numerical_string()
    def concat_numerical_strings(codec, left, right)
  end
end
