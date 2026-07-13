# credo:disable-for-this-file Credo.Check.Readability.ModuleNames
# credo:disable-for-this-file Credo.Check.Readability.VariableNames
defmodule ExFPE.FFX do
  @moduledoc """
  FFX definitions.
  """

  # https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38Gr1-draft.pdf

  ## Types

  @type key :: <<_::128>> | <<_::192>> | <<_::256>>
  @type radix :: pos_integer

  # Definition below is up to `Codec`
  @type numerical_string :: term()

  @type byte_string :: <<_::8, _::_*8>>

  ## Internal API

  # 4.5, Algorithm 2: NUM(X) -> x
  @doc false
  @spec num(vX) :: x
        when vX: byte_string, x: non_neg_integer
  def num(vX) do
    :binary.decode_unsigned(vX)
  end

  # 4.5, Algorithm 5: REVB(X) -> Y
  @doc false
  @spec revb(vX) :: vY
        when vX: byte_string, vY: byte_string
  def revb(vX) do
    size = byte_size(vX)
    integer = :binary.decode_unsigned(vX)
    <<integer::little-integer-size(size)-unit(8)>>
  end
end
