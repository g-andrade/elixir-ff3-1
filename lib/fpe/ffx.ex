defmodule FPE.FFX do
  # https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38Gr1-draft.pdf

  ## Types

  @type key :: <<_::128>> | <<_::192>> | <<_::256>>
  @type radix :: pos_integer
  @type numerical_string :: <<_::8, _::_*8>>
  @type byte_string :: <<_::8, _::_*8>>

  ## Internal API

  @doc false
  @spec num(vX) :: x
        when vX: byte_string, x: non_neg_integer
  def num(vX) do
    # 4.5, Algorithm 2: NUM(X) -> x
    <<x::integer-size(byte_size(vX))-unit(8)>> = vX
    x
  end

  @doc false
  @spec rev(vX) :: vY
        when vX: numerical_string, vY: numerical_string
  def rev(vX) do
    # 4.5, Algorithm 4: REV(X) -> Y
    # TODO optimize for builtin and unibyte alphabets
    String.reverse(vX)
  end

  @doc false
  @spec revb(vX) :: vY
        when vX: byte_string, vY: byte_string
  def revb(vX) do
    # 4.5, Algorithm 5: REVB(X) -> Y
    size = byte_size(vX)
    <<integer::big-integer-size(size)-unit(8)>> = vX
    <<integer::little-integer-size(size)-unit(8)>>
  end

  defprotocol Codec do
    @moduledoc false
    alias FPE.FFX

    # 4.5, Algorithm 1: NUM_radix(X) -> x
    @spec num_radix(t, vX) :: x
          when vX: FFX.numerical_string, x: non_neg_integer
    def num_radix(codec, vX)

    # 4.5, Algorithm 3: STR_m_radix(X) -> x
    @spec str_m_radix(t, m, x) :: vX
          when m: pos_integer, x: non_neg_integer, vX: FFX.numerical_string
    def str_m_radix(codec, m, int)
  end
end
