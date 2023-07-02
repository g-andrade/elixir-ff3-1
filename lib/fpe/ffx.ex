defmodule FPE.FFX do
  # https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38Gr1-draft.pdf

  ## Types

  @type key :: <<_::128>> | <<_::192>> | <<_::256>>
  @type radix :: pos_integer
  @type numerical_string :: <<_::8, _::_*8>>
  @type byte_string :: <<_::8, _::_*8>>
  @opaque codec :: %{atom => term, __struct__: module}

  ## Internal API

  # 4.5, Algorithm 2: NUM(X) -> x
  @doc false
  @spec num(vX) :: x
        when vX: byte_string, x: non_neg_integer
  def num(vX) do
    <<x::integer-size(byte_size(vX))-unit(8)>> = vX
    x
  end

  # 4.5, Algorithm 5: REVB(X) -> Y
  @doc false
  @spec revb(vX) :: vY
        when vX: byte_string, vY: byte_string
  def revb(vX) do
    size = byte_size(vX)
    <<integer::big-integer-size(size)-unit(8)>> = vX
    <<integer::little-integer-size(size)-unit(8)>>
  end

  defprotocol Codec do
    @moduledoc false
    alias FPE.FFX

    @spec radix(FFX.codec()) :: FFX.radix()
    def radix(codec)

    # 4.5, Algorithm 1: NUM_radix(X) -> x
    @spec string_to_int(FFX.codec(), vX) :: x
          when vX: FFX.numerical_string(), x: non_neg_integer
    def string_to_int(codec, vX)

    # 4.5, Algorithm 3: STR_m_radix(x) -> X
    @spec int_to_padded_string(FFX.codec(), count, non_neg_integer) :: vX
          when count: non_neg_integer, vX: FFX.numerical_string()
    def int_to_padded_string(codec, count, int)
  end

  defprotocol Reversible do
    @moduledoc false
    alias FPE.FFX

    # 4.5, Algorithm 4: REV(X) -> Y
    @spec reverse_string(FFX.codec(), vX) :: vY
          when vX: FFX.numerical_string(), vY: FFX.numerical_string()
    def reverse_string(codec, vX)
  end

  defimpl Reversible, for: Any do
    def reverse_string(_codec, vX), do: FPE.FFX.revb(vX)
  end
end
