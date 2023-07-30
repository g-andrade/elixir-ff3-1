# credo:disable-for-this-file Credo.Check.Readability.VariableNames
defmodule FPE.FFX do
  # https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38Gr1-draft.pdf

  ## Types

  @type key :: <<_::128>> | <<_::192>> | <<_::256>>
  @type radix :: pos_integer
  @type numerical_string :: <<_::8, _::_*8>>
  @type byte_string :: <<_::8, _::_*8>>
  @type codec :: FPE.FFX.Codec.t()

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
    @moduledoc """
    FFX reference functions required to encode and decode integers
    to and from the numerical strings that represent them, given
    a particular alphabet or radix.
    """
    alias FPE.FFX

    defmodule InputOpts do
      @moduledoc false

      defstruct case_insensitive: true,
                norm_insensitive: true

      @type t :: %__MODULE__{
              case_insensitive: boolean,
              norm_insensitive: boolean
            }
    end

    @doc """
    Prepares an input ciphertext or plaintext for internal processing
    """
    @spec prepare_input_string(t(), FFX.numerical_string()) ::
            {:ok, FFX.numerical_string()} | {:error, term}
    def prepare_input_string(codec, vX)

    @doc """
    Returns a codec instance's radix
    """
    @spec radix(t()) :: FFX.radix()
    def radix(codec)

    # 4.5, Algorithm 1: NUM_radix(X) -> x
    @doc """
    Converts numerical string `vX` to integer `x`
    """
    @spec string_to_int(t(), vX) :: x
          when vX: FFX.numerical_string(), x: non_neg_integer
    def string_to_int(codec, vX)

    # 4.5, Algorithm 3: STR_m_radix(x) -> X
    @doc """
    Converts integer `x` to padded numerical string `vX`
    """
    @spec int_to_padded_string(t(), count, non_neg_integer) :: vX
          when count: non_neg_integer, vX: FFX.numerical_string()
    def int_to_padded_string(codec, count, int)
  end
end
