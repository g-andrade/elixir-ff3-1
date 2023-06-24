defmodule FPE.FFX do
  # https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38Gr1-draft.pdf

  alias __MODULE__.CustomCodec

  ## Types

  @type key :: <<_::128>> | <<_::192>> | <<_::256>>
  @type radix :: pos_integer
  @type numerical_string :: <<_::8, _::_*8>>
  @type byte_string :: <<_::8, _::_*1>>
  @type block_string :: <<_::128>>

  @type codec :: :builtin | :builtin_upper | __MODULE__.MultibyteCodec.t()

  ## Internal API

  @doc false
  @spec largest_builtin_alphabet() :: String.t()
  def largest_builtin_alphabet() do
    "0123456789abcdefghijklmnopqrstuvwxyz"
  end

  @doc false
  @spec num_radix(codec, radix, vX) :: x
        when codec: codec, radix: radix, vX: numerical_string, x: non_neg_integer
  def num_radix(codec, radix, vX) do
    # 4.5, Algorithm 1: NUM_radix(X) -> x
    case codec in [:builtin, :builtin_upper] do
      true ->
        String.to_integer(vX, radix)

      false ->
        CustomCodec.to_integer(codec, vX)
    end
  end

  @doc false
  @spec num(vX) :: x
        when vX: byte_string, x: non_neg_integer
  def num(vX) do
    # 4.5, Algorithm 2: NUM(X) -> x
    <<x::integer-size(byte_size(vX))-unit(8)>> = vX
    x
  end

  @doc false
  @spec str_m_radix(codec, m, radix, x) :: vX
        when codec: codec, m: pos_integer, radix: radix, x: non_neg_integer, vX: numerical_string
  def str_m_radix(codec, m, radix, x) when m > 0 and x >= 0 do
    # 4.5, Algorithm 3: STR_m_radix(X) -> x
    case codec do
      :builtin ->
        Integer.to_string(x, radix)
        |> String.downcase()
        |> String.pad_leading(m, "0")

      :builtin_upper ->
        Integer.to_string(x, radix)
        |> String.pad_leading(m, "0")

      custom_codec ->
        CustomCodec.to_padded_string(custom_codec, m, x)
    end
  end

  @doc false
  @spec rev(vX) :: vY
        when vX: numerical_string, vY: numerical_string
  def rev(vX) do
    # 4.5, Algorithm 4: REV(X) -> Y

    # vX
    # |> String.to_charlist
    # |> Enum.reverse
    # |> List.to_string

    vX
    |> String.graphemes()
    |> Enum.reverse()
    |> :unicode.characters_to_binary()
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

  # @doc false
  # @spec prf(k, vX, enc) :: vY
  # when k: key, vX: block_string, enc: boolean, vY: block_string
  # def prf(k, vX, enc) when byte_size(vX) == 16 do
  #   # 4.5, Algorithm 6: PRF(X) -> Y
  #   #  Modified to support a single block at a time
  #   #  since that's enough for our use case.
  #   %{
  #     128 => :aes_128_ecb,
  #     192 => :aes_192_ecb,
  #     256 => :aes_256_ecb
  #   }
  #   |> Map.fetch!(byte_size(k))
  #   |> :crypto.crypto_one_time(k, vX, enc)
  # end
end
