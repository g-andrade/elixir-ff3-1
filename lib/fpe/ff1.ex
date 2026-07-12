defmodule FPE.FF1 do
  @moduledoc false

  # Reference: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38G.pdf

  import Bitwise

  alias FPE.Algorithm
  alias FPE.FFX

  ## API Types

  @type key :: FFX.key()
  @type codec :: FFX.Codec.t()
  @type numerical_string :: FFX.numerical_string()

  # 5.2, FF3-1 requirements
  @min_radix 2
  @max_radix 0xFFFF
  @type radix :: 2..0x10_000
  @type alphabet :: <<_::16, _::_*8>>

  # 5.2, Algorithm 9: FF3.Encrypt(K, T, X)
  @type tweak :: <<_::56>>

  @type constraints :: %{min_length: pos_integer, max_length: pos_integer}

  @enforce_keys [
    :key,
    :codec,
    :min_length,
    :max_length
  ]
  defstruct [
    :key,
    :codec,
    :min_length,
    :max_length
  ]

  @type ctx ::
          %__MODULE__{
            key: key,
            codec: codec,
            min_length: pos_integer,
            max_length: pos_integer
          }

  ## API

  @doc """
  Validates arguments and creates a context used for both encryption and decryption.
  """
  @spec new_ctx(key, radix | alphabet | codec) :: {:ok, ctx} | {:error, term}
  def new_ctx(key, radix_or_alphabet_or_codec) do
    alias FFX.Codec

    with :ok <- validate_key(key),
         {:ok, codec} <- validate_radix_or_alphabet(radix_or_alphabet_or_codec),
         radix = Codec.radix(codec),
         {:ok, min_length} <- calculate_min_length(radix),
         {:ok, max_length} <- calculate_max_length(min_length) do
      {:ok,
       %__MODULE__{
         key: key,
         codec: codec,
         min_length: min_length,
         max_length: max_length
       }}
    else
      {:error, _} = error ->
        error
    end
  end

  ## Internal

  defp validate_key(key) do
    case key do
      key when byte_size(key) in [16, 24, 32] ->
        :ok

      <<invalid_size::bytes>> ->
        {:error, {:key_has_invalid_size, byte_size(invalid_size)}}

      not_a_binary ->
        {:error, {:key_not_a_binary, not_a_binary}}
    end
  end

  defp validate_radix_or_alphabet(%{__struct__: _} = codec) do
    alias FPE.FFX.Codec

    radix = Codec.radix(codec)

    cond do
      radix < @min_radix ->
        {:error, {:invalid_radix, {radix, :less_than_minimum, @min_radix}}}

      radix > @max_radix ->
        {:error, {:invalid_radix, {radix, :more_than_maximum, @max_radix}}}

      true ->
        {:ok, codec}
    end
  end

  defp validate_radix_or_alphabet(radix_or_alphabet) do
    alias FPE.FFX.Codec

    case Codec.Builtin.maybe_new(radix_or_alphabet) do
      {:ok, codec} ->
        {:ok, codec}

      nil ->
        validate_custom_alphabet(radix_or_alphabet)
    end
  end

  defp validate_custom_alphabet(radix) when is_integer(radix) do
    # largest than builtin
    if radix < @min_radix do
      {:error, {:invalid_radix, {radix, :less_than_minimum, @min_radix}}}
    else
      {:error, {:invalid_radix, {radix, :you_need_to_provide_either_an_alphabet_or_a_codec}}}
    end
  end

  defp validate_custom_alphabet(alphabet) when is_binary(alphabet) do
    alias FPE.FFX.Codec

    case Codec.Custom.new(alphabet) do
      {:ok, codec} ->
        radix = Codec.radix(codec)

        cond do
          radix < @min_radix ->
            {:error, {:alphabet_smaller_than_min_radix, @min_radix}}

          radix > @max_radix ->
            {:error, {:alphabet_larger_than_max_radix, @max_radix}}

          true ->
            {:ok, codec}
        end

      {:error, _} = error ->
        error
    end
  end

  defp calculate_min_length(radix) do
    # FF1 requirement: 'radix**minlen >= 100'
    min_length = ceil(:math.log(100.0) / :math.log(radix))
    {:ok, min_length}
  end

  defp calculate_max_length(min_length) do
    # FF1 requirement: 'minlen <= maxlen < 2**32'
    upper_limit = 1 <<< 32

    case upper_limit do
      max_length when max_length >= min_length ->
        {:ok, max_length}
    end
  end

  defimpl Algorithm, for: __MODULE__ do
    def do_encrypt_or_decrypt(ctx, tweak, vX, enc) do
      with {:ok, vX_length, vX} <- validate_enc_or_dec_input(ctx, vX),
           :ok <- validate_tweak(ctx, tweak),
           %FPE.FF1{key: key, codec: codec} = ctx,
           {:ok, u, v, vA, vB, b, d, vP} <- setup_encrypt_or_decrypt_vars(codec, tweak, vX, vX_length) do
        vY =
          if enc do
            do_encrypt_rounds!(
              _i = 0,
              key,
              codec,
              tweak,
              #
              u,
              v,
              vA,
              vB,
              b,
              d,
              vP
            )
          else
            do_decrypt_rounds!(
              _i = 9,
              key,
              codec,
              tweak,
              #
              u,
              v,
              vA,
              vB,
              b,
              d,
              vP
            )
          end

        {:ok, vY}
      else
        {:error, _} = error ->
          error
      end
    end

    defp validate_enc_or_dec_input(ctx, vX) do
      alias FFX.Codec

      %FPE.FF1{codec: codec, min_length: min_length, max_length: max_length} = ctx

      case Codec.normalize_input(codec, vX) do
        {:ok, valid_length, normalized_vX} when valid_length in min_length..max_length//1 ->
          {:ok, valid_length, normalized_vX}

        {:ok, _invalid_length, _} ->
          {:error, "Invalid input not between #{min_length} and #{max_length} symbols long: #{inspect(vX)}"}

        {:error, reason} ->
          {:error, {:invalid_input, reason}}
      end
    end

    defp validate_tweak(%FPE.FF1{max_length: max_length}, tweak) do
      case tweak do
        _ when byte_size(tweak) <= max_length ->
          :ok

        invalid_size when is_binary(invalid_size) ->
          {:error, "Invalid tweak, too large (#{byte_size(invalid_size)} bytes long)"}

        not_a_binary ->
          {:error, "Invalid tweak not a binary #{inspect(not_a_binary)}"}
      end
    end

    defp setup_encrypt_or_decrypt_vars(codec, tweak, vX, vX_length) do
      alias FFX.Codec

      n = vX_length
      t = byte_size(tweak)

      # 1. Let u = floor(n/2); v = n - u
      u = div(n, 2)
      v = n - u

      # 2. Let A = X[1..u]; B = X[u + 1..n]
      {vA_str, vB_str} = Codec.split_numerical_string_at(codec, vX, u)

      with {:ok, vA} <- Codec.numerical_string_to_int(codec, vA_str),
           {:ok, vB} <- Codec.numerical_string_to_int(codec, vB_str) do
        # 3. Let b = ⎡ ⎡v ⋅ LOG(radix)⎤/8⎤.
        radix = Codec.radix(codec)
        b = ceil(ceil(v * :math.log2(radix)) / 8)

        # 4. Let d = 4 ⎡b/4⎤ + 4.
        d = 4 * ceil(b / 4) + 4

        # 5. Let P = [1]1 || [2]1 || [1]1 || [radix]3 || [10]1 || [u mod 256]1 || [n]4 || [t]4.
        vP = <<
          1,
          2,
          1,
          radix::24,
          10,
          Integer.mod(u, 256),
          n::32,
          t::32
        >>

        {:ok, u, v, vA, vB, b, d, vP}
      else
        {:error, reason} ->
          {:error, {:invalid_input, vX, reason}}
      end
    end

    # credo:disable-for-next-line Credo.Check.Refactor.FunctionArity
    defp do_encrypt_rounds!(i, key, codec, tweak, u, v, vA, vB, b, d, vP) when i < 10 do
      alias FFX.Codec

      radix = Codec.radix(codec)
      t = byte_size(tweak)

      # i. Let Q = T || [0](−t−b−1) mod 16 || [i]1 || [NUMradix(B)]b
      vQ_zeros_size = Integer.mod(-t - b - 1, 16)

      vQ = <<
        tweak::bytes,
        0::unsigned-size(vQ_zeros_size)-unit(8),
        i,
        vB::unsigned-size(b)-unit(8)
      >>

      # ii. Let R = PRF(P || Q).
      vR = prf(key, [vP, vQ])

      # iii. Let S be the first d bytes of the following string of ⎡d/16⎤ blocks:
      # R || CIPHK (R ⊕ [1]16) || CIPHK (R ⊕ [2]16) … CIPHK (R ⊕ [⎡d/16⎤ – 1]16
      #
      vS_blocks = compute_vS_blocks(key, d, vR)
      vS = :binary.part(vS_blocks, 0, d)

      # iv. Let y = NUM(S).
      y = FFX.num(vS)

      # v. If i is even, let m = u; else, let m = v
      m =
        if rem(i, 2) === 0 do
          u
        else
          v
        end

      # vi. Let c = (NUMradix(A) + y) mod (radix ** m)
      c = Integer.mod(vA + y, Integer.pow(radix, m))

      # vii. Let C = STR_m_radix(c)
      vC = c

      vA = vB
      vB = vC

      do_encrypt_rounds!(i + 1, key, codec, tweak, u, v, vA, vB, b, d, vP)
    end

    # credo:disable-for-next-line Credo.Check.Refactor.FunctionArity
    defp do_encrypt_rounds!(10, _key, codec, _tweak, u, v, vA, vB, _b, _d, _vP) do
      alias FFX.Codec
      ## 5. Return A || B
      vA_str = Codec.int_to_padded_numerical_string(codec, vA, u)
      vB_str = Codec.int_to_padded_numerical_string(codec, vB, v)
      Codec.concat_numerical_strings(codec, vA_str, vB_str)
    end

    #################

    # credo:disable-for-next-line Credo.Check.Refactor.FunctionArity
    defp do_decrypt_rounds!(i, key, codec, tweak, u, v, vA, vB, b, d, vP) when i >= 0 do
      alias FFX.Codec

      radix = Codec.radix(codec)
      t = byte_size(tweak)

      # i. Let Q = T || [0](−t−b−1) mod 16 || [i]1 || [NUMradix (A)]b
      vQ_zeros_size = Integer.mod(-t - b - 1, 16)

      vQ = <<
        tweak::bytes,
        0::unsigned-size(vQ_zeros_size)-unit(8),
        i,
        vA::unsigned-size(b)-unit(8)
      >>

      # ii. Let R = PRF(P || Q).
      vR = prf(key, [vP, vQ])

      # iii. Let S be the first d bytes of the following string of ⎡d/16⎤ blocks:
      # R || CIPHK (R ⊕ [1]16) || CIPHK (R ⊕ [2]16) … CIPHK (R ⊕ [⎡d/16⎤ – 1]16
      #
      vS_blocks = compute_vS_blocks(key, d, vR)
      vS = :binary.part(vS_blocks, 0, d)

      # iv. Let y = NUM(S).
      y = FFX.num(vS)

      # v. If i is even, let m = u; else, let m = v
      m =
        if rem(i, 2) === 0 do
          u
        else
          v
        end

      # vi. Let c = (NUMradix(B) - y) mod (radix ** m)
      c = Integer.mod(vB - y, Integer.pow(radix, m))

      # vii. Let C = STR_m_radix(c)
      vC = c

      vB = vA
      vA = vC

      do_decrypt_rounds!(i - 1, key, codec, tweak, u, v, vA, vB, b, d, vP)
    end

    # credo:disable-for-next-line Credo.Check.Refactor.FunctionArity
    defp do_decrypt_rounds!(-1, _key, codec, _tweak, u, v, vA, vB, _b, _d, _vP) do
      alias FFX.Codec
      ## 5. Return A || B
      vA_str = Codec.int_to_padded_numerical_string(codec, vA, u)
      vB_str = Codec.int_to_padded_numerical_string(codec, vB, v)
      Codec.concat_numerical_strings(codec, vA_str, vB_str)
    end

    ###########

    defp compute_vS_blocks(key, d, vR) do
      last_index = ceil(d / 16) - 1
      acc_size = byte_size(vR)
      IO.iodata_to_binary([vR | compute_vS_blocks_recur(key, d, vR, acc_size, 1, last_index)])
      # <<
      #  vR::bytes,
      #  #
      #  ciph(key, :crypto.exor(vR, <<1::unsigned-size(16)>>)),
      #  #
      #  ciph(key, :crypto.exor(vR, <<2::unsigned-size(16)>>)),
      # >>
    end

    defp compute_vS_blocks_recur(key, d, vR, acc_size, index, last_index) when index <= last_index and acc_size < d do
      [
        ciph(key, :crypto.exor(vR, <<index::unsigned-size(16)-unit(8)>>))
        | compute_vS_blocks_recur(key, d, vR, acc_size + 16, index + 1, last_index)
      ]
    end

    defp compute_vS_blocks_recur(_key, _d, _vR, _acc_size, _index, _last_index) do
      []
    end

    defp prf(key, x) do
      cipher = Map.fetch!(%{128 => :aes_128_cbc, 192 => :aes_192_cbc, 256 => :aes_256_cbc}, bit_size(key))

      ct = :crypto.crypto_one_time(cipher, key, <<0::128>>, x, _enc = true)
      binary_part(ct, byte_size(ct) - 16, 16)
    end

    defp ciph(key, input) do
      %{
        128 => :aes_128_ecb,
        192 => :aes_192_ecb,
        256 => :aes_256_ecb
      }
      |> Map.fetch!(bit_size(key))
      |> :crypto.crypto_one_time(key, input, _enc = true)
    end
  end
end
