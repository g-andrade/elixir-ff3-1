# credo:disable-for-this-file Credo.Check.Readability.ModuleNames
# credo:disable-for-this-file Credo.Check.Readability.VariableNames
defmodule ExFPE.FF1 do
  @moduledoc """
  The FF1 format-preserving encryption mode.

  FF1 is the **only FPE mode approved by NIST** as of
  [SP 800-38Gr1 2pd](https://csrc.nist.gov/pubs/sp/800/38/g/r1/2pd)
  (Second Public Draft, February 2025), and this library's **default** mode.

  Use it through the `ExFPE` facade: since FF1 is the default, `ExFPE.new(key,
  radix_or_alphabet)` already selects it (no mode argument needed); then
  `ExFPE.encrypt!/3` / `ExFPE.decrypt!/3`. See `ExFPE` for the full how-to-use guide
  (contexts, alphabets, tweaks). This module documents what is specific to FF1:
  its **variable-length tweak** and its **length constraints**.

  ## Length constraints

  Numerical strings under FF1 are subject to minimum and maximum lengths that
  depend on the radix.

      iex> key = :crypto.strong_rand_bytes(32)
      iex> {:ok, ctx} = ExFPE.new(key, _radix = 10)
      iex> %{min_length: 6, max_length: 4_294_967_295} = ExFPE.FF1.constraints(ctx.algorithm)

      iex> key = :crypto.strong_rand_bytes(32)
      iex> {:ok, ctx} = ExFPE.new(key, _radix = 16)
      iex> %{min_length: 5, max_length: 4_294_967_295} = ExFPE.FF1.constraints(ctx.algorithm)

  `min_length` exists because, for a given radix, short numerical strings
  encompass too few possible values, rendering encryption ineffective under
  adversarial conditions. The 2pd requires the domain `radix ** min_length` to
  be at least **1 000 000** (strengthened from 100 in the first version, to
  mitigate FF1's small-domain vulnerabilities).

  ## Tweak

  FF1 accepts a **variable-length** tweak: any byte string, from the empty
  string up to the maximum tweak length. See `ExFPE` for the general role of
  tweaks, and the reference document below for the specifics.
  """

  import Bitwise

  alias ExFPE.Algorithm
  alias ExFPE.Codec
  alias ExFPE.FFX

  ## API Types

  # §4 FF1 requirements: radix ∈ [2 .. 2**16]
  @min_radix 2
  @max_radix 0x10_000
  @type radix :: 2..0x10_000

  # FF1 takes a variable-length byte-string tweak (0 .. maxTlen bytes)
  @type tweak :: binary()

  @typedoc false
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

  @typep ctx ::
           %__MODULE__{
             key: FFX.key(),
             codec: Codec.t(),
             min_length: pos_integer,
             max_length: pos_integer
           }

  ## API

  @doc false
  @spec new_ctx(FFX.key(), Codec.t()) :: {:ok, ctx} | {:error, term}
  def new_ctx(key, codec) do
    with :ok <- validate_key(key),
         radix = Codec.radix(codec),
         :ok <- validate_radix(radix),
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

  @doc false
  @spec codec(ctx) :: Codec.t()
  def codec(%__MODULE__{codec: codec}), do: codec

  @doc false
  @spec constraints(ctx) :: constraints()
  def constraints(%__MODULE__{min_length: min_length, max_length: max_length}) do
    %{min_length: min_length, max_length: max_length}
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

  defp validate_radix(radix) do
    cond do
      radix < @min_radix ->
        {:error, {:bad_radix, {radix, :less_than_minimum, @min_radix}}}

      radix > @max_radix ->
        {:error, {:bad_radix, {radix, :more_than_maximum, @max_radix}}}

      true ->
        :ok
    end
  end

  defp calculate_min_length(radix) do
    # §4 FF1 requirements: 'radix**minlen >= 1_000_000' and '2 <= minlen'.
    #
    # The first version required only >= 100; the 2pd strengthens the previous
    # small-domain guidance into a requirement to mitigate FF1's vulnerabilities.
    #
    # Computed with integer arithmetic only, since the 2pd (§5) forbids
    # floating-point representations and arithmetic.
    min_domain_size = 1_000_000
    min_length = max(2, smallest_exponent_reaching(radix, min_domain_size))
    {:ok, min_length}
  end

  # Smallest positive `exponent` such that `radix ** exponent >= target`.
  defp smallest_exponent_reaching(radix, target) do
    smallest_exponent_reaching(radix, target, _exponent = 1, _value = radix)
  end

  defp smallest_exponent_reaching(_radix, target, exponent, value) when value >= target do
    exponent
  end

  defp smallest_exponent_reaching(radix, target, exponent, value) do
    smallest_exponent_reaching(radix, target, exponent + 1, value * radix)
  end

  defp calculate_max_length(min_length) do
    # §4 FF1 requirements: 'minlen <= maxlen < 2**32'.
    max_length = (1 <<< 32) - 1

    case max_length do
      max_length when max_length >= min_length ->
        {:ok, max_length}
    end
  end

  defimpl Algorithm, for: __MODULE__ do
    def do_encrypt_or_decrypt(ctx, tweak, vX, enc) do
      with {:ok, vX_length, vX} <- validate_enc_or_dec_input(ctx, vX),
           :ok <- validate_tweak(ctx, tweak),
           %ExFPE.FF1{key: key, codec: codec} = ctx,
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
      %ExFPE.FF1{codec: codec, min_length: min_length, max_length: max_length} = ctx

      case Codec.normalize_input(codec, vX) do
        {:ok, valid_length, normalized_vX} when valid_length in min_length..max_length//1 ->
          {:ok, valid_length, normalized_vX}

        {:ok, invalid_length, _} ->
          {:error, {:invalid_input, {:length_out_of_bounds, invalid_length, {min_length, max_length}}}}

        {:error, reason} ->
          {:error, {:invalid_input, reason}}
      end
    end

    defp validate_tweak(%ExFPE.FF1{max_length: max_length}, tweak) do
      case tweak do
        _ when byte_size(tweak) <= max_length ->
          :ok

        invalid_size when is_binary(invalid_size) ->
          {:error, {:invalid_tweak, {:too_large, byte_size(invalid_size), max_length}}}

        not_a_binary ->
          {:error, {:invalid_tweak, {:not_a_binary, not_a_binary}}}
      end
    end

    defp setup_encrypt_or_decrypt_vars(codec, tweak, vX, vX_length) do
      n = vX_length
      t = byte_size(tweak)

      # 1. Let u = floor(n/2); v = n - u
      u = div(n, 2)
      v = n - u

      # 2. Let A = X[1..u]; B = X[u + 1..n]
      {vA_str, vB_str} = Codec.split_numerical_string_at(codec, vX, u)

      with {:ok, vA} <- Codec.numerical_string_to_int(codec, vA_str),
           {:ok, vB} <- Codec.numerical_string_to_int(codec, vB_str) do
        # 3. Let b = ⎡BITLEN(radix**v − 1)/8⎤.
        #
        # BITLEN(radix**v − 1) is the number of bits needed to represent it, so
        # ⎡that/8⎤ is the number of bytes: exactly the length of its minimal
        # big-endian encoding. Computed without floating point, as the 2pd (§5)
        # requires (the first version defined b via ⎡v·LOG2(radix)⎤).
        radix = Codec.radix(codec)
        b = byte_size(:binary.encode_unsigned(Integer.pow(radix, v) - 1))

        # 4. Let d = 4 ⎡b/4⎤ + 4.
        d = 4 * div(b + 3, 4) + 4

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
          {:error, {:invalid_input, reason}}
      end
    end

    # credo:disable-for-next-line Credo.Check.Refactor.FunctionArity
    defp do_encrypt_rounds!(i, key, codec, tweak, u, v, vA, vB, b, d, vP) when i < 10 do
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
      ## 5. Return A || B
      vA_str = Codec.int_to_padded_numerical_string(codec, vA, u)
      vB_str = Codec.int_to_padded_numerical_string(codec, vB, v)
      Codec.concat_numerical_strings(codec, vA_str, vB_str)
    end

    #################

    # credo:disable-for-next-line Credo.Check.Refactor.FunctionArity
    defp do_decrypt_rounds!(i, key, codec, tweak, u, v, vA, vB, b, d, vP) when i >= 0 do
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
      ## 5. Return A || B
      vA_str = Codec.int_to_padded_numerical_string(codec, vA, u)
      vB_str = Codec.int_to_padded_numerical_string(codec, vB, v)
      Codec.concat_numerical_strings(codec, vA_str, vB_str)
    end

    ###########

    # credo:disable-for-next-line Credo.Check.Readability.FunctionNames
    defp compute_vS_blocks(key, d, vR) do
      # ⎡d/16⎤ blocks, computed without floating point (2pd §5).
      last_index = div(d + 15, 16) - 1
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

    # credo:disable-for-next-line Credo.Check.Readability.FunctionNames
    defp compute_vS_blocks_recur(key, d, vR, acc_size, index, last_index) when index <= last_index and acc_size < d do
      [
        ciph(key, :crypto.exor(vR, <<index::unsigned-size(16)-unit(8)>>))
        | compute_vS_blocks_recur(key, d, vR, acc_size + 16, index + 1, last_index)
      ]
    end

    # credo:disable-for-next-line Credo.Check.Readability.FunctionNames
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
