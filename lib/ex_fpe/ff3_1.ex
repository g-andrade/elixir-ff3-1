# credo:disable-for-this-file Credo.Check.Readability.ModuleNames
# credo:disable-for-this-file Credo.Check.Readability.VariableNames
defmodule ExFPE.FF3_1 do
  @moduledoc """
  The FF3-1 format-preserving encryption mode.

  > #### No longer NIST-approved {: .warning}
  >
  > NIST **removed the entire FF3 family (FF3 and FF3-1)** in
  > [SP 800-38Gr1 2pd](https://csrc.nist.gov/pubs/sp/800/38/g/r1/2pd)
  > (Second Public Draft, February 2025): Beyne's linear cryptanalysis
  > ([CRYPTO 2021](https://doi.org/10.1007/978-3-030-84242-0_3)) found a weakness
  > in the tweak schedule that affects both FF3 and FF3-1 but **not** FF1. FF1 is
  > now the only approved FPE mode.
  >
  > FF3-1 is retained here for interoperability with existing data, but new
  > applications should prefer `ExFPE.FF1` (the `:ff1` mode, which is the default).

  Use it through the `ExFPE` facade: `ExFPE.new(key, :ff3_1, radix_or_alphabet)`,
  then `ExFPE.encrypt!/3` / `ExFPE.decrypt!/3`. See `ExFPE` for the full how-to-use
  guide (contexts, alphabets, tweaks). This module documents what is specific
  to FF3-1: its fixed **7-byte tweak** and its **length constraints**.

  This implementation conforms, as best as possible, to
  [Draft SP 800-38G Rev. 1](https://csrc.nist.gov/pubs/sp/800/38/g/r1/ipd)
  (the first draft, in which FF3-1 was still specified), as published by NIST in
  their Cryptographic Standards.

  No official test vectors for FF3-1 exist as of the time of writing;
  many of the ones used in this library's test suite were copied almost verbatim
  from [ubiq-fpe-go](https://gitlab.com/ubiqsecurity/ubiq-fpe-go), an implementation
  of the FF1 and FF3-1 algorithms in Go.

  ## Length constraints

  Numerical strings under FF3-1 are subject to minimum and maximum lengths.
  These constraints depend on the radix.

      iex> key = :crypto.strong_rand_bytes(32)
      iex> {:ok, ctx} = ExFPE.new(key, :ff3_1,_radix = 10)
      iex> %{min_length: 6, max_length: 56} = ExFPE.FF3_1.constraints(ctx.algorithm)

      iex> key = :crypto.strong_rand_bytes(32)
      iex> {:ok, ctx} = ExFPE.new(key, :ff3_1,_radix = 16)
      iex> %{min_length: 5, max_length: 48} = ExFPE.FF3_1.constraints(ctx.algorithm)

      iex> key = :crypto.strong_rand_bytes(32)
      iex> {:ok, ctx} = ExFPE.new(key, :ff3_1,_radix = 2)
      iex> %{min_length: 20, max_length: 192} = ExFPE.FF3_1.constraints(ctx.algorithm)

  `min_length` is required because, for any given radix, short enough numerical
  strings encompass too few possible values, rendering encryption ineffective
  under adversarial conditions. In other words: their domain is too small.

  `max_length` may be there - pure layman speculation - as an incentive for people
  to use regular crypto when working with large enough numbers. I didn't find
  the exact reasoning for it.

  ## Tweak

  FF3-1 uses a fixed **7-byte (56-bit)** tweak. See `ExFPE` for the general role
  of tweaks in FPE, and Appendix C (page 20) of
  [the reference
  document](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38Gr1-draft.pdf)
  for the specifics.

      iex> byte_size(<<0::56>>)
      7

  """

  alias ExFPE.Algorithm
  alias ExFPE.Codec
  alias ExFPE.FFX

  ## API Types

  # 5.2, FF3-1 requirements
  @min_radix 2
  @max_radix 0xFFFF
  @type radix :: 2..0xFFFF

  # 5.2, Algorithm 9: FF3.Encrypt(K, T, X)
  @type tweak :: <<_::56>>

  @typedoc false
  @type constraints :: %{min_length: pos_integer, max_length: pos_integer}

  @enforce_keys [
    :key,
    :iform_ctx,
    :min_length,
    :max_length
  ]
  defstruct [
    :key,
    :iform_ctx,
    :min_length,
    :max_length
  ]

  @typep ctx ::
           %__MODULE__{
             key: FFX.key(),
             iform_ctx: FFX.IntermediateForm.ctx(),
             min_length: pos_integer,
             max_length: pos_integer
           }

  ## API

  @doc false
  @spec new_ctx(FFX.key(), radix) :: {:ok, ctx} | {:error, term}
  def new_ctx(key, radix) do
    alias FFX.IntermediateForm

    with :ok <- validate_key(key),
         :ok <- validate_radix(radix),
         iform_ctx = IntermediateForm.new_ctx(radix),
         {:ok, min_length} <- calculate_min_length(radix),
         {:ok, max_length} <- calculate_max_length(min_length, radix) do
      {:ok,
       %__MODULE__{
         key: key,
         iform_ctx: iform_ctx,
         min_length: min_length,
         max_length: max_length
       }}
    else
      {:error, _} = error ->
        error
    end
  end

  @doc false
  @spec constraints(ctx) :: %{min_length: pos_integer, max_length: pos_integer}
  def constraints(%__MODULE__{min_length: min_length, max_length: max_length}) do
    %{min_length: min_length, max_length: max_length}
  end

  ## Internal Functions

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
    # 5.2, FF3-1 requirements: radix ** min_length >= 1_000_000
    min_domain_size = 1_000_000

    case ceil(:math.log2(min_domain_size) / :math.log2(radix)) do
      min_length when min_length >= 2 ->
        # 5.2, FF3-1 requirements: 2 <= min_length <= [...]
        {:ok, min_length}
    end
  end

  defp calculate_max_length(min_length, radix) do
    upper_limit = 2 * floor(96 / :math.log2(radix))

    case upper_limit do
      max_length when max_length >= min_length ->
        # 5.2, FF3-1 requirements: 2 <= min_length <= max_length <= [...]
        {:ok, max_length}
    end
  end

  defimpl Algorithm, for: __MODULE__ do
    alias ExFPE.FF3_1
    alias FFX.IntermediateForm

    require Record

    @total_rounds 8

    Record.defrecordp(:aux, [
      :key,
      :codec,
      :iform_ctx,
      :radix
    ])

    @typep aux ::
             record(:aux,
               key: FFX.key(),
               codec: Codec.t(),
               iform_ctx: IntermediateForm.ctx(),
               radix: FF3_1.radix()
             )

    def do_encrypt_or_decrypt(ctx, t, codec, vX, enc) do
      with {:ok, vX_length, vX} <- validate_enc_or_dec_input(ctx, codec, vX),
           :ok <- validate_tweak(t),
           %FF3_1{key: key, iform_ctx: iform_ctx} = ctx,
           {:ok, aux, even_m, odd_m, a, b, even_w, odd_w} <-
             setup_encdec_vars(key, codec, iform_ctx, t, vX, vX_length) do
        vY =
          if enc do
            do_encrypt_rounds!(aux, 0, even_m, odd_m, a, b, even_w, odd_w)
          else
            do_decrypt_rounds!(aux, @total_rounds - 1, odd_m, even_m, a, b, odd_w, even_w)
          end

        {:ok, vY}
      else
        {:error, _} = error ->
          error
      end
    end

    defp validate_enc_or_dec_input(ctx, codec, vX) do
      %FF3_1{min_length: min_length, max_length: max_length} = ctx

      case Codec.normalize_input(codec, vX) do
        {:ok, valid_length, normalized_vX} when valid_length in min_length..max_length//1 ->
          {:ok, valid_length, normalized_vX}

        {:ok, invalid_length, _} ->
          {:error, {:invalid_input, {:length_out_of_bounds, invalid_length, {min_length, max_length}}}}

        {:error, reason} ->
          {:error, {:invalid_input, reason}}
      end
    end

    defp validate_tweak(tweak) do
      case tweak do
        valid_size when bit_size(valid_size) == 56 ->
          :ok

        invalid_size when is_bitstring(invalid_size) ->
          {:error, {:invalid_tweak, {:invalid_bit_size, bit_size(invalid_size), 56}}}

        not_a_bitstring ->
          {:error, {:invalid_tweak, {:not_a_bitstring, not_a_bitstring}}}
      end
    end

    defp setup_encdec_vars(key, codec, iform_ctx, t, vX, vX_length) do
      n = vX_length

      # 1. Let u = ceil(n/2); v = n - u
      u = div(n + 1, 2)
      v = n - u

      # 2. Let A = X[1..u]; B = X[u + 1..n]
      {a_str, b_str} = Codec.split_numerical_string_at(codec, vX, u)

      with {:ok, a} <- Codec.numerical_string_to_int(codec, a_str),
           {:ok, b} <- Codec.numerical_string_to_int(codec, b_str) do
        # 3. Let T_L = T[0..27] || O⁴ and T_R = T[32..55] || T[28..31] || O⁴
        <<t_left::bits-size(28), t_middle::bits-size(4), t_right::bits-size(24)>> = t
        <<t_l::bytes>> = <<t_left::bits, 0::4>>
        <<t_r::bytes>> = <<t_right::bits, t_middle::bits, 0::4>>

        aux =
          aux(
            key: key,
            codec: codec,
            iform_ctx: iform_ctx,
            radix: Codec.radix(codec)
          )

        # 4.i. If i is even, let m = u and W = T_R, else let m = v and W = T_L
        even_m = u
        odd_m = v
        even_w = t_r
        odd_w = t_l
        {:ok, aux, even_m, odd_m, a, b, even_w, odd_w}
      else
        {:error, reason} ->
          {:error, {:invalid_input, reason}}
      end
    end

    #####################

    @spec do_encrypt_rounds!(
            aux,
            non_neg_integer,
            pos_integer,
            pos_integer,
            non_neg_integer,
            non_neg_integer,
            binary,
            binary
          ) :: term

    defp do_encrypt_rounds!(aux, i, m, other_m, a, b, w, other_w) when i < @total_rounds do
      aux(key: key, iform_ctx: iform_ctx, radix: radix) = aux

      # 4.ii. Let P = W ⊕ [i]⁴ || [NUM_radix(REV(B))]¹²
      p_w_xor_i = :crypto.exor(w, <<i::unsigned-size(4)-unit(8)>>)
      p_num_radix_rev_b = IntermediateForm.left_pad_and_revert(iform_ctx, b, other_m)
      p = <<p_w_xor_i::bytes, p_num_radix_rev_b::unsigned-size(12)-unit(8)>>

      ## 4.iii. Let S = REVB(CIPH_REVB(K)(REVB(P)))
      s_revb_p = FFX.revb(p)
      s_revb_k = FFX.revb(key)
      s_ciph_etc = ciph(s_revb_k, s_revb_p)
      s = FFX.revb(s_ciph_etc)

      ## 4.iv. Let y = NUM(S)
      y = FFX.num(s)

      ## 4.v. Let c = (NUM_radix(REV(A)) + y) mod (radix**m)
      c_num_radix_rev_a = IntermediateForm.left_pad_and_revert(iform_ctx, a, m)
      small_c = rem(c_num_radix_rev_a + y, Integer.pow(radix, m))

      ## 4.vi. Let C = REV(STR_m_radix(c))
      c = IntermediateForm.left_pad_and_revert(iform_ctx, small_c, m)

      ## 4.vii. Let A = B; 4.viii. let B = C
      a = b
      b = c

      # swap odd with even
      do_encrypt_rounds!(aux, i + 1, other_m, m, a, b, other_w, w)
    end

    defp do_encrypt_rounds!(aux, i, m, other_m, a, b, _w, _other_w) when i === @total_rounds do
      aux(codec: codec) = aux

      ## 5. Return A || B
      a_str = Codec.int_to_padded_numerical_string(codec, a, m)
      b_str = Codec.int_to_padded_numerical_string(codec, b, other_m)
      Codec.concat_numerical_strings(codec, a_str, b_str)
    end

    #################

    @spec do_decrypt_rounds!(
            aux,
            -1 | non_neg_integer,
            pos_integer,
            pos_integer,
            non_neg_integer,
            non_neg_integer,
            binary,
            binary
          ) :: term

    defp do_decrypt_rounds!(aux, i, m, other_m, a, b, w, other_w) when i >= 0 do
      aux(key: key, iform_ctx: iform_ctx, radix: radix) = aux

      ## 4.ii. Let P = W ⊕ [i]⁴ || [NUM_radix(REV(A))]¹²
      p_w_xor_i = :crypto.exor(w, <<i::unsigned-size(4)-unit(8)>>)
      p_num_radix_rev_a = IntermediateForm.left_pad_and_revert(iform_ctx, a, other_m)
      p = <<p_w_xor_i::bytes, p_num_radix_rev_a::unsigned-size(12)-unit(8)>>

      ## 4.iii. Let S = REVB(CIPH_REVB(K)(REVB(P)))
      s_revb_p = FFX.revb(p)
      s_revb_k = FFX.revb(key)
      s_ciph_etc = ciph(s_revb_k, s_revb_p)
      s = FFX.revb(s_ciph_etc)

      ## 4.iv. Let y = NUM(S)
      y = FFX.num(s)

      ## 4.v. Let c = (NUM_radix(REV(B)) - y) mod (radix**m)
      c_num_radix_rev_b = IntermediateForm.left_pad_and_revert(iform_ctx, b, m)
      small_c = Integer.mod(c_num_radix_rev_b - y, Integer.pow(radix, m))

      ## 4.vi. Let C = REV(STR_m_radix(c))
      c = IntermediateForm.left_pad_and_revert(iform_ctx, small_c, m)

      ## 4.vii. Let B = A; 4.viii. Let A = C
      b = a
      a = c

      # swap odd with even
      do_decrypt_rounds!(aux, i - 1, other_m, m, a, b, other_w, w)
    end

    defp do_decrypt_rounds!(aux, i, m, other_m, a, b, _w, _other_w) when i === -1 do
      aux(codec: codec) = aux

      ## 5. Return A || B
      a_str = Codec.int_to_padded_numerical_string(codec, a, other_m)
      b_str = Codec.int_to_padded_numerical_string(codec, b, m)
      Codec.concat_numerical_strings(codec, a_str, b_str)
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
