defmodule FPE.FF3_1 do
  # https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38Gr1-draft.pdf

  import Bitwise
  require Record

  alias FPE.FFX

  ## Types

  # 5.2, FF3-1 requirements
  @min_radix 2
  @max_radix 0xFFFF
  @type radix :: 2..0xFFFF
  @type alphabet :: <<_::16, _::_*8>> | :builtin | :builtin_upper

  # 5.2, Algorithm 9: FF3.Encrypt(K, T, X)
  @type tweak :: <<_::56>>

  Record.defrecordp(:ctx, [
    :k,
    :radix,
    :codec,
    :minlen,
    :maxlen
  ])

  @opaque ctx ::
            record(:ctx,
              k: FFX.key(),
              radix: radix,
              codec: FFX.codec(),
              minlen: pos_integer,
              maxlen: pos_integer
            )

  ## API

  defguardp is_valid_key(k) when is_binary(k) and bit_size(k) in [128, 192, 256]

  @spec new(k, radix | alphabet) :: {:ok, ctx} | {:error, term}
        when k: FFX.key(), radix: radix
  def new(k, _radix_or_alphabet) when not is_valid_key(k), do: {:error, {:invalid_key, k}}
  # def new(_k, radix) when not is_valid_radix(radix), do: {:error, {:invalid_radix, radix}}
  def new(k, radix_or_alphabet) do
    with {:ok, radix, codec} <- validate_radix_or_alphabet(radix_or_alphabet),
         {:ok, minlen} <- calculate_minlen(radix),
         {:ok, maxlen} <- calculate_maxlen(minlen, radix) do
      {:ok,
       ctx(
         k: k,
         radix: radix,
         codec: codec,
         minlen: minlen,
         maxlen: maxlen
       )}
    else
      {:error, _} = error ->
        error
    end
  end

  @spec encrypt!(ctx, t, vX) :: vY
        when ctx: ctx, t: tweak, vX: String.t(), vY: String.t()
  def encrypt!(ctx, t, vX) do
    do_encrypt_or_decrypt!(ctx, t, vX, _enc = true)
  end

  @spec decrypt!(ctx, t, vX) :: vY
        when ctx: ctx, t: tweak, vX: String.t(), vY: String.t()
  def decrypt!(ctx, t, vX) do
    do_encrypt_or_decrypt!(ctx, t, vX, _enc = false)
  end

  ## Internal Functions

  defp validate_radix_or_alphabet(radix) when is_integer(radix) do
    cond do
      radix < @min_radix ->
        {:error, {:invalid_radix, radix, :less_than_minimum, @min_radix}}

      radix > String.length(FFX.largest_builtin_alphabet()) ->
        {:error, {:invalid_radix, radix, :you_need_to_provide_the_alphabet}}

      true ->
        {:ok, radix, _codec = :builtin}
    end
  end

  defp validate_radix_or_alphabet(alphabet) when is_binary(alphabet) do
    # If alphabet is a prefix of the builtin, this allows us
    # to use the faster integer conversion functions bundled with ERTS.
    largest_builtin = FFX.largest_builtin_alphabet()

    use_builtin =
      largest_builtin
      |> String.starts_with?(alphabet)

    use_builtin_upper =
      !use_builtin &&
        largest_builtin
        |> String.upcase()
        |> String.starts_with?(alphabet)

    cond do
      use_builtin ->
        radix = String.length(alphabet)
        {:ok, radix, _codec = :builtin}

      use_builtin_upper ->
        radix = String.length(alphabet)
        {:ok, radix, _codec = :builtin_upper}

      true ->
        validate_custom_alphabet(alphabet)
    end
  end

  defp validate_radix_or_alphabet(alphabet) when alphabet in [:builtin, :builtin_upper] do
    radix = FFX.largest_builtin_alphabet() |> String.length()
    {:ok, radix, alphabet}
  end

  defp validate_radix_or_alphabet(neither), do: {:error, {:neither_radix_nor_alphabet, neither}}

  defp validate_custom_alphabet(alphabet) do
    ordered_graphemes = String.graphemes(alphabet)
    unique_graphemes = Enum.uniq(ordered_graphemes)
    nr_of_symbols = length(ordered_graphemes)
    nr_of_unique_symbols = length(unique_graphemes)

    cond do
      nr_of_symbols > @max_radix ->
        {:error, {:alphabet_exceeds_max_radix, @max_radix}}

      nr_of_symbols == nr_of_unique_symbols ->
        codec = new_custom_codec(ordered_graphemes)
        {:ok, _radix = nr_of_symbols, codec}

      nr_of_symbols > nr_of_unique_symbols ->
        repeated_symbols = ordered_graphemes -- unique_graphemes
        {:error, {:alphabet_has_repeated_symbols, repeated_symbols}}
    end
  end

  defp new_custom_codec(ordered_graphemes) do
    case ordered_graphemes |> Enum.any?(&(byte_size(&1) > 1)) do
      true ->
        FFX.MultibyteCodec.new(ordered_graphemes)

      false ->
        FFX.UnibyteCodec.new(ordered_graphemes)
    end
  end

  defp calculate_minlen(radix) do
    # 5.2, FF3-1 requirements: radix ** minlen >= 1_000_000
    min_domain_size = 1_000_000

    case ceil(:math.log2(min_domain_size) / :math.log2(radix)) do
      minlen when minlen >= 2 ->
        # 5.2, FF3-1 requirements: 2 <= minlen <= [...]
        {:ok, minlen}

      minlen ->
        {:error, {:minlen_too_low, minlen}}
    end
  end

  defp calculate_maxlen(minlen, radix) do
    upper_limit = 2 * floor(96 / :math.log2(radix))

    case upper_limit do
      maxlen when maxlen >= minlen ->
        # 5.2, FF3-1 requirements: 2 <= minlen <= maxlen <= [...]
        {:ok, maxlen}

      maxlen ->
        {:error, {:maxlen_less_when_minlen, %{max: maxlen, min: minlen}}}
    end
  end

  defp do_encrypt_or_decrypt!(ctx, t, vX, enc) do
    with :ok <- validate_enc_or_dec_input(ctx, vX),
         :ok <- validate_tweak(t) do
      ctx(k: k, radix: radix, codec: codec) = ctx
      {even_m, odd_m, vA, vB, even_vW, odd_vW} = setup_encrypt_or_decrypt_vars!(t, vX)

      case enc do
        true ->
          do_encrypt_rounds!(_i = 0, k, radix, codec, even_m, odd_m, vA, vB, even_vW, odd_vW)

        false ->
          do_decrypt_rounds!(_i = 7, k, radix, codec, odd_m, even_m, vA, vB, odd_vW, even_vW)
      end
    else
      {whats_wrong, details_msg} ->
        raise ArgumentError, message: "Invalid #{whats_wrong}: #{inspect(t)}: #{details_msg}"
    end
  end

  defp validate_enc_or_dec_input(ctx, vX) do
    ctx(minlen: minlen, maxlen: maxlen) = ctx
    # TODO validate alphabet
    case String.length(vX) do
      valid_size when valid_size in minlen..maxlen ->
        :ok

      _invalid_size ->
        {:input, "invalid size (not between #{minlen} and #{maxlen} symbols long"}
    end
  end

  defp validate_tweak(<<_::bits-size(56)>>), do: :ok
  defp validate_tweak(<<_::bits>>), do: {:tweak, "invalid size (not 56 bits long)"}
  defp validate_tweak(_), do: {:tweak, "not a 56 bits -long bitstring"}

  defp setup_encrypt_or_decrypt_vars!(t, vX) do
    n = String.length(vX)

    # 1. Let u = ceil(n/2); v = n - u
    u = div(n, 2) + (n &&& 1)
    v = n - u

    # 2. Let A = X[1..u]; B = X[u + 1..n]
    {vA, vB} = String.split_at(vX, u)

    # 3. Let T_L = T[0..27] || O⁴ and T_R = T[32..55] || T[28..31] || O⁴
    <<t_left::bits-size(28), t_middle::bits-size(4), t_right::bits-size(24)>> = t
    <<vT_L::bytes>> = <<t_left::bits, 0::4>>
    <<vT_R::bytes>> = <<t_right::bits, t_middle::bits, 0::4>>

    # 4.i. If i is even, let m = u and W = T_R, else let m = v and W = T_L
    even_m = u
    odd_m = v
    even_vW = vT_R
    odd_vW = vT_L
    {even_m, odd_m, vA, vB, even_vW, odd_vW}
  end

  defp do_encrypt_rounds!(i, k, radix, codec, m, other_m, vA, vB, vW, other_vW) when i < 8 do
    # 4.ii. Let P = W ⊕ [i]⁴ || [NUM_radix(REV(B))]¹²
    vP_W_xor_i = :crypto.exor(vW, <<i::unsigned-size(4)-unit(8)>>)
    vP_num_radix_rev_B = FFX.num_radix(codec, radix, FFX.rev(vB))
    vP = <<vP_W_xor_i::bytes, vP_num_radix_rev_B::unsigned-size(12)-unit(8)>>

    ## 4.iii. Let S = REVB(CIPH_REVB(K)(REVB(P)))
    vS_revb_P = FFX.revb(vP)
    vS_revb_K = FFX.revb(k)
    vS_ciph_etc = ciph(vS_revb_K, vS_revb_P)
    vS = FFX.revb(vS_ciph_etc)

    ## 4.iv. Let y = NUM(S)
    y = FFX.num(vS)

    ## 4.v. Let c = (NUM_radix(REV(A)) + y) mod (radix**m)
    c_rev_A = FFX.rev(vA)
    c_num_radix_rev_A_plus_y = FFX.num_radix(codec, radix, c_rev_A) + y
    c = rem(c_num_radix_rev_A_plus_y, Integer.pow(radix, m))

    ## 4.vi. Let C = REV(STR_m_radix(c))
    vC = FFX.rev(FFX.str_m_radix(codec, m, radix, c))

    ## 4.vii. Let A = B
    vA = vB

    ## 4.viii. let B = C
    vB = vC

    do_encrypt_rounds!(
      i + 1,
      k,
      radix,
      codec,
      # swap odd with even
      _m = other_m,
      _other_m = m,
      vA,
      vB,
      # swap odd with even
      _vW = other_vW,
      _other_vW = vW
    )
  end

  defp do_encrypt_rounds!(8 = _i, _k, _radix, _codec, _m, _other_m, vA, vB, _vW, _other_vW) do
    ## 5. Return A || B
    <<vA::bytes, vB::bytes>>
  end

  defp do_decrypt_rounds!(i, k, radix, codec, m, other_m, vA, vB, vW, other_vW) when i >= 0 do
    ## 4.ii. Let P = W ⊕ [i]⁴ || [NUM_radix(REV(A))]¹²
    vP_W_xor_i = :crypto.exor(vW, <<i::unsigned-size(4)-unit(8)>>)
    vP_num_radix_rev_A = FFX.num_radix(codec, radix, FFX.rev(vA))
    vP = <<vP_W_xor_i::bytes, vP_num_radix_rev_A::unsigned-size(12)-unit(8)>>

    ## 4.iii. Let S = REVB(CIPH_REVB(K)(REVB(P)))
    vS_revb_P = FFX.revb(vP)
    vS_revb_K = FFX.revb(k)
    vS_ciph_etc = ciph(vS_revb_K, vS_revb_P)
    vS = FFX.revb(vS_ciph_etc)

    ## 4.iv. Let y = NUM(S)
    y = FFX.num(vS)

    ## 4.v. Let c = (NUM_radix(REV(B)) - y) mod (radix**m)
    c_rev_B = FFX.rev(vB)
    c_num_radix_rev_B_minus_y = FFX.num_radix(codec, radix, c_rev_B) - y
    c = Integer.mod(c_num_radix_rev_B_minus_y, Integer.pow(radix, m))

    ## 4.vi. Let C = REV(STR_m_radix(c))
    vC = FFX.rev(FFX.str_m_radix(codec, m, radix, c))

    ## 4.vii. Let B = A
    vB = vA

    ## 4.viii. Let A = C
    vA = vC

    do_decrypt_rounds!(
      i - 1,
      k,
      radix,
      codec,
      # swap odd with even
      _m = other_m,
      _other_m = m,
      vA,
      vB,
      # swap odd with even
      _vW = other_vW,
      _other_vW = vW
    )
  end

  defp do_decrypt_rounds!(-1 = _i, _k, _radix, _codec, _m, _other_m, vA, vB, _vW, _other_vW) do
    ## 5. Return A || B
    <<vA::bytes, vB::bytes>>
  end

  defp ciph(k, input) do
    %{
      128 => :aes_128_ecb,
      192 => :aes_192_ecb,
      256 => :aes_256_ecb
    }
    |> Map.fetch!(bit_size(k))
    |> :crypto.crypto_one_time(k, input, _enc = true)
  end
end
