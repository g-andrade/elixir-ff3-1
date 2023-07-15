# credo:disable-for-this-file Credo.Check.Readability.ModuleNames
# credo:disable-for-this-file Credo.Check.Readability.VariableNames
defmodule FPE.FF3_1 do
  @moduledoc """
  An implementation of the NIST-approved FF3-1 algorithm in Elixir.

  This implementation conforms, as best as possible, to
  [Draft SP 800-38G Rev. 1](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38Gr1-draft.pdf)
  specified by NIST in their Cryptographic Standards.

  No official test vectors for FF3-1 exist as of the time of writing;
  many of the ones used in this library's test suite were copied almost verbatim
  from [ubiq-fpe-go](https://gitlab.com/ubiqsecurity/ubiq-fpe-go), an implementation
  of the FF1 and FF3-1 algorithms in Go, licensed under MIT.
  """

  import Bitwise
  require Record

  alias FPE.FFX

  ## Types

  # 5.2, FF3-1 requirements
  @min_radix 2
  @max_radix 0xFFFF
  @type radix :: 2..0xFFFF
  @type alphabet :: <<_::16, _::_*8>>

  # 5.2, Algorithm 9: FF3.Encrypt(K, T, X)
  @type tweak :: <<_::56>>

  Record.defrecordp(:fpe_ff3_1_ctx, [
    :k,
    :codec,
    :minlen,
    :maxlen
  ])

  @opaque ctx ::
            record(:fpe_ff3_1_ctx,
              k: FFX.key(),
              codec: map,
              minlen: pos_integer,
              maxlen: pos_integer
            )

  ## API

  @doc """
  Validates arguments and creates context used for both encryption and decryption.

  ## Examples

      iex> key = :crypto.strong_rand_bytes(32)
      iex> {:ok, _ctx} = FPE.FF3_1.new_ctx(key, _radix = 10)

  """
  @spec new_ctx(k, radix | alphabet) :: {:ok, ctx} | {:error, term}
        when k: FFX.key()
  def new_ctx(k, radix_or_alphabet) do
    alias FPE.FFX.Codec

    with :ok <- validate_key(k),
         {:ok, codec} <- validate_radix_or_alphabet(radix_or_alphabet),
         radix = Codec.radix(codec),
         {:ok, minlen} <- calculate_minlen(radix),
         {:ok, maxlen} <- calculate_maxlen(minlen, radix) do
      {:ok,
       fpe_ff3_1_ctx(
         k: k,
         codec: codec,
         minlen: minlen,
         maxlen: maxlen
       )}
    else
      {:error, _} = error ->
        error
    end
  end

  @doc """
  Encrypts plaintext numerical string `vX` in base `radix` using `ctx` and 7-byte `tweak`.

  Returns encrypted numerical string `vY` in base `radix` and **of length equal to `vX`**
  (⚠ no padding!)

  Minimum and maximum length of `vX` depend on radix, as defined by the spec.

  ## Examples

      iex> # Base 10, AES-256
      iex> key = :crypto.strong_rand_bytes(32)
      iex> radix = 10
      iex> {:ok, ctx} = FPE.FF3_1.new_ctx(key, radix)
      iex> tweak = <<0::56>>
      iex> plaintext = "0034436524"
      iex> _ciphertext = FPE.FF3_1.encrypt!(ctx, tweak, plaintext)

  ⚠️ **Leading zeroes matter**!

      iex> # Base 16, AES-128
      iex> key = :crypto.strong_rand_bytes(16)
      iex> radix = 16
      iex> {:ok, ctx} = FPE.FF3_1.new_ctx(key, radix)
      iex> tweak = <<0::56>>
      iex> plaintext1 =   "4343af29cc"
      iex> plaintext2 = "004343af29cc"
      iex> ciphertext1 = FPE.FF3_1.encrypt!(ctx, tweak, plaintext1)
      iex> ciphertext2 = FPE.FF3_1.encrypt!(ctx, tweak, plaintext2)
      iex> ciphertext2 != ciphertext1
      true

  Tweaks may be public and used to make encrypted results distinct for the same inputs and key
  (see Appendix C of reference document):

      iex> # Base 12, AES-128
      iex> key = :crypto.strong_rand_bytes(16)
      iex> radix = 12
      iex> {:ok, ctx} = FPE.FF3_1.new_ctx(key, radix)
      iex> plaintext= "4534435abbbaa"
      iex> tweak1 = <<"dev.env">>
      iex> tweak2 = <<"prodenv">>
      iex> ciphertext1 = FPE.FF3_1.encrypt!(ctx, tweak1, plaintext)
      iex> ciphertext2 = FPE.FF3_1.encrypt!(ctx, tweak2, plaintext)
      iex> ciphertext2 != ciphertext1
      true

  Custom alphabets can be used:

      iex> # Lower case base 36, AES-256
      iex> key = :crypto.strong_rand_bytes(32)
      iex> alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"
      iex> {:ok, ctx} = FPE.FF3_1.new_ctx(key, alphabet)
      iex> tweak = <<0::56>>
      iex> plaintext = "pqlr4343afz29cc"
      iex> _ciphertext = FPE.FF3_1.encrypt!(ctx, tweak, plaintext)

  And Unicode is well supported:

      iex> # Base 8 with custom alphabet, AES-192
      iex> key = :crypto.strong_rand_bytes(24)
      iex> alphabet = "🌕🌖🌗🌘🌑🌒🌓🌔"
      iex> {:ok, ctx} = FPE.FF3_1.new_ctx(key, alphabet)
      iex> tweak = <<"badidea">>
      iex> plaintext = "🌖🌕🌘🌑🌓🌗🌔🌒🌒🌒🌒"
      iex> _ciphertext = FPE.FF3_1.encrypt!(ctx, tweak, plaintext)

    (you _really shouldn't_, but you can)

  """
  @spec encrypt!(ctx, tweak, vX) :: vY
        when vX: String.t(), vY: String.t()
  def encrypt!(ctx, t, vX) do
    {:ok, vY} = do_encrypt_or_decrypt(ctx, t, vX, _enc = true)
    vY
  end

  @doc """
  Decrypts encrypted numerical string `vX` in base `radix` using `ctx` and 7-byte `tweak`.

  Returns plaintext numerical string `vY` in base `radix` and **of length equal to `vX`**
  (⚠ no padding!)

  Minimum and maximum length of `vX` depend on radix, as defined by the spec.

  ## Examples

      iex> # Base 10, AES-256
      iex> key = :crypto.strong_rand_bytes(32)
      iex> radix = 10
      iex> {:ok, ctx} = FPE.FF3_1.new_ctx(key, radix)
      iex> tweak = <<0::56>>
      iex> plaintext = "0034436524"
      iex> ciphertext = FPE.FF3_1.encrypt!(ctx, tweak, plaintext)
      iex> FPE.FF3_1.decrypt!(ctx, tweak, ciphertext)
      plaintext

  ⚠️ **Leading zeroes matter**!

      iex> # Base 16, AES-128
      iex> key = :crypto.strong_rand_bytes(16)
      iex> radix = 16
      iex> {:ok, ctx} = FPE.FF3_1.new_ctx(key, radix)
      iex> tweak = <<0::56>>
      iex> plaintext1 =   "4343AF29CC"
      iex> plaintext2 = "004343AF29CC"
      iex> ciphertext1 = FPE.FF3_1.encrypt!(ctx, tweak, plaintext1)
      iex> ciphertext2 = FPE.FF3_1.encrypt!(ctx, tweak, plaintext2)
      iex> ciphertext2 != ciphertext1
      true
      iex> FPE.FF3_1.decrypt!(ctx, tweak, ciphertext1)
      plaintext1
      iex> FPE.FF3_1.decrypt!(ctx, tweak, ciphertext2)
      plaintext2

  Tweaks may be public and used to make encrypted results distinct for the same inputs and key
  (see Appendix C of reference document):

      iex> # Base 12, AES-128
      iex> key = :crypto.strong_rand_bytes(16)
      iex> radix = 12
      iex> {:ok, ctx} = FPE.FF3_1.new_ctx(key, radix)
      iex> plaintext= "4534435AABBBAABBB"
      iex> tweak1 = <<"dev.env">>
      iex> tweak2 = <<"prodenv">>
      iex> ciphertext1 = FPE.FF3_1.encrypt!(ctx, tweak1, plaintext)
      iex> ciphertext2 = FPE.FF3_1.encrypt!(ctx, tweak2, plaintext)
      iex> ciphertext2 != ciphertext1
      true
      iex> FPE.FF3_1.decrypt!(ctx, tweak1, ciphertext1)
      plaintext
      iex> FPE.FF3_1.decrypt!(ctx, tweak2, ciphertext2)
      plaintext

  Custom alphabets can be used:

      iex> # Uppercase base 36, AES-256
      iex> key = :crypto.strong_rand_bytes(32)
      iex> alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
      iex> {:ok, ctx} = FPE.FF3_1.new_ctx(key, alphabet)
      iex> tweak = <<0::56>>
      iex> plaintext = "PQLR4343AFZ29CC"
      iex> ciphertext = FPE.FF3_1.encrypt!(ctx, tweak, plaintext)
      iex> FPE.FF3_1.decrypt!(ctx, tweak, ciphertext)
      plaintext

  And Unicode is well supported:

      iex> # Base 8 with custom alphabet, AES-192
      iex> key = :crypto.strong_rand_bytes(24)
      iex> alphabet = "🌕🌖🌗🌘🌑🌒🌓🌔"
      iex> {:ok, ctx} = FPE.FF3_1.new_ctx(key, alphabet)
      iex> tweak = <<"badidea">>
      iex> plaintext = "🌖🌕🌘🌑🌓🌗🌔🌒🌒🌒🌒"
      iex> ciphertext = FPE.FF3_1.encrypt!(ctx, tweak, plaintext)
      iex> FPE.FF3_1.decrypt!(ctx, tweak, ciphertext)
      plaintext

    (you _really shouldn't_, but you can)

  """
  @spec decrypt!(ctx, t, vX) :: vY
        when t: tweak, vX: String.t(), vY: String.t()
  def decrypt!(ctx, t, vX) do
    {:ok, vY} = do_encrypt_or_decrypt(ctx, t, vX, _enc = false)
    vY
  end

  @doc """
  Returns a `ctx`'s `FPE.FFX.Codec`, should you wish to manipulate
  or prepare encryption and decryption inputs.
  """
  @spec codec(ctx) :: FFX.codec()
  def codec(fpe_ff3_1_ctx(codec: codec)), do: codec

  ## Internal Functions

  defp validate_key(k) do
    case k do
      k when byte_size(k) in [16, 24, 32] ->
        :ok

      <<invalid_size::bytes>> ->
        {:error, {:key_has_invalid_size, byte_size(invalid_size)}}

      not_a_binary ->
        {:error, {:key_not_a_binary, not_a_binary}}
    end
  end

  defp validate_radix_or_alphabet(radix_or_alphabet) do
    alias FPE.FFX.Codec

    case [Codec.Builtin, Codec.BuiltinLower]
         |> Enum.find_value(& &1.maybe_new(radix_or_alphabet)) do
      {:ok, codec} ->
        {:ok, codec}

      nil ->
        validate_custom_alphabet(radix_or_alphabet)
    end
  end

  defp validate_custom_alphabet(radix) when is_integer(radix) do
    case radix < @min_radix do
      true ->
        {:error, {:invalid_radix, radix, :less_than_minimum, @min_radix}}

      false ->
        # largest than builtin
        {:error, {:invalid_radix, radix, :you_need_to_provide_the_alphabet}}
    end
  end

  defp validate_custom_alphabet(alphabet) when is_binary(alphabet) do
    ordered_graphemes = String.graphemes(alphabet)
    unique_graphemes = Enum.uniq(ordered_graphemes)
    nr_of_symbols = length(ordered_graphemes)
    nr_of_unique_symbols = length(unique_graphemes)

    cond do
      nr_of_symbols > @max_radix ->
        {:error, {:alphabet_exceeds_max_radix, @max_radix}}

      nr_of_symbols == nr_of_unique_symbols ->
        codec = new_custom_codec(ordered_graphemes)
        {:ok, codec}

      nr_of_symbols > nr_of_unique_symbols ->
        repeated_symbols = ordered_graphemes -- unique_graphemes
        {:error, {:alphabet_has_repeated_symbols, repeated_symbols}}
    end
  end

  defp new_custom_codec(ordered_graphemes) do
    alias FPE.FFX.Codec

    case ordered_graphemes |> Enum.any?(&(byte_size(&1) > 1)) do
      true ->
        Codec.CustomMultibyte.new(ordered_graphemes)

      false ->
        Codec.CustomUnibyte.new(ordered_graphemes)
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

  defp do_encrypt_or_decrypt(ctx, t, vX, enc) do
    with :ok <- validate_enc_or_dec_input_len(ctx, vX),
         :ok <- validate_enc_or_dec_input_alphabet(ctx, vX),
         :ok <- validate_tweak(t) do
      fpe_ff3_1_ctx(k: k, codec: codec) = ctx
      {even_m, odd_m, vA, vB, even_vW, odd_vW} = setup_encrypt_or_decrypt_vars!(t, vX)

      vY =
        case enc do
          true ->
            do_encrypt_rounds!(_i = 0, k, codec, even_m, odd_m, vA, vB, even_vW, odd_vW)

          false ->
            do_decrypt_rounds!(_i = 7, k, codec, odd_m, even_m, vA, vB, odd_vW, even_vW)
        end

      {:ok, vY}
    else
      {:error, _} = error ->
        error
    end
  end

  defp validate_enc_or_dec_input_len(ctx, vX) do
    fpe_ff3_1_ctx(minlen: minlen, maxlen: maxlen) = ctx

    case String.length(vX) do
      valid_size when valid_size in minlen..maxlen ->
        :ok

      _invalid_size ->
        {:error, "Invalid input not between #{minlen} and #{maxlen} symbols long: #{inspect(vX)}"}
    end
  end

  defp validate_enc_or_dec_input_alphabet(ctx, vX) do
    alias FPE.FFX.Codec
    fpe_ff3_1_ctx(codec: codec) = ctx
    _ = Codec.string_to_int(codec, vX)
    :ok
  rescue
    exc in ArgumentError ->
      {:error, {:invalid_input, exc.message}}
  end

  defp validate_tweak(tweak) do
    case tweak do
      valid_size when bit_size(valid_size) == 56 ->
        :ok

      invalid_size when is_bitstring(invalid_size) ->
        {:error, "Invalid tweak not 56 bits long: #{inspect(invalid_size)}"}

      not_a_bitstring ->
        {:error, "Invalid tweak not a bitstring #{inspect(not_a_bitstring)}"}
    end
  end

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

  defp do_encrypt_rounds!(i, k, codec, m, other_m, vA, vB, vW, other_vW) when i < 8 do
    alias FPE.FFX.Codec
    alias FPE.FFX.Codec.Reversible
    radix = Codec.radix(codec)

    # 4.ii. Let P = W ⊕ [i]⁴ || [NUM_radix(REV(B))]¹²
    vP_W_xor_i = :crypto.exor(vW, <<i::unsigned-size(4)-unit(8)>>)
    vP_num_radix_rev_B = Codec.string_to_int(codec, Reversible.reverse_string(codec, vB))
    vP = <<vP_W_xor_i::bytes, vP_num_radix_rev_B::unsigned-size(12)-unit(8)>>

    ## 4.iii. Let S = REVB(CIPH_REVB(K)(REVB(P)))
    vS_revb_P = FFX.revb(vP)
    vS_revb_K = FFX.revb(k)
    vS_ciph_etc = ciph(vS_revb_K, vS_revb_P)
    vS = FFX.revb(vS_ciph_etc)

    ## 4.iv. Let y = NUM(S)
    y = FFX.num(vS)

    ## 4.v. Let c = (NUM_radix(REV(A)) + y) mod (radix**m)
    c_rev_A = Reversible.reverse_string(codec, vA)
    c_num_radix_rev_A_plus_y = Codec.string_to_int(codec, c_rev_A) + y
    c = rem(c_num_radix_rev_A_plus_y, Integer.pow(radix, m))

    ## 4.vi. Let C = REV(STR_m_radix(c))
    vC = Reversible.reverse_string(codec, Codec.int_to_padded_string(codec, m, c))

    ## 4.vii. Let A = B
    vA = vB

    ## 4.viii. let B = C
    vB = vC

    do_encrypt_rounds!(
      i + 1,
      k,
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

  # credo:disable-for-next-line Credo.Check.Refactor.FunctionArity
  defp do_encrypt_rounds!(8 = _i, _k, _codec, _m, _other_m, vA, vB, _vW, _other_vW) do
    ## 5. Return A || B
    <<vA::bytes, vB::bytes>>
  end

  defp do_decrypt_rounds!(i, k, codec, m, other_m, vA, vB, vW, other_vW) when i >= 0 do
    alias FPE.FFX.Codec
    alias FPE.FFX.Codec.Reversible
    radix = Codec.radix(codec)

    ## 4.ii. Let P = W ⊕ [i]⁴ || [NUM_radix(REV(A))]¹²
    vP_W_xor_i = :crypto.exor(vW, <<i::unsigned-size(4)-unit(8)>>)
    vP_num_radix_rev_A = Codec.string_to_int(codec, Reversible.reverse_string(codec, vA))
    vP = <<vP_W_xor_i::bytes, vP_num_radix_rev_A::unsigned-size(12)-unit(8)>>

    ## 4.iii. Let S = REVB(CIPH_REVB(K)(REVB(P)))
    vS_revb_P = FFX.revb(vP)
    vS_revb_K = FFX.revb(k)
    vS_ciph_etc = ciph(vS_revb_K, vS_revb_P)
    vS = FFX.revb(vS_ciph_etc)

    ## 4.iv. Let y = NUM(S)
    y = FFX.num(vS)

    ## 4.v. Let c = (NUM_radix(REV(B)) - y) mod (radix**m)
    c_rev_B = Reversible.reverse_string(codec, vB)
    c_num_radix_rev_B_minus_y = Codec.string_to_int(codec, c_rev_B) - y
    c = Integer.mod(c_num_radix_rev_B_minus_y, Integer.pow(radix, m))

    ## 4.vi. Let C = REV(STR_m_radix(c))
    vC = Reversible.reverse_string(codec, Codec.int_to_padded_string(codec, m, c))

    ## 4.vii. Let B = A
    vB = vA

    ## 4.viii. Let A = C
    vA = vC

    do_decrypt_rounds!(
      i - 1,
      k,
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

  # credo:disable-for-next-line Credo.Check.Refactor.FunctionArity
  defp do_decrypt_rounds!(-1 = _i, _k, _codec, _m, _other_m, vA, vB, _vW, _other_vW) do
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
