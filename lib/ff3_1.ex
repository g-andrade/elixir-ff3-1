# credo:disable-for-this-file Credo.Check.Readability.ModuleNames
# credo:disable-for-this-file Credo.Check.Readability.VariableNames
defmodule FF3_1 do
  @moduledoc """
  An implementation of the NIST-approved FF3-1 algorithm in Elixir.

  This implementation conforms, as best as possible, to
  [Draft SP 800-38G Rev. 1](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38Gr1-draft.pdf)
  specified by NIST in their Cryptographic Standards.

  No official test vectors for FF3-1 exist as of the time of writing;
  many of the ones used in this library's test suite were copied almost verbatim
  from [ubiq-fpe-go](https://gitlab.com/ubiqsecurity/ubiq-fpe-go), an implementation
  of the FF1 and FF3-1 algorithms in Go.

  # How to use

  ## Context

  We start by creating a context with `:new_ctx/2`, passing it a cryptographic
  key and radix.

      iex> key = :crypto.strong_rand_bytes(32)
      iex> {:ok, _ctx} = FF3_1.new_ctx(key, _radix = 10)

  Keys can be 32, 24 or 16 bytes long, and AES-256, AES-192 or AES-128 will be
  used, respectively.

  Radix is an integer between 2 and 36. For larger radices up to 65535, a
  custom alphabet is needed (more on that later).

  ## Encrypting and decrypting

  We're going to `:encrypt!/3` our numerical string `plaintext`, in base 10,
  and get another of equal length, `ciphertext`, which we can `decrypt!/3`
  back to get the original `plaintext`.

  A 7-byte `tweak` is required, which we'll handwave for now.

      iex> key = :crypto.strong_rand_bytes(32)
      iex> {:ok, ctx} = FF3_1.new_ctx(key, _radix = 10)
      iex> tweak = <<0::56>>
      iex> plaintext = "34436524"
      iex> ciphertext = FF3_1.encrypt!(ctx, tweak, plaintext)
      iex> ^plaintext = FF3_1.decrypt!(ctx, tweak, ciphertext)

  ## Leading zeroes

  ⚠️ Bear in mind that **leading zeroes are significant**: ciphertexts are always
  of equal length to their respective plaintexts, and vice-versa.

      iex> key = :crypto.strong_rand_bytes(32)
      iex> {:ok, ctx} = FF3_1.new_ctx(key, _radix = 10)
      iex> tweak = <<0::56>>
      iex> plaintext1 =   "34436524"
      iex> plaintext2 = "0034436524"
      iex> ciphertext1 = FF3_1.encrypt!(ctx, tweak, plaintext1)
      iex> ciphertext2 = FF3_1.encrypt!(ctx, tweak, plaintext2)
      iex> false = (ciphertext2 == ciphertext1)
      iex> true = (String.length(ciphertext1) == String.length(plaintext1))
      iex> true = (String.length(ciphertext2) == String.length(plaintext2))

  ## Length constraints

  FF3-1 imposes constraints on the length of the numerical strings used with
  any given `ctx`; these limits depend on the radix.

      iex> key = :crypto.strong_rand_bytes(32)
      iex> {:ok, ctx} = FF3_1.new_ctx(key, _radix = 10)
      iex> %{minlen: 6, maxlen: 56} = FF3_1.domain_constraints(ctx)

      iex> key = :crypto.strong_rand_bytes(32)
      iex> {:ok, ctx} = FF3_1.new_ctx(key, _radix = 16)
      iex> %{minlen: 5, maxlen: 48} = FF3_1.domain_constraints(ctx)

      iex> key = :crypto.strong_rand_bytes(32)
      iex> {:ok, ctx} = FF3_1.new_ctx(key, _radix = 2)
      iex> %{minlen: 20, maxlen: 192} = FF3_1.domain_constraints(ctx)

  The reasoning for `minlen`, from my layman's understanding, is that when
  working with smaller radixes, numerical strings below a particular length
  encompass too few possible values, rendering the encryption ineffective in
  adversarial conditions.

  As for `maxlen`: I have no idea. But it's probably not sensible to use FPE
  instead of regular crypto when working with such large numbers, anyway.

  ## Tweaks

  Tweaks may be public information that can be used to produce different
  ciphertexts for the same plaintext. **They are important in FPE modes**,
  given that FPE (the technique) may be used in situations where the number of
  possible strings is relatively small. In such a scenario, the tweak should
  vary with each instance of the encryption whenever possible.

      iex> key = :crypto.strong_rand_bytes(32)
      iex> {:ok, ctx} = FF3_1.new_ctx(key, _radix = 10)
      iex> plaintext= "135522432"
      iex> tweak1 = <<"dev.env">>
      iex> tweak2 = <<"prodenv">>
      iex> ciphertext1 = FF3_1.encrypt!(ctx, tweak1, plaintext)
      iex> ciphertext2 = FF3_1.encrypt!(ctx, tweak2, plaintext)
      iex> ciphertext2 != ciphertext1

  For an explanation and further examples, refer to Appendix C (page 20) of
  [the reference
  document](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38Gr1-draft.pdf).

  ## Built-in alphabet

  For radixes between 2 and 36, if what `String.to_integer/2` does fits your
  use case, you can specify the `radix` when building your `ctx` and you're
  good to go. Both `plaintext` and `ciphertext` will be encoded in the chosen
  base.

  #### Base 8

      iex> key = :crypto.strong_rand_bytes(32)
      iex> {:ok, ctx} = FF3_1.new_ctx(key, _radix = 8)
      iex> tweak = <<0::56>>
      iex> plaintext = "34436524"
      iex> ciphertext = FF3_1.encrypt!(ctx, tweak, plaintext)
      iex> ^plaintext = FF3_1.decrypt!(ctx, tweak, ciphertext)

  #### Base 16

      iex> key = :crypto.strong_rand_bytes(32)
      iex> {:ok, ctx} = FF3_1.new_ctx(key, _radix = 16)
      iex> tweak = <<0::56>>
      iex> plaintext = "AFD093902C"
      iex> ciphertext = FF3_1.encrypt!(ctx, tweak, plaintext)
      iex> ^plaintext = FF3_1.decrypt!(ctx, tweak, ciphertext)

  #### Base 36

      iex> key = :crypto.strong_rand_bytes(32)
      iex> {:ok, ctx} = FF3_1.new_ctx(key, _radix = 36)
      iex> tweak = <<0::56>>
      iex> plaintext = "ZZZAFD093902CBZDE"
      iex> ciphertext = FF3_1.encrypt!(ctx, tweak, plaintext)
      iex> ^plaintext = FF3_1.decrypt!(ctx, tweak, ciphertext)

  ### Built-in alphabet: case insensitivity to input

  Even though the output of either `:encrypt!/3` or `:decrypt!` is
  upper case, any case is accepted in inputs.

      iex> key = :crypto.strong_rand_bytes(32)
      iex> radix = 16
      iex> {:ok, ctx} = FF3_1.new_ctx(key, radix)
      iex> tweak = <<0::56>>
      iex> input = "aBcDDFF01234eeEee"
      iex> _ciphertext = FF3_1.encrypt!(ctx, tweak, input)
      iex> _plaintext = FF3_1.decrypt!(ctx, tweak, input)

  ### Builtin-alphabet: lower case

  If you want to use the built-in alphabet but desire for the output
  to be lower case, you can specify it by declaring the alphabet
  when creating `ctx`.

      iex> key = :crypto.strong_rand_bytes(32)
      iex> alphabet = "0123456789abcdef" # radix 16
      iex> {:ok, ctx} = FF3_1.new_ctx(key, alphabet)
      iex> tweak = <<0::56>>
      iex> input = "aBcDDFF01234eeEee"
      iex> ciphertext = FF3_1.encrypt!(ctx, tweak, input)
      iex> plaintext = FF3_1.decrypt!(ctx, tweak, input)
      iex> ^ciphertext = String.downcase(ciphertext)
      iex> ^plaintext = String.downcase(plaintext)

  ### Custom alphabets

  Whether you need a radix beyond 36, or use symbols other than 0-9, A-Z in
  your numerical strings (or use such symbols in a different order), custom
  alphabets can be used.

  Note that custom alphabets are **case sensitive** but norm insensitive.
  The reasoning behind this can be found under `FF3_1.FFX.Codec.Custom`.

  #### Base 20 with custom alphabet

      iex> key = :crypto.strong_rand_bytes(32)
      iex> alphabet = "abcdefghij0123456789"
      iex> {:ok, ctx} = FF3_1.new_ctx(key, alphabet)
      iex> tweak = <<0::56>>
      iex> plaintext = "34534abcd32235"
      iex> ciphertext = FF3_1.encrypt!(ctx, tweak, plaintext)
      iex> ^plaintext = FF3_1.decrypt!(ctx, tweak, ciphertext)

  #### Base 40 with custom alphabet

      iex> key = :crypto.strong_rand_bytes(32)
      iex> alphabet = "0123456789abcdefghijklmnopqrstuvwxyz@#/*"
      iex> {:ok, ctx} = FF3_1.new_ctx(key, alphabet)
      iex> tweak = <<0::56>>
      iex> plaintext = "34534ab@@@@@/cd32235"
      iex> ciphertext = FF3_1.encrypt!(ctx, tweak, plaintext)
      iex> ^plaintext = FF3_1.decrypt!(ctx, tweak, ciphertext)

  #### Unicode support

      iex> key = :crypto.strong_rand_bytes(32)
      iex> alphabet = "🌕🌖🌗🌘🌑🌒🌓🌔"
      iex> {:ok, ctx} = FF3_1.new_ctx(key, alphabet)
      iex> tweak = <<0::56>>
      iex> plaintext = "🌖🌕🌘🌑🌓🌗🌔🌒🌒🌒🌒"
      iex> ciphertext = FF3_1.encrypt!(ctx, tweak, plaintext)
      iex> ^plaintext = FF3_1.decrypt!(ctx, tweak, ciphertext)

  """

  import Bitwise

  alias FF3_1.FFX

  require Record

  ## API Types

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
    :iform_ctx,
    :minlen,
    :maxlen
  ])

  @opaque ctx ::
            record(:fpe_ff3_1_ctx,
              k: FFX.key(),
              codec: FFX.Codec.t(),
              iform_ctx: FFX.IntermediateForm.ctx(),
              minlen: pos_integer,
              maxlen: pos_integer
            )

  ## API

  @doc """
  Validates arguments and creates a context used for both encryption and decryption.
  """
  @spec new_ctx(k, radix | alphabet) :: {:ok, ctx} | {:error, term}
        when k: FFX.key()
  def new_ctx(k, radix_or_alphabet) do
    alias FFX.Codec
    alias FFX.IntermediateForm

    with :ok <- validate_key(k),
         {:ok, codec} <- validate_radix_or_alphabet(radix_or_alphabet),
         radix = Codec.radix(codec),
         iform_ctx = IntermediateForm.new_ctx(radix),
         {:ok, minlen} <- calculate_minlen(radix),
         {:ok, maxlen} <- calculate_maxlen(minlen, radix) do
      {:ok,
       fpe_ff3_1_ctx(
         k: k,
         codec: codec,
         iform_ctx: iform_ctx,
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

  Returns encrypted numerical string `vY` in base `radix` and **of length equal to `vX`**.

  Minimum and maximum length of `vX` depend on radix, as defined by the spec.
  """
  @spec encrypt!(ctx, tweak, vX) :: vY
        when vX: String.t(), vY: String.t()
  def encrypt!(ctx, t, vX) do
    {:ok, vY} = do_encrypt_or_decrypt(ctx, t, vX, _enc = true)
    vY
  end

  @doc """
  Decrypts encrypted numerical string `vX` in base `radix` using `ctx` and 7-byte `tweak`.

  Returns plaintext numerical string `vY` in base `radix` and **of length equal to `vX`**.

  Minimum and maximum length of `vX` depend on radix, as defined by the spec.
  """
  @spec decrypt!(ctx, t, vX) :: vY
        when t: tweak, vX: String.t(), vY: String.t()
  def decrypt!(ctx, t, vX) do
    {:ok, vY} = do_encrypt_or_decrypt(ctx, t, vX, _enc = false)
    vY
  end

  @doc """
  Returns a `ctx`'s `FF3_1.FFX.Codec`, should you wish to manipulate
  or prepare encryption and decryption inputs.
  """
  @spec codec(ctx) :: FFX.codec()
  def codec(fpe_ff3_1_ctx(codec: codec)), do: codec

  @doc """
  Returns a `ctx`'s domain constraints.
  """
  @spec domain_constraints(ctx) :: %{minlen: pos_integer, maxlen: pos_integer}
  def domain_constraints(fpe_ff3_1_ctx(minlen: minlen, maxlen: maxlen)) do
    %{minlen: minlen, maxlen: maxlen}
  end

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
    alias FF3_1.FFX.Codec

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
      {:error, {:invalid_radix, radix, :less_than_minimum, @min_radix}}
    else
      {:error, {:invalid_radix, radix, :you_need_to_provide_the_alphabet}}
    end
  end

  defp validate_custom_alphabet(alphabet) when is_binary(alphabet) do
    alias FF3_1.FFX.Codec

    ordered_graphemes = String.graphemes(alphabet)
    unique_graphemes = Enum.uniq(ordered_graphemes)
    nr_of_symbols = length(ordered_graphemes)
    nr_of_unique_symbols = length(unique_graphemes)

    cond do
      nr_of_symbols > @max_radix ->
        {:error, {:alphabet_exceeds_max_radix, @max_radix}}

      nr_of_symbols == nr_of_unique_symbols ->
        Codec.Custom.new(ordered_graphemes)

      nr_of_symbols > nr_of_unique_symbols ->
        repeated_symbols = ordered_graphemes -- unique_graphemes
        {:error, {:alphabet_has_repeated_symbols, repeated_symbols}}
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
         :ok <- validate_tweak(t),
         fpe_ff3_1_ctx(k: k, codec: codec, iform_ctx: iform_ctx) = ctx,
         {:ok, even_m, odd_m, vA, vB, even_vW, odd_vW} <-
           setup_encrypt_or_decrypt_vars(codec, t, vX) do
      vY =
        if enc do
          do_encrypt_rounds!(
            _i = 0,
            k,
            codec,
            iform_ctx,
            even_m,
            odd_m,
            vA,
            vB,
            even_vW,
            odd_vW
          )
        else
          do_decrypt_rounds!(
            _i = 7,
            k,
            codec,
            iform_ctx,
            odd_m,
            even_m,
            vA,
            vB,
            odd_vW,
            even_vW
          )
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

  defp setup_encrypt_or_decrypt_vars(codec, t, vX) do
    alias FFX.Codec
    alias FFX.IntermediateForm

    n = String.length(vX)

    # 1. Let u = ceil(n/2); v = n - u
    u = div(n, 2) + (n &&& 1)
    v = n - u

    # 2. Let A = X[1..u]; B = X[u + 1..n]
    {vA_str, vB_str} = String.split_at(vX, u)

    with {:ok, vA} <- Codec.string_to_int(codec, vA_str),
         {:ok, vB} <- Codec.string_to_int(codec, vB_str) do
      # 3. Let T_L = T[0..27] || O⁴ and T_R = T[32..55] || T[28..31] || O⁴
      <<t_left::bits-size(28), t_middle::bits-size(4), t_right::bits-size(24)>> = t
      <<vT_L::bytes>> = <<t_left::bits, 0::4>>
      <<vT_R::bytes>> = <<t_right::bits, t_middle::bits, 0::4>>

      # 4.i. If i is even, let m = u and W = T_R, else let m = v and W = T_L
      even_m = u
      odd_m = v
      even_vW = vT_R
      odd_vW = vT_L
      {:ok, even_m, odd_m, vA, vB, even_vW, odd_vW}
    else
      {:error, reason} ->
        {:error, {:invalid_input, vX, reason}}
    end
  end

  defp do_encrypt_rounds!(i, k, codec, iform_ctx, m, other_m, vA, vB, vW, other_vW) when i < 8 do
    alias FFX.Codec
    alias FFX.IntermediateForm

    radix = Codec.radix(codec)

    # 4.ii. Let P = W ⊕ [i]⁴ || [NUM_radix(REV(B))]¹²
    vP_W_xor_i = :crypto.exor(vW, <<i::unsigned-size(4)-unit(8)>>)
    vP_num_radix_rev_B = IntermediateForm.left_pad_and_revert(iform_ctx, vB, other_m)
    vP = <<vP_W_xor_i::bytes, vP_num_radix_rev_B::unsigned-size(12)-unit(8)>>

    ## 4.iii. Let S = REVB(CIPH_REVB(K)(REVB(P)))
    vS_revb_P = FFX.revb(vP)
    vS_revb_K = FFX.revb(k)
    vS_ciph_etc = ciph(vS_revb_K, vS_revb_P)
    vS = FFX.revb(vS_ciph_etc)

    ## 4.iv. Let y = NUM(S)
    y = FFX.num(vS)

    ## 4.v. Let c = (NUM_radix(REV(A)) + y) mod (radix**m)
    c_num_radix_rev_A = IntermediateForm.left_pad_and_revert(iform_ctx, vA, m)
    c_num_radix_rev_A_plus_y = c_num_radix_rev_A + y
    c = rem(c_num_radix_rev_A_plus_y, Integer.pow(radix, m))

    ## 4.vi. Let C = REV(STR_m_radix(c))
    vC = IntermediateForm.left_pad_and_revert(iform_ctx, c, m)

    ## 4.vii. Let A = B
    vA = vB

    ## 4.viii. let B = C
    vB = vC

    do_encrypt_rounds!(
      i + 1,
      k,
      codec,
      iform_ctx,
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
  defp do_encrypt_rounds!(8 = _i, _k, codec, _iform_ctx, m, other_m, vA, vB, _vW, _other_vW) do
    alias FFX.Codec
    alias FFX.IntermediateForm
    ## 5. Return A || B
    vA_str = Codec.int_to_padded_string(codec, m, vA)
    vB_str = Codec.int_to_padded_string(codec, other_m, vB)
    <<vA_str::bytes, vB_str::bytes>>
  end

  defp do_decrypt_rounds!(i, k, codec, iform_ctx, m, other_m, vA, vB, vW, other_vW) when i >= 0 do
    alias FFX.Codec
    alias FFX.IntermediateForm

    radix = Codec.radix(codec)

    ## 4.ii. Let P = W ⊕ [i]⁴ || [NUM_radix(REV(A))]¹²
    vP_W_xor_i = :crypto.exor(vW, <<i::unsigned-size(4)-unit(8)>>)
    vP_num_radix_rev_A = IntermediateForm.left_pad_and_revert(iform_ctx, vA, other_m)
    vP = <<vP_W_xor_i::bytes, vP_num_radix_rev_A::unsigned-size(12)-unit(8)>>

    ## 4.iii. Let S = REVB(CIPH_REVB(K)(REVB(P)))
    vS_revb_P = FFX.revb(vP)
    vS_revb_K = FFX.revb(k)
    vS_ciph_etc = ciph(vS_revb_K, vS_revb_P)
    vS = FFX.revb(vS_ciph_etc)

    ## 4.iv. Let y = NUM(S)
    y = FFX.num(vS)

    ## 4.v. Let c = (NUM_radix(REV(B)) - y) mod (radix**m)
    c_num_radix_rev_B = IntermediateForm.left_pad_and_revert(iform_ctx, vB, m)
    c_num_radix_rev_B_minus_y = c_num_radix_rev_B - y
    c = Integer.mod(c_num_radix_rev_B_minus_y, Integer.pow(radix, m))

    ## 4.vi. Let C = REV(STR_m_radix(c))
    vC = IntermediateForm.left_pad_and_revert(iform_ctx, c, m)

    ## 4.vii. Let B = A
    vB = vA

    ## 4.viii. Let A = C
    vA = vC

    do_decrypt_rounds!(
      i - 1,
      k,
      codec,
      iform_ctx,
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
  defp do_decrypt_rounds!(-1 = _i, _k, codec, _iform_ctx, m, other_m, vA, vB, _vW, _other_vW) do
    alias FF3_1.FFX.Codec
    ## 5. Return A || B
    vA_str = Codec.int_to_padded_string(codec, other_m, vA)
    vB_str = Codec.int_to_padded_string(codec, m, vB)
    <<vA_str::bytes, vB_str::bytes>>
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
