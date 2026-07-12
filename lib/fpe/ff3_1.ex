# credo:disable-for-this-file Credo.Check.Readability.ModuleNames
# credo:disable-for-this-file Credo.Check.Readability.VariableNames
defmodule FPE.FF3_1 do
  @moduledoc """
  An implementation of the FF3-1 [format-preserving crypto
  (FPE)](https://en.wikipedia.org/wiki/Format-preserving_encryption) algorithm
  in Elixir.

  Numerical strings output by FPE have the same alphabet and length as the
  input, which is useful to e.g. save encrypted credit card numbers in storage
  that only accepts them in credit card number format, and other suchlike
  applications.

  This implementation conforms, as best as possible, to
  [Draft SP 800-38G Rev. 1](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38Gr1-draft.pdf)
  specified by NIST in their Cryptographic Standards.

  No official test vectors for FF3-1 exist as of the time of writing;
  many of the ones used in this library's test suite were copied almost verbatim
  from [ubiq-fpe-go](https://gitlab.com/ubiqsecurity/ubiq-fpe-go), an implementation
  of the FF1 and FF3-1 algorithms in Go.

  # How to use

  ## Context

  We start by creating a context with `new_ctx/2`, passing it a cryptographic
  key and a radix.

      iex> key = :crypto.strong_rand_bytes(32)
      iex> {:ok, _ctx} = FPE.FF3_1.new_ctx(key, _radix = 10)

  Keys can be:
  * 32 bytes long for AES-256
  * 24 bytes long for AES-192
  * 16 bytes long for AES-128

  Radix is an integer between 2 and 36. For larger radixes up to 65535, a
  custom alphabet is needed - more on that later.

  ## Encryption and decryption

  We're going to `FPE.encrypt!/3` our `plaintext` numerical string, in base 10,
  and get another of equal length, `ciphertext`, which we can `FPE.decrypt!/3`
  to get the `plaintext` back.

  A 7-byte `tweak` is required, which we'll handwave for now.

      iex> key = :crypto.strong_rand_bytes(32)
      iex> {:ok, ctx} = FPE.new(key, FPE.FF3_1, _radix = 10)
      iex> tweak = <<0::56>>
      iex> plaintext = "34436524"
      iex> ciphertext = FPE.encrypt!(ctx, tweak, plaintext)
      iex> ^plaintext = FPE.decrypt!(ctx, tweak, ciphertext)

  ## Leading zeroes matter

  ⚠️ Keep in mind that **leading zeroes are significant**. Ciphertexts are always
  of equal length to their respective plaintexts, and vice-versa.

      iex> key = :crypto.strong_rand_bytes(32)
      iex> {:ok, ctx} = FPE.new(key, FPE.FF3_1, _radix = 10)
      iex> tweak = <<0::56>>
      iex> plaintext1 =   "34436524"
      iex> plaintext2 = "0034436524"
      iex> ciphertext1 = FPE.encrypt!(ctx, tweak, plaintext1)
      iex> ciphertext2 = FPE.encrypt!(ctx, tweak, plaintext2)
      iex> false = (ciphertext2 == ciphertext1)
      iex> true = (String.length(ciphertext1) == String.length(plaintext1))
      iex> true = (String.length(ciphertext2) == String.length(plaintext2))

  ## Length constraints

  Numerical strings under FF3-1 are subject to minimum and maximum lengths.
  These constraints depend on the radix.

      iex> key = :crypto.strong_rand_bytes(32)
      iex> {:ok, ctx} = FPE.FF3_1.new_ctx(key, _radix = 10)
      iex> %{min_length: 6, max_length: 56} = FPE.FF3_1.constraints(ctx)

      iex> key = :crypto.strong_rand_bytes(32)
      iex> {:ok, ctx} = FPE.FF3_1.new_ctx(key, _radix = 16)
      iex> %{min_length: 5, max_length: 48} = FPE.FF3_1.constraints(ctx)

      iex> key = :crypto.strong_rand_bytes(32)
      iex> {:ok, ctx} = FPE.FF3_1.new_ctx(key, _radix = 2)
      iex> %{min_length: 20, max_length: 192} = FPE.FF3_1.constraints(ctx)

  `min_length` is required because, for any given radix, short enough numerical
  strings encompass too few possible values, rendering encryption ineffective
  under adversarial conditions. In other words: their domain is too small.

  `max_length` may be there - pure layman speculation - as an incentive for people
  to use regular crypto when working with large enough numbers. I didn't find
  the exact reasoning for it.

  ## Tweaks

  Tweaks may be public information used to produce different ciphertexts for
  the same plaintext.

  **They are important in FPE modes**, since FPE (the technique) may be used
  when the number of possible strings is somewhat small. In such a scenario,
  the tweak should vary with each instance of the encryption whenever possible.

      iex> key = :crypto.strong_rand_bytes(32)
      iex> {:ok, ctx} = FPE.new(key, FPE.FF3_1, _radix = 10)
      iex> plaintext= "135522432"
      iex> tweak1 = <<"dev.env">>
      iex> tweak2 = <<"prodenv">>
      iex> ciphertext1 = FPE.encrypt!(ctx, tweak1, plaintext)
      iex> ciphertext2 = FPE.encrypt!(ctx, tweak2, plaintext)
      iex> ciphertext2 != ciphertext1

  For an explanation and further examples, refer to Appendix C (page 20) of
  [the reference
  document](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38Gr1-draft.pdf).

  ## Built-in alphabet

  For radix values between 2 and 36, if what `String.to_integer/2` produces is
  good enough, you only need to specify the `radix` when building your `ctx`.

  Both `plaintext` and `ciphertext` will be encoded in the chosen base.

  #### Base 8

      iex> key = :crypto.strong_rand_bytes(32)
      iex> {:ok, ctx} = FPE.new(key, FPE.FF3_1, _radix = 8)
      iex> tweak = <<0::56>>
      iex> plaintext = "34436524"
      iex> ciphertext = FPE.encrypt!(ctx, tweak, plaintext)
      iex> ^plaintext = FPE.decrypt!(ctx, tweak, ciphertext)

  #### Base 16

      iex> key = :crypto.strong_rand_bytes(32)
      iex> {:ok, ctx} = FPE.new(key, FPE.FF3_1, _radix = 16)
      iex> tweak = <<0::56>>
      iex> plaintext = "AFD093902C"
      iex> ciphertext = FPE.encrypt!(ctx, tweak, plaintext)
      iex> ^plaintext = FPE.decrypt!(ctx, tweak, ciphertext)

  #### Base 36

      iex> key = :crypto.strong_rand_bytes(32)
      iex> {:ok, ctx} = FPE.new(key, FPE.FF3_1, _radix = 36)
      iex> tweak = <<0::56>>
      iex> plaintext = "ZZZAFD093902CBZDE"
      iex> ciphertext = FPE.encrypt!(ctx, tweak, plaintext)
      iex> ^plaintext = FPE.decrypt!(ctx, tweak, ciphertext)

  ### Built-in alphabet: case insensitivity to input

  Even though the output of either `FPE.encrypt!/3` or `FPE.decrypt!/3` is
  upper case, any case is accepted as input.

      iex> key = :crypto.strong_rand_bytes(32)
      iex> radix = 16
      iex> {:ok, ctx} = FPE.new(key, FPE.FF3_1, radix)
      iex> tweak = <<0::56>>
      iex> input = "aBcDDFF01234eeEee"
      iex> _ciphertext = FPE.encrypt!(ctx, tweak, input)
      iex> _plaintext = FPE.decrypt!(ctx, tweak, input)

  ### Built-in alphabet: lower case

  If you want to use the built-in alphabet but desire lower case outputs, you
  can do it by declaring the alphabet when creating `ctx`.

      iex> key = :crypto.strong_rand_bytes(32)
      iex> alphabet = "0123456789abcdef" # radix 16
      iex> {:ok, ctx} = FPE.new(key, FPE.FF3_1, alphabet)
      iex> tweak = <<0::56>>
      iex> input = "aBcDDFF01234eeEee"
      iex> ciphertext = FPE.encrypt!(ctx, tweak, input)
      iex> plaintext = FPE.decrypt!(ctx, tweak, input)
      iex> ^ciphertext = String.downcase(ciphertext)
      iex> ^plaintext = String.downcase(plaintext)

  ### Custom alphabets

  Whether you need a radix larger than 36, or use symbols other than 0-9, A-Z
  in your numerical strings (or use such symbols in a different order), custom
  alphabets are supported.

  Note that custom alphabets are **case sensitive** but norm insensitive.
  The reasoning behind this can be found under `FPE.FFX.Codec.Custom`.

  Each symbol must be a single Unicode scalar that stands on its own as one
  visual unit; alphabets are validated at construction. See
  `FPE.FFX.Codec.Custom` for the exact rules and the guarantees they buy.

  #### Base 20 with custom alphabet

      iex> key = :crypto.strong_rand_bytes(32)
      iex> alphabet = "abcdefghij0123456789"
      iex> {:ok, ctx} = FPE.new(key, FPE.FF3_1, alphabet)
      iex> tweak = <<0::56>>
      iex> plaintext = "34534abcd32235"
      iex> ciphertext = FPE.encrypt!(ctx, tweak, plaintext)
      iex> ^plaintext = FPE.decrypt!(ctx, tweak, ciphertext)

  #### Base 40 with custom alphabet

      iex> key = :crypto.strong_rand_bytes(32)
      iex> alphabet = "0123456789abcdefghijklmnopqrstuvwxyz@#/*"
      iex> {:ok, ctx} = FPE.new(key, FPE.FF3_1, alphabet)
      iex> tweak = <<0::56>>
      iex> plaintext = "34534ab@@@@@/cd32235"
      iex> ciphertext = FPE.encrypt!(ctx, tweak, plaintext)
      iex> ^plaintext = FPE.decrypt!(ctx, tweak, ciphertext)

  #### Unicode support

      iex> key = :crypto.strong_rand_bytes(32)
      iex> alphabet = "🌕🌖🌗🌘🌑🌒🌓🌔"
      iex> {:ok, ctx} = FPE.new(key, FPE.FF3_1, alphabet)
      iex> tweak = <<0::56>>
      iex> plaintext = "🌖🌕🌘🌑🌓🌗🌔🌒🌒🌒🌒"
      iex> ciphertext = FPE.encrypt!(ctx, tweak, plaintext)
      iex> ^plaintext = FPE.decrypt!(ctx, tweak, ciphertext)

  ### No alphabet

  If you wish to handle translation of integers into and from symbols yourself,
  you can use `FPE.FFX.Codec.NoSymbols`. Encryption and decryption functions
  will receive, and return, integer values with a length tag.

  #### Radix 10

      iex> alias FPE.FFX.Codec.NoSymbols
      iex> key = :crypto.strong_rand_bytes(32)
      iex> radix = 10
      iex> {:ok, codec} = NoSymbols.new(radix)
      iex> {:ok, ctx} = FPE.new(key, FPE.FF3_1, codec)
      iex> tweak = <<0::56>>
      iex> input = 1234567
      iex> input_length = 10
      iex>
      iex> plaintext = %NoSymbols.NumString{value: input, length: input_length}
      iex> ciphertext = FPE.encrypt!(ctx, tweak, plaintext)
      iex> %NoSymbols.NumString{length: ^input_length} = ciphertext
      iex> ^plaintext = FPE.decrypt!(ctx, tweak, ciphertext)

  #### Radix 40

      iex> alias FPE.FFX.Codec.NoSymbols
      iex> key = :crypto.strong_rand_bytes(32)
      iex> radix = 40
      iex> {:ok, codec} = NoSymbols.new(radix)
      iex> {:ok, ctx} = FPE.new(key, FPE.FF3_1, codec)
      iex> tweak = <<0::56>>
      iex> input = 1234567
      iex> input_length = 10
      iex>
      iex> plaintext = %NoSymbols.NumString{value: input, length: input_length}
      iex> ciphertext = FPE.encrypt!(ctx, tweak, plaintext)
      iex> %NoSymbols.NumString{length: ^input_length} = ciphertext
      iex> ^plaintext = FPE.decrypt!(ctx, tweak, ciphertext)

  #### Radix 500

      iex> alias FPE.FFX.Codec.NoSymbols
      iex> key = :crypto.strong_rand_bytes(32)
      iex> radix = 500
      iex> {:ok, codec} = NoSymbols.new(radix)
      iex> {:ok, ctx} = FPE.new(key, FPE.FF3_1, codec)
      iex> tweak = <<0::56>>
      iex> input = 1234567
      iex> input_length = 10
      iex>
      iex> plaintext = %NoSymbols.NumString{value: input, length: input_length}
      iex> ciphertext = FPE.encrypt!(ctx, tweak, plaintext)
      iex> %NoSymbols.NumString{length: ^input_length} = ciphertext
      iex> ^plaintext = FPE.decrypt!(ctx, tweak, ciphertext)

  #### Radix 65535

      iex> alias FPE.FFX.Codec.NoSymbols
      iex> key = :crypto.strong_rand_bytes(32)
      iex> radix = 65535
      iex> {:ok, codec} = NoSymbols.new(radix)
      iex> {:ok, ctx} = FPE.new(key, FPE.FF3_1, codec)
      iex> tweak = <<0::56>>
      iex> input = 1234567
      iex> input_length = 10
      iex>
      iex> plaintext = %NoSymbols.NumString{value: input, length: input_length}
      iex> ciphertext = FPE.encrypt!(ctx, tweak, plaintext)
      iex> %NoSymbols.NumString{length: ^input_length} = ciphertext
      iex> ^plaintext = FPE.decrypt!(ctx, tweak, ciphertext)

  """

  alias FPE.Algorithm
  alias FPE.FFX
  alias FPE.FFX.Codec

  ## API Types

  @type key :: FFX.key()
  @type codec :: Codec.t()
  @type numerical_string :: FFX.numerical_string()

  # 5.2, FF3-1 requirements
  @min_radix 2
  @max_radix 0xFFFF
  @type radix :: 2..0xFFFF
  @type alphabet :: <<_::16, _::_*8>>

  # 5.2, Algorithm 9: FF3.Encrypt(K, T, X)
  @type tweak :: <<_::56>>

  @type constraints :: %{min_length: pos_integer, max_length: pos_integer}

  @enforce_keys [
    :key,
    :codec,
    :iform_ctx,
    :min_length,
    :max_length
  ]
  defstruct [
    :key,
    :codec,
    :iform_ctx,
    :min_length,
    :max_length
  ]

  @type ctx ::
          %__MODULE__{
            key: key,
            codec: codec,
            iform_ctx: FFX.IntermediateForm.ctx(),
            min_length: pos_integer,
            max_length: pos_integer
          }

  ## API

  @doc """
  Validates arguments and creates a context used for both encryption and decryption.
  """
  @spec new_ctx(key, Codec.t()) :: {:ok, ctx} | {:error, term}
  def new_ctx(key, codec) do
    alias FFX.IntermediateForm

    with :ok <- validate_key(key),
         radix = Codec.radix(codec),
         :ok <- validate_radix(radix),
         iform_ctx = IntermediateForm.new_ctx(radix),
         {:ok, min_length} <- calculate_min_length(radix),
         {:ok, max_length} <- calculate_max_length(min_length, radix) do
      {:ok,
       %__MODULE__{
         key: key,
         codec: codec,
         iform_ctx: iform_ctx,
         min_length: min_length,
         max_length: max_length
       }}
    else
      {:error, _} = error ->
        error
    end
  end

  @doc """
  Returns a `ctx`'s `FPE.FFX.Codec`, should you wish to further manipulate or
  prepare encryption and decryption inputs or outputs.
  """
  @spec codec(ctx) :: codec
  def codec(%__MODULE__{codec: codec}), do: codec

  @doc """
  Returns a `ctx`'s [constraints](#module-length-constraints).
  """
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
        {:error, {:invalid_radix, {radix, :less_than_minimum, @min_radix}}}

      radix > @max_radix ->
        {:error, {:invalid_radix, {radix, :more_than_maximum, @max_radix}}}

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
    def do_encrypt_or_decrypt(ctx, t, vX, enc) do
      with {:ok, vX_length, vX} <- validate_enc_or_dec_input(ctx, vX),
           :ok <- validate_tweak(t),
           %FPE.FF3_1{key: key, codec: codec, iform_ctx: iform_ctx} = ctx,
           {:ok, even_m, odd_m, vA, vB, even_vW, odd_vW} <-
             setup_encrypt_or_decrypt_vars(codec, t, vX, vX_length) do
        vY =
          if enc do
            do_encrypt_rounds!(
              _i = 0,
              key,
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
              key,
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

    defp validate_enc_or_dec_input(ctx, vX) do
      %FPE.FF3_1{codec: codec, min_length: min_length, max_length: max_length} = ctx

      case Codec.normalize_input(codec, vX) do
        {:ok, valid_length, normalized_vX} when valid_length in min_length..max_length//1 ->
          {:ok, valid_length, normalized_vX}

        {:ok, _invalid_length, _} ->
          {:error, "Invalid input not between #{min_length} and #{max_length} symbols long: #{inspect(vX)}"}

        {:error, reason} ->
          {:error, {:invalid_input, reason}}
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

    defp setup_encrypt_or_decrypt_vars(codec, t, vX, vX_length) do
      alias FFX.IntermediateForm

      n = vX_length

      # 1. Let u = ceil(n/2); v = n - u
      u = div(n + 1, 2)
      v = n - u

      # 2. Let A = X[1..u]; B = X[u + 1..n]
      {vA_str, vB_str} = Codec.split_numerical_string_at(codec, vX, u)

      with {:ok, vA} <- Codec.numerical_string_to_int(codec, vA_str),
           {:ok, vB} <- Codec.numerical_string_to_int(codec, vB_str) do
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

    # credo:disable-for-next-line Credo.Check.Refactor.FunctionArity
    defp do_encrypt_rounds!(i, key, codec, iform_ctx, m, other_m, vA, vB, vW, other_vW) when i < 8 do
      alias FFX.IntermediateForm

      radix = Codec.radix(codec)

      # 4.ii. Let P = W ⊕ [i]⁴ || [NUM_radix(REV(B))]¹²
      vP_W_xor_i = :crypto.exor(vW, <<i::unsigned-size(4)-unit(8)>>)
      vP_num_radix_rev_B = IntermediateForm.left_pad_and_revert(iform_ctx, vB, other_m)
      vP = <<vP_W_xor_i::bytes, vP_num_radix_rev_B::unsigned-size(12)-unit(8)>>

      ## 4.iii. Let S = REVB(CIPH_REVB(K)(REVB(P)))
      vS_revb_P = FFX.revb(vP)
      vS_revb_K = FFX.revb(key)
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
        key,
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
    defp do_encrypt_rounds!(8 = _i, _key, codec, _iform_ctx, m, other_m, vA, vB, _vW, _other_vW) do
      alias FFX.IntermediateForm
      ## 5. Return A || B
      vA_str = Codec.int_to_padded_numerical_string(codec, vA, m)
      vB_str = Codec.int_to_padded_numerical_string(codec, vB, other_m)
      Codec.concat_numerical_strings(codec, vA_str, vB_str)
    end

    # credo:disable-for-next-line Credo.Check.Refactor.FunctionArity
    defp do_decrypt_rounds!(i, key, codec, iform_ctx, m, other_m, vA, vB, vW, other_vW) when i >= 0 do
      alias FFX.IntermediateForm

      radix = Codec.radix(codec)

      ## 4.ii. Let P = W ⊕ [i]⁴ || [NUM_radix(REV(A))]¹²
      vP_W_xor_i = :crypto.exor(vW, <<i::unsigned-size(4)-unit(8)>>)
      vP_num_radix_rev_A = IntermediateForm.left_pad_and_revert(iform_ctx, vA, other_m)
      vP = <<vP_W_xor_i::bytes, vP_num_radix_rev_A::unsigned-size(12)-unit(8)>>

      ## 4.iii. Let S = REVB(CIPH_REVB(K)(REVB(P)))
      vS_revb_P = FFX.revb(vP)
      vS_revb_K = FFX.revb(key)
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
        key,
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
    defp do_decrypt_rounds!(-1 = _i, _key, codec, _iform_ctx, m, other_m, vA, vB, _vW, _other_vW) do
      ## 5. Return A || B
      vA_str = Codec.int_to_padded_numerical_string(codec, vA, other_m)
      vB_str = Codec.int_to_padded_numerical_string(codec, vB, m)
      Codec.concat_numerical_strings(codec, vA_str, vB_str)
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
