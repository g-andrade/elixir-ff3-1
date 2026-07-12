defmodule FPE do
  @moduledoc """
  Format-preserving encryption (FPE) for Elixir.

  FPE encrypts a numerical string into another of the **same length over the
  same alphabet**, which is useful to e.g. store an encrypted credit card
  number in a field that only accepts credit-card-shaped values, and other
  suchlike applications.

  `FPE` is the entry point. It wraps a concrete algorithm behind a single API —
  `new/3`, `encrypt!/3`, `decrypt!/3` — dispatching to the algorithm you choose:

  * `FPE.FF3_1` — the FF3-1 mode (fixed **7-byte** tweak).
  * `FPE.FF1` — the FF1 mode (variable-length tweak).

  The examples below use FF3-1. Pass `FPE.FF1` instead to use FF1, or omit the
  module to use the default (`FPE.FF1`).

  > #### Algorithm-specific rules {: .info}
  >
  > The **tweak size** and the **length constraints** on inputs depend on the
  > algorithm. FF3-1 uses a 7-byte (56-bit) tweak; see `FPE.FF3_1` for its
  > length constraints. FF1 supports variable-length tweaks; see `FPE.FF1`.

  # How to use

  ## Context

  We start by creating a context with `new/3`, passing it a cryptographic key,
  the algorithm module, and a radix.

      iex> key = :crypto.strong_rand_bytes(32)
      iex> {:ok, _ctx} = FPE.new(key, FPE.FF3_1, _radix = 10)

  Keys can be:
  * 32 bytes long for AES-256
  * 24 bytes long for AES-192
  * 16 bytes long for AES-128

  Radix is an integer between 2 and 36. For larger radixes up to 65535, a
  custom alphabet is needed - more on that later.

  ## Encryption and decryption

  We're going to `encrypt!/3` our `plaintext` numerical string, in base 10,
  and get another of equal length, `ciphertext`, which we can `decrypt!/3`
  to get the `plaintext` back.

  A `tweak` is required, which we'll handwave for now. Its size depends on the
  algorithm (7 bytes for FF3-1).

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

  Even though the output of either `encrypt!/3` or `decrypt!/3` is
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
  alias FPE.FF1
  alias FPE.FFX.Codec

  ## Constants

  @default_module FF1

  ## Types

  @enforce_keys [:algorithm, :codec]
  defstruct [:algorithm, :codec]

  @type t :: %__MODULE__{algorithm: Algorithm.t(), codec: Codec.t()}

  ## API

  def new!(key, module \\ @default_module, radix_or_alphabet_or_codec) do
    case new(key, module, radix_or_alphabet_or_codec) do
      {:ok, fpe} ->
        fpe

      {:error, reason} ->
        raise "TODO proper exception: #{inspect(reason)}"
    end
  end

  def new(key, module \\ @default_module, radix_or_alphabet_or_codec) do
    with {:ok, codec} <- init_codec(radix_or_alphabet_or_codec),
         {:ok, algorithm} <- module.new_ctx(key, codec) do
      fpe = %__MODULE__{
        algorithm: algorithm,
        codec: codec
      }

      {:ok, fpe}
    else
      {:error, _} = error ->
        error
    end
  end

  def encrypt!(fpe, tweak, plaintext) do
    case encrypt(fpe, tweak, plaintext) do
      {:ok, ciphertext} ->
        ciphertext

      {:error, reason} ->
        raise "TODO proper exception: #{inspect(reason)}"
    end
  end

  def encrypt(%__MODULE__{algorithm: algorithm}, tweak, plaintext) do
    Algorithm.do_encrypt_or_decrypt(algorithm, tweak, plaintext, true)
  end

  def decrypt!(fpe, tweak, plaintext) do
    case decrypt(fpe, tweak, plaintext) do
      {:ok, ciphertext} ->
        ciphertext

      {:error, reason} ->
        raise "TODO proper exception: #{inspect(reason)}"
    end
  end

  def decrypt(%__MODULE__{algorithm: algorithm}, tweak, plaintext) do
    Algorithm.do_encrypt_or_decrypt(algorithm, tweak, plaintext, false)
  end

  ## Internal

  defp init_codec(%{__struct__: _} = codec) do
    {:ok, codec}
  end

  defp init_codec(radix_or_alphabet) do
    case Codec.Builtin.maybe_new(radix_or_alphabet) do
      {:ok, _} = success ->
        success

      nil when is_binary(radix_or_alphabet) ->
        case Codec.Custom.new(radix_or_alphabet) do
          {:ok, _} = success ->
            success

          {:error, _} = error ->
            error
        end

      nil when is_integer(radix_or_alphabet) ->
        {:error, {:invalid_radix, {radix_or_alphabet, :you_need_to_provide_either_an_alphabet_or_a_codec}}}
    end
  end
end
