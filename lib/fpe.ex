defmodule FPE do
  @moduledoc """
  Format-preserving encryption (FPE) for Elixir.

  FPE encrypts a numerical string into another of the **same length over the
  same alphabet**, which is useful to e.g. store an encrypted credit card
  number in a field that only accepts credit-card-shaped values, and other
  suchlike applications.

  `FPE` is the entry point. It wraps a concrete FPE mode behind a single API —
  `new/2` (or `new/3`), `encrypt!/3`, `decrypt!/3`.

  By default it uses **FF1** (`FPE.FF1`), the only mode approved by NIST in
  [SP 800-38Gr1 2pd](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38Gr1.2pd.pdf).
  The examples below all use the default. To pick a mode explicitly, pass it as
  the **second argument** to `new/3`:

  * `:ff1` — the FF1 mode (default; variable-length tweak).
  * `:ff3_1` — the FF3-1 mode (fixed **7-byte** tweak). ⚠️ NIST removed FF3-1;
    use it only for interop with existing data. See `FPE.FF3_1`.

  > #### Mode-specific rules {: .info}
  >
  > The **tweak size** and the **length constraints** on inputs depend on the
  > mode. FF1 accepts a variable-length tweak (it may even be empty); see
  > `FPE.FF1`. FF3-1 uses a fixed 7-byte (56-bit) tweak; see `FPE.FF3_1`.

  # How to use

  ## Context

  We start by creating a context with `new/2`, passing it a cryptographic key
  and a radix. With no mode given, the default (FF1) is used.

      iex> key = :crypto.strong_rand_bytes(32)
      iex> {:ok, _ctx} = FPE.new(key, _radix = 10)

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
  mode: FF1 (the default) accepts a variable-length byte string, so the 7-byte
  tweak below is just one valid choice.

      iex> key = :crypto.strong_rand_bytes(32)
      iex> {:ok, ctx} = FPE.new(key, _radix = 10)
      iex> tweak = "dev.env"
      iex> plaintext = "34436524"
      iex> ciphertext = FPE.encrypt!(ctx, tweak, plaintext)
      iex> ^plaintext = FPE.decrypt!(ctx, tweak, ciphertext)

  ## Leading zeroes matter

  ⚠️ Keep in mind that **leading zeroes are significant**. Ciphertexts are always
  of equal length to their respective plaintexts, and vice-versa.

      iex> key = :crypto.strong_rand_bytes(32)
      iex> {:ok, ctx} = FPE.new(key, _radix = 10)
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
      iex> {:ok, ctx} = FPE.new(key, _radix = 10)
      iex> plaintext= "135522432"
      iex> tweak1 = "dev.env"
      iex> tweak2 = "prod.env"
      iex> ciphertext1 = FPE.encrypt!(ctx, tweak1, plaintext)
      iex> ciphertext2 = FPE.encrypt!(ctx, tweak2, plaintext)
      iex> ciphertext2 != ciphertext1

  ## Built-in alphabet

  For radix values between 2 and 36, if what `String.to_integer/2` produces is
  good enough, you only need to specify the `radix` when building your `ctx`.

  Both `plaintext` and `ciphertext` will be encoded in the chosen base.

  #### Base 8

      iex> key = :crypto.strong_rand_bytes(32)
      iex> {:ok, ctx} = FPE.new(key, _radix = 8)
      iex> tweak = <<0::56>>
      iex> plaintext = "34436524"
      iex> ciphertext = FPE.encrypt!(ctx, tweak, plaintext)
      iex> ^plaintext = FPE.decrypt!(ctx, tweak, ciphertext)

  #### Base 16

      iex> key = :crypto.strong_rand_bytes(32)
      iex> {:ok, ctx} = FPE.new(key, _radix = 16)
      iex> tweak = <<0::56>>
      iex> plaintext = "AFD093902C"
      iex> ciphertext = FPE.encrypt!(ctx, tweak, plaintext)
      iex> ^plaintext = FPE.decrypt!(ctx, tweak, ciphertext)

  #### Base 36

      iex> key = :crypto.strong_rand_bytes(32)
      iex> {:ok, ctx} = FPE.new(key, _radix = 36)
      iex> tweak = <<0::56>>
      iex> plaintext = "ZZZAFD093902CBZDE"
      iex> ciphertext = FPE.encrypt!(ctx, tweak, plaintext)
      iex> ^plaintext = FPE.decrypt!(ctx, tweak, ciphertext)

  ### Built-in alphabet: case insensitivity to input

  Even though the output of either `encrypt!/3` or `decrypt!/3` is
  upper case, any case is accepted as input.

      iex> key = :crypto.strong_rand_bytes(32)
      iex> radix = 16
      iex> {:ok, ctx} = FPE.new(key, radix)
      iex> tweak = <<0::56>>
      iex> input = "aBcDDFF01234eeEee"
      iex> _ciphertext = FPE.encrypt!(ctx, tweak, input)
      iex> _plaintext = FPE.decrypt!(ctx, tweak, input)

  ### Built-in alphabet: lower case

  If you want to use the built-in alphabet but desire lower case outputs, you
  can do it by declaring the alphabet when creating `ctx`.

      iex> key = :crypto.strong_rand_bytes(32)
      iex> alphabet = "0123456789abcdef" # radix 16
      iex> {:ok, ctx} = FPE.new(key, alphabet)
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
      iex> {:ok, ctx} = FPE.new(key, alphabet)
      iex> tweak = <<0::56>>
      iex> plaintext = "34534abcd32235"
      iex> ciphertext = FPE.encrypt!(ctx, tweak, plaintext)
      iex> ^plaintext = FPE.decrypt!(ctx, tweak, ciphertext)

  #### Base 40 with custom alphabet

      iex> key = :crypto.strong_rand_bytes(32)
      iex> alphabet = "0123456789abcdefghijklmnopqrstuvwxyz@#/*"
      iex> {:ok, ctx} = FPE.new(key, alphabet)
      iex> tweak = <<0::56>>
      iex> plaintext = "34534ab@@@@@/cd32235"
      iex> ciphertext = FPE.encrypt!(ctx, tweak, plaintext)
      iex> ^plaintext = FPE.decrypt!(ctx, tweak, ciphertext)

  #### Unicode support

      iex> key = :crypto.strong_rand_bytes(32)
      iex> alphabet = "🌕🌖🌗🌘🌑🌒🌓🌔"
      iex> {:ok, ctx} = FPE.new(key, alphabet)
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
      iex> {:ok, ctx} = FPE.new(key, codec)
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
      iex> {:ok, ctx} = FPE.new(key, codec)
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
      iex> {:ok, ctx} = FPE.new(key, codec)
      iex> tweak = <<0::56>>
      iex> input = 1234567
      iex> input_length = 10
      iex>
      iex> plaintext = %NoSymbols.NumString{value: input, length: input_length}
      iex> ciphertext = FPE.encrypt!(ctx, tweak, plaintext)
      iex> %NoSymbols.NumString{length: ^input_length} = ciphertext
      iex> ^plaintext = FPE.decrypt!(ctx, tweak, ciphertext)

  ## Choosing a mode

  Everything above uses the default mode, `:ff1`. To select a mode explicitly,
  pass it as the second argument to `new/3`. The only other mode is `:ff3_1`,
  which is **no longer NIST-approved** (see `FPE.FF3_1`) — reach for it only to
  interoperate with data that was already encrypted with FF3-1. It takes a
  fixed 7-byte tweak.

      iex> key = :crypto.strong_rand_bytes(32)
      iex> {:ok, ctx} = FPE.new(key, :ff3_1, _radix = 10)
      iex> tweak = <<0::56>>
      iex> plaintext = "34436524"
      iex> ciphertext = FPE.encrypt!(ctx, tweak, plaintext)
      iex> ^plaintext = FPE.decrypt!(ctx, tweak, ciphertext)

  """

  alias FPE.Algorithm
  alias FPE.FF1
  alias FPE.FF3_1
  alias FPE.FFX.Codec

  ## Constants

  @default_mode :ff1

  ## Types

  @enforce_keys [:algorithm, :codec]
  defstruct [:algorithm, :codec]

  @type t :: %__MODULE__{algorithm: Algorithm.t(), codec: Codec.t()}

  @typedoc "A supported FPE mode."
  @type mode :: :ff1 | :ff3_1

  @type key :: FPE.FFX.key()

  ## API

  def new!(key, mode \\ @default_mode, radix_or_alphabet_or_codec) do
    case new(key, mode, radix_or_alphabet_or_codec) do
      {:ok, fpe} ->
        fpe

      {:error, reason} ->
        raise "TODO proper exception: #{inspect(reason)}"
    end
  end

  def new(key, mode \\ @default_mode, radix_or_alphabet_or_codec) do
    with {:ok, codec} <- init_codec(radix_or_alphabet_or_codec),
         {:ok, algorithm} <- init_algorithm(mode, key, codec) do
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

  ## Convenience: `use FPE`

  @doc """
  Returns the `Supervisor` child spec for the module that `use FPE`.

  Implement it by calling the generated `child_spec/2` or `child_spec/3` with
  your key, mode, and radix/alphabet/codec — see the moduledoc.
  """
  @callback child_spec() :: Supervisor.child_spec()

  @doc """
  Places an `FPE` context under your supervision tree so that you can encrypt
  and decrypt without threading the context through every call.

  A module that `use FPE` gets:

    * a `child_spec/2` / `child_spec/3` builder and a `start_link/3`, backed by
      a uniquely named process holding the context in a `:persistent_term`;
    * `encrypt/2`, `encrypt!/2`, `decrypt/2`, `decrypt!/2` that retrieve the
      context transparently; plus `constraints/0`, `codec/0`, and `fpe/0`.

  You implement the `c:child_spec/0` callback declaring your configuration, and
  add `MyModule.child_spec()` to your supervision tree.

      defmodule MyApp.CardCipher do
        use FPE

        @impl true
        def child_spec do
          child_spec(fetch_key(), :ff3_1, _radix = 10)
        end

        defp fetch_key, do: Application.fetch_env!(:my_app, :fpe_key)
      end

      # in your application's supervision tree:
      children = [
        MyApp.CardCipher.child_spec(),
        # ...
      ]

      # then, anywhere:
      MyApp.CardCipher.encrypt!(tweak, "34436524")
  """
  defmacro __using__([]) do
    quote do
      @behaviour FPE

      @doc """
      Builds a `Supervisor` child spec for `#{inspect(__MODULE__)}`'s context.

      Call this from your `c:FPE.child_spec/0` implementation.
      """
      @spec child_spec(FPE.key(), FPE.mode(), term()) :: Supervisor.child_spec()
      def child_spec(key, mode \\ unquote(@default_mode), radix_or_alphabet_or_codec) do
        FPE.Agent.child_spec(
          __MODULE__,
          {__MODULE__, :start_link, [key, mode, radix_or_alphabet_or_codec]}
        )
      end

      @doc """
      Starts the process holding `#{inspect(__MODULE__)}`'s context.
      """
      @spec start_link(FPE.key(), FPE.mode(), term()) :: {:ok, pid} | {:error, term}
      def start_link(key, mode, radix_or_alphabet_or_codec) do
        FPE.Agent.start_link(
          __MODULE__,
          {&FPE.new/3, [key, mode, radix_or_alphabet_or_codec]}
        )
      end

      @doc "Like `FPE.encrypt/3`, retrieving `#{inspect(__MODULE__)}`'s context."
      def encrypt(tweak, plaintext), do: FPE.encrypt(fpe(), tweak, plaintext)

      @doc "Like `FPE.encrypt!/3`, retrieving `#{inspect(__MODULE__)}`'s context."
      def encrypt!(tweak, plaintext), do: FPE.encrypt!(fpe(), tweak, plaintext)

      @doc "Like `FPE.decrypt/3`, retrieving `#{inspect(__MODULE__)}`'s context."
      def decrypt(tweak, ciphertext), do: FPE.decrypt(fpe(), tweak, ciphertext)

      @doc "Like `FPE.decrypt!/3`, retrieving `#{inspect(__MODULE__)}`'s context."
      def decrypt!(tweak, ciphertext), do: FPE.decrypt!(fpe(), tweak, ciphertext)

      @doc "Returns this module's mode-specific constraints."
      def constraints do
        algorithm = fpe().algorithm
        algorithm.__struct__.constraints(algorithm)
      end

      @doc "Returns this module's `FPE.FFX.Codec`."
      def codec, do: fpe().codec

      @doc "Returns this module's `t:FPE.t/0`."
      @spec fpe() :: FPE.t()
      def fpe do
        case FPE.Agent.get(__MODULE__) do
          {:ok, fpe} ->
            fpe

          {:error, {:ctx_not_found_for_module, module}} ->
            raise "FPE context for #{inspect(module)} not found; " <>
                    "is it started under your supervision tree?"
        end
      end
    end
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

  defp init_algorithm(:ff1, key, codec) do
    FF1.new_ctx(key, codec)
  end

  defp init_algorithm(:ff3_1, key, codec) do
    FF3_1.new_ctx(key, codec)
  end

  defp init_algorithm(mode, _key, _codec) do
    {:error, {:unknown_mode, mode}}
  end
end
