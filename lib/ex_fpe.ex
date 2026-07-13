defmodule ExFPE do
  @moduledoc """
  Format-preserving encryption (FPE) for Elixir.

  ExFPE encrypts a numerical string into another of the **same length over the
  same alphabet**, which is useful to e.g. store an encrypted credit card
  number in a field that only accepts credit-card-shaped values, and other
  suchlike applications.

  `ExFPE` is the entry point. It wraps a concrete FPE mode behind a single API —
  `new/2` (or `new/3`), `encrypt!/3`, `decrypt!/3`.

  By default it uses **FF1** (`ExFPE.FF1`), the only mode approved by NIST in
  [SP 800-38Gr1 2pd](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38Gr1.2pd.pdf).
  The examples below all use the default. To pick a mode explicitly, pass it as
  the **second argument** to `new/3`:

  * `:ff1` — the FF1 mode (default; variable-length tweak).
  * `:ff3_1` — the FF3-1 mode (fixed **7-byte** tweak). ⚠️ NIST removed FF3-1;
    use it only for interop with existing data. See `ExFPE.FF3_1`.

  > #### Mode-specific rules {: .info}
  >
  > The **tweak size** and the **length constraints** on inputs depend on the
  > mode. FF1 accepts a variable-length tweak (it may even be empty); see
  > `ExFPE.FF1`. FF3-1 uses a fixed 7-byte (56-bit) tweak; see `ExFPE.FF3_1`.

  # How to use

  ## Context

  We start by creating a context with `new/2`, passing it a cryptographic key
  and a radix. With no mode given, the default (FF1) is used.

      iex> key = :crypto.strong_rand_bytes(32)
      iex> {:ok, _ctx} = ExFPE.new(key, _radix = 10)

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
      iex> {:ok, ctx} = ExFPE.new(key, _radix = 10)
      iex> tweak = "dev.env"
      iex> plaintext = "34436524"
      iex> ciphertext = ExFPE.encrypt!(ctx, tweak, plaintext)
      iex> ^plaintext = ExFPE.decrypt!(ctx, tweak, ciphertext)

  ## Leading zeroes matter

  ⚠️ Keep in mind that **leading zeroes are significant**. Ciphertexts are always
  of equal length to their respective plaintexts, and vice-versa.

      iex> key = :crypto.strong_rand_bytes(32)
      iex> {:ok, ctx} = ExFPE.new(key, _radix = 10)
      iex> tweak = <<0::56>>
      iex> plaintext1 =   "34436524"
      iex> plaintext2 = "0034436524"
      iex> ciphertext1 = ExFPE.encrypt!(ctx, tweak, plaintext1)
      iex> ciphertext2 = ExFPE.encrypt!(ctx, tweak, plaintext2)
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
      iex> {:ok, ctx} = ExFPE.new(key, _radix = 10)
      iex> plaintext= "135522432"
      iex> tweak1 = "dev.env"
      iex> tweak2 = "prod.env"
      iex> ciphertext1 = ExFPE.encrypt!(ctx, tweak1, plaintext)
      iex> ciphertext2 = ExFPE.encrypt!(ctx, tweak2, plaintext)
      iex> ciphertext2 != ciphertext1

  ## Built-in alphabet

  For radix values between 2 and 36, if what `String.to_integer/2` produces is
  good enough, you only need to specify the `radix` when building your `ctx`.

  Both `plaintext` and `ciphertext` will be encoded in the chosen base.

  #### Base 8

      iex> key = :crypto.strong_rand_bytes(32)
      iex> {:ok, ctx} = ExFPE.new(key, _radix = 8)
      iex> tweak = <<0::56>>
      iex> plaintext = "34436524"
      iex> ciphertext = ExFPE.encrypt!(ctx, tweak, plaintext)
      iex> ^plaintext = ExFPE.decrypt!(ctx, tweak, ciphertext)

  #### Base 16

      iex> key = :crypto.strong_rand_bytes(32)
      iex> {:ok, ctx} = ExFPE.new(key, _radix = 16)
      iex> tweak = <<0::56>>
      iex> plaintext = "AFD093902C"
      iex> ciphertext = ExFPE.encrypt!(ctx, tweak, plaintext)
      iex> ^plaintext = ExFPE.decrypt!(ctx, tweak, ciphertext)

  #### Base 36

      iex> key = :crypto.strong_rand_bytes(32)
      iex> {:ok, ctx} = ExFPE.new(key, _radix = 36)
      iex> tweak = <<0::56>>
      iex> plaintext = "ZZZAFD093902CBZDE"
      iex> ciphertext = ExFPE.encrypt!(ctx, tweak, plaintext)
      iex> ^plaintext = ExFPE.decrypt!(ctx, tweak, ciphertext)

  ### Built-in alphabet: case insensitivity to input

  Even though the output of either `encrypt!/3` or `decrypt!/3` is
  upper case, any case is accepted as input.

      iex> key = :crypto.strong_rand_bytes(32)
      iex> radix = 16
      iex> {:ok, ctx} = ExFPE.new(key, radix)
      iex> tweak = <<0::56>>
      iex> input = "aBcDDFF01234eeEee"
      iex> _ciphertext = ExFPE.encrypt!(ctx, tweak, input)
      iex> _plaintext = ExFPE.decrypt!(ctx, tweak, input)

  ### Built-in alphabet: lower case

  If you want to use the built-in alphabet but desire lower case outputs, you
  can do it by declaring the alphabet when creating `ctx`.

      iex> key = :crypto.strong_rand_bytes(32)
      iex> alphabet = "0123456789abcdef" # radix 16
      iex> {:ok, ctx} = ExFPE.new(key, alphabet)
      iex> tweak = <<0::56>>
      iex> input = "aBcDDFF01234eeEee"
      iex> ciphertext = ExFPE.encrypt!(ctx, tweak, input)
      iex> plaintext = ExFPE.decrypt!(ctx, tweak, input)
      iex> ^ciphertext = String.downcase(ciphertext)
      iex> ^plaintext = String.downcase(plaintext)

  ### Custom alphabets

  Whether you need a radix larger than 36, or use symbols other than 0-9, A-Z
  in your numerical strings (or use such symbols in a different order), custom
  alphabets are supported.

  Note that custom alphabets are **case sensitive** but norm insensitive.
  The reasoning behind this can be found under `ExFPE.FFX.Codec.Custom`.

  Each symbol must be a single Unicode scalar that stands on its own as one
  visual unit; alphabets are validated at construction. See
  `ExFPE.FFX.Codec.Custom` for the exact rules and the guarantees they buy.

  #### Base 20 with custom alphabet

      iex> key = :crypto.strong_rand_bytes(32)
      iex> alphabet = "abcdefghij0123456789"
      iex> {:ok, ctx} = ExFPE.new(key, alphabet)
      iex> tweak = <<0::56>>
      iex> plaintext = "34534abcd32235"
      iex> ciphertext = ExFPE.encrypt!(ctx, tweak, plaintext)
      iex> ^plaintext = ExFPE.decrypt!(ctx, tweak, ciphertext)

  #### Base 40 with custom alphabet

      iex> key = :crypto.strong_rand_bytes(32)
      iex> alphabet = "0123456789abcdefghijklmnopqrstuvwxyz@#/*"
      iex> {:ok, ctx} = ExFPE.new(key, alphabet)
      iex> tweak = <<0::56>>
      iex> plaintext = "34534ab@@@@@/cd32235"
      iex> ciphertext = ExFPE.encrypt!(ctx, tweak, plaintext)
      iex> ^plaintext = ExFPE.decrypt!(ctx, tweak, ciphertext)

  #### Unicode support

      iex> key = :crypto.strong_rand_bytes(32)
      iex> alphabet = "🌕🌖🌗🌘🌑🌒🌓🌔"
      iex> {:ok, ctx} = ExFPE.new(key, alphabet)
      iex> tweak = <<0::56>>
      iex> plaintext = "🌖🌕🌘🌑🌓🌗🌔🌒🌒🌒🌒"
      iex> ciphertext = ExFPE.encrypt!(ctx, tweak, plaintext)
      iex> ^plaintext = ExFPE.decrypt!(ctx, tweak, ciphertext)

  ### No alphabet

  If you wish to handle translation of integers into and from symbols yourself,
  you can use `ExFPE.FFX.Codec.NoSymbols`. Encryption and decryption functions
  will receive, and return, integer values with a length tag.

  #### Radix 10

      iex> alias ExFPE.FFX.Codec.NoSymbols
      iex> key = :crypto.strong_rand_bytes(32)
      iex> radix = 10
      iex> {:ok, codec} = NoSymbols.new(radix)
      iex> {:ok, ctx} = ExFPE.new(key, codec)
      iex> tweak = <<0::56>>
      iex> input = 1234567
      iex> input_length = 10
      iex>
      iex> plaintext = %NoSymbols.NumString{value: input, length: input_length}
      iex> ciphertext = ExFPE.encrypt!(ctx, tweak, plaintext)
      iex> %NoSymbols.NumString{length: ^input_length} = ciphertext
      iex> ^plaintext = ExFPE.decrypt!(ctx, tweak, ciphertext)

  #### Radix 500

      iex> alias ExFPE.FFX.Codec.NoSymbols
      iex> key = :crypto.strong_rand_bytes(32)
      iex> radix = 500
      iex> {:ok, codec} = NoSymbols.new(radix)
      iex> {:ok, ctx} = ExFPE.new(key, codec)
      iex> tweak = <<0::56>>
      iex> input = 1234567
      iex> input_length = 10
      iex>
      iex> plaintext = %NoSymbols.NumString{value: input, length: input_length}
      iex> ciphertext = ExFPE.encrypt!(ctx, tweak, plaintext)
      iex> %NoSymbols.NumString{length: ^input_length} = ciphertext
      iex> ^plaintext = ExFPE.decrypt!(ctx, tweak, ciphertext)

  #### Radix 65535

      iex> alias ExFPE.FFX.Codec.NoSymbols
      iex> key = :crypto.strong_rand_bytes(32)
      iex> radix = 65535
      iex> {:ok, codec} = NoSymbols.new(radix)
      iex> {:ok, ctx} = ExFPE.new(key, codec)
      iex> tweak = <<0::56>>
      iex> input = 1234567
      iex> input_length = 10
      iex>
      iex> plaintext = %NoSymbols.NumString{value: input, length: input_length}
      iex> ciphertext = ExFPE.encrypt!(ctx, tweak, plaintext)
      iex> %NoSymbols.NumString{length: ^input_length} = ciphertext
      iex> ^plaintext = ExFPE.decrypt!(ctx, tweak, ciphertext)

  ## Choosing a mode

  Everything above uses the default mode, `:ff1`. To select a mode explicitly,
  pass it as the second argument to `new/3`. The only other mode is `:ff3_1`,
  which is **no longer NIST-approved** (see `ExFPE.FF3_1`) — reach for it only to
  interoperate with data that was already encrypted with FF3-1. It takes a
  fixed 7-byte tweak.

      iex> key = :crypto.strong_rand_bytes(32)
      iex> {:ok, ctx} = ExFPE.new(key, :ff3_1, _radix = 10)
      iex> tweak = <<0::56>>
      iex> plaintext = "34436524"
      iex> ciphertext = ExFPE.encrypt!(ctx, tweak, plaintext)
      iex> ^plaintext = ExFPE.decrypt!(ctx, tweak, ciphertext)

  """

  alias ExFPE.Algorithm
  alias ExFPE.FF1
  alias ExFPE.FF3_1
  alias ExFPE.FFX
  alias ExFPE.FFX.Codec

  ## Constants

  @default_mode :ff1

  ## Types

  @enforce_keys [:algorithm, :codec]
  defstruct [:algorithm, :codec]

  @type t :: %__MODULE__{algorithm: Algorithm.t(), codec: Codec.t()}

  @typedoc "A supported FPE mode."
  @type mode :: :ff1 | :ff3_1

  @type key :: FFX.key()
  @type radix :: FFX.radix()
  @type alphabet :: String.t()
  @type codec :: Codec.t()

  @type tweak :: binary()
  @type numerical_string :: FFX.numerical_string()

  @type constraints :: %{min_length: pos_integer, max_length: pos_integer}

  ## API

  @doc """
  Like `new/3`, but returns the context directly and raises `ExFPE.ArgumentError`
  on failure.
  """
  @spec new!(key, mode, radix | alphabet | codec) :: t
  def new!(key, mode \\ @default_mode, radix_or_alphabet_or_codec) do
    case new(key, mode, radix_or_alphabet_or_codec) do
      {:ok, ex_fpe} ->
        ex_fpe

      {:error, reason} ->
        raise ExFPE.ArgumentError, reason: reason
    end
  end

  @doc """
  Creates a context for both encryption and decryption from a `key`, an optional
  `mode` (`:ff1` by default), and either a `radix`, an `alphabet`, or a
  `ExFPE.FFX.Codec`.

  Returns `{:error, reason}` if any argument is invalid.
  """
  @spec new(key, mode, radix | alphabet | codec) :: {:ok, t} | {:error, term}
  def new(key, mode \\ @default_mode, radix_or_alphabet_or_codec) do
    with {:ok, codec} <- init_codec(radix_or_alphabet_or_codec),
         {:ok, algorithm} <- init_algorithm(mode, key, codec) do
      ex_fpe = %__MODULE__{
        algorithm: algorithm,
        codec: codec
      }

      {:ok, ex_fpe}
    else
      {:error, _} = error ->
        error
    end
  end

  @doc """
  Like `encrypt/3`, but returns the ciphertext directly and raises
  `ExFPE.InputError` on failure.
  """
  @spec encrypt!(t, tweak, numerical_string) :: numerical_string
  def encrypt!(ex_fpe, tweak, plaintext) do
    case encrypt(ex_fpe, tweak, plaintext) do
      {:ok, ciphertext} ->
        ciphertext

      {:error, reason} ->
        raise ExFPE.InputError, reason: reason
    end
  end

  @doc """
  Encrypts `plaintext` into a numerical string of the same length over the same
  alphabet, using `tweak`.

  Returns `{:error, reason}` if the tweak or input is invalid.
  """
  @spec encrypt(t, tweak, numerical_string) :: {:ok, numerical_string} | {:error, term}
  def encrypt(%__MODULE__{algorithm: algorithm}, tweak, plaintext) do
    Algorithm.do_encrypt_or_decrypt(algorithm, tweak, plaintext, true)
  end

  @doc """
  Like `decrypt/3`, but returns the plaintext directly and raises
  `ExFPE.InputError` on failure.
  """
  @spec decrypt!(t, tweak, numerical_string) :: numerical_string
  def decrypt!(ex_fpe, tweak, ciphertext) do
    case decrypt(ex_fpe, tweak, ciphertext) do
      {:ok, plaintext} ->
        plaintext

      {:error, reason} ->
        raise ExFPE.InputError, reason: reason
    end
  end

  @doc """
  Decrypts `ciphertext` back into its plaintext numerical string, using `tweak`.

  Returns `{:error, reason}` if the tweak or input is invalid.
  """
  @spec decrypt(t, tweak, numerical_string) :: {:ok, numerical_string} | {:error, term}
  def decrypt(%__MODULE__{algorithm: algorithm}, tweak, ciphertext) do
    Algorithm.do_encrypt_or_decrypt(algorithm, tweak, ciphertext, false)
  end

  @doc """
  Returns a `ctx`'s mode-specific length constraints (`min_length`/`max_length`).
  """
  @spec constraints(t) :: constraints
  def constraints(%__MODULE__{algorithm: algorithm}) do
    algorithm.__struct__.constraints(algorithm)
  end

  @doc """
  Returns a `ctx`'s `ExFPE.FFX.Codec`, should you wish to further manipulate or
  prepare encryption and decryption inputs or outputs.
  """
  @spec codec(t) :: Codec.t()
  def codec(%__MODULE__{codec: codec}), do: codec

  ## Convenience: `use ExFPE`

  @doc """
  Returns the `Supervisor` child spec for the module that `use ExFPE`.

  Implement it by calling the generated `child_spec/2` or `child_spec/3` with
  your key, mode, and radix/alphabet/codec — see the moduledoc.
  """
  @callback child_spec() :: Supervisor.child_spec()

  @doc """
  Places an `ExFPE` context under your supervision tree so that you can encrypt
  and decrypt without threading the context through every call.

  A module that `use ExFPE` gets:

    * a `child_spec/2` / `child_spec/3` builder and a `start_link/3`, backed by
      a uniquely named process holding the context in a `:persistent_term`;
    * `encrypt/2`, `encrypt!/2`, `decrypt/2`, `decrypt!/2` that retrieve the
      context transparently; plus `constraints/0`, `codec/0`, and `ex_fpe!/0`.

  You implement the `c:child_spec/0` callback declaring your configuration, and
  add `MyModule.child_spec()` to your supervision tree.

      defmodule MyApp.CardCipher do
        use ExFPE

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
      @behaviour ExFPE

      @doc """
      Builds a `Supervisor` child spec for `#{inspect(__MODULE__)}`'s context.

      Call this from your `c:ExFPE.child_spec/0` implementation.
      """
      @spec child_spec(ExFPE.key(), ExFPE.mode(), radix | alphabet | codec) :: Supervisor.child_spec()
            when radix: ExFPE.radix(), alphabet: ExFPE.alphabet(), codec: ExFPE.codec()
      def child_spec(key, mode \\ unquote(@default_mode), radix_or_alphabet_or_codec) do
        ExFPE.Agent.child_spec(
          __MODULE__,
          {__MODULE__, :start_link, [key, mode, radix_or_alphabet_or_codec]}
        )
      end

      @doc """
      Starts the process holding `#{inspect(__MODULE__)}`'s context.
      """
      @spec start_link(ExFPE.key(), ExFPE.mode(), radix | alphabet | codec) :: {:ok, pid} | {:error, term}
            when radix: ExFPE.radix(), alphabet: ExFPE.alphabet(), codec: ExFPE.codec()
      def start_link(key, mode, radix_or_alphabet_or_codec) do
        ExFPE.Agent.start_link(
          __MODULE__,
          {&ExFPE.new/3, [key, mode, radix_or_alphabet_or_codec]}
        )
      end

      @doc "Like `ExFPE.encrypt/3`, retrieving `#{inspect(__MODULE__)}`'s context."
      @spec encrypt(ExFPE.tweak(), ExFPE.numerical_string()) ::
              {:ok, ExFPE.numerical_string()} | {:error, term}
      def encrypt(tweak, plaintext), do: ExFPE.encrypt(ex_fpe!(), tweak, plaintext)

      @doc "Like `ExFPE.encrypt!/3`, retrieving `#{inspect(__MODULE__)}`'s context."
      @spec encrypt!(ExFPE.tweak(), ExFPE.numerical_string()) :: ExFPE.numerical_string()
      def encrypt!(tweak, plaintext), do: ExFPE.encrypt!(ex_fpe!(), tweak, plaintext)

      @doc "Like `ExFPE.decrypt/3`, retrieving `#{inspect(__MODULE__)}`'s context."
      @spec decrypt(ExFPE.tweak(), ExFPE.numerical_string()) ::
              {:ok, ExFPE.numerical_string()} | {:error, term}
      def decrypt(tweak, ciphertext), do: ExFPE.decrypt(ex_fpe!(), tweak, ciphertext)

      @doc "Like `ExFPE.decrypt!/3`, retrieving `#{inspect(__MODULE__)}`'s context."
      @spec decrypt!(ExFPE.tweak(), ExFPE.numerical_string()) :: ExFPE.numerical_string()
      def decrypt!(tweak, ciphertext), do: ExFPE.decrypt!(ex_fpe!(), tweak, ciphertext)

      @doc "Like `ExFPE.constraints/1` for `#{inspect(__MODULE__)}`'s context."
      @spec constraints() :: ExFPE.constraints()
      def constraints, do: ExFPE.constraints(ex_fpe!())

      @doc "Like `ExFPE.codec/1` for `#{inspect(__MODULE__)}`'s context."
      @spec codec() :: FFX.Codec.t()
      def codec, do: ExFPE.codec(ex_fpe!())

      @doc "Returns this module's `t:ExFPE.t/0`."
      @spec ex_fpe!() :: ExFPE.t()
      def ex_fpe! do
        case ExFPE.Agent.get(__MODULE__) do
          {:ok, ex_fpe} ->
            ex_fpe

          {:error, {:ctx_not_found_for_module, module}} ->
            raise ExFPE.NotStartedError, reason: {:ctx_not_found_for_module, module}
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
        alphabet = radix_or_alphabet

        case Codec.Custom.new(alphabet) do
          {:ok, _} = success ->
            success

          {:error, reason} ->
            {:error, {:bad_alphabet, reason}}
        end

      nil when is_integer(radix_or_alphabet) ->
        radix = radix_or_alphabet
        {:error, {:bad_radix, {radix, :need_alphabet_or_codec}}}
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
