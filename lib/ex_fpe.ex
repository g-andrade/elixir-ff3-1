defmodule ExFPE do
  @moduledoc """
  Format-preserving encryption (FPE) for Elixir.

  ExFPE encrypts a numerical string into another of the **same length over the
  same alphabet**, which is useful to e.g. store an encrypted credit card
  number in a field that only accepts credit-card-shaped values, and other
  suchlike applications.

  `ExfPE` is the entry point. It wraps a concrete FPE mode behind a single API:
  `new!/2`, `encrypt!/3`, `decrypt!/3`, and error-returning variants.


  By default it uses **FF1** (`ExFPE.FF1`), the only mode approved by NIST in
  [SP 800-38Gr1 2pd](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38Gr1.2pd.pdf).
  To pick a mode explicitly, pass it as the **second argument** to `new/3`:

  * `:ff1` — the FF1 mode (default; variable-length tweak).
  * `:ff3_1` — the FF3-1 mode (fixed **7-byte** tweak). ⚠️ NIST removed FF3-1;
    use it only for interop with existing data. See `ExFPE.FF3_1`.

  > #### Mode-specific rules {: .info}
  >
  > The **tweak size** and the **length constraints** on inputs depend on the
  > mode. FF1 accepts a variable-length tweak (it may even be empty); see
  > `ExFPE.FF1`. FF3-1 uses a fixed 7-byte (56-bit) tweak; see `ExFPE.FF3_1`.

  ## Guide

  See the [usage guide](readme.html) for worked, runnable examples — contexts,
  built-in and custom alphabets, tweaks, symbol-free codecs, choosing a mode,
  and the `use ExFPE` convenience for supervised contexts.
  """

  alias ExFPE.Algorithm
  alias ExFPE.Codec
  alias ExFPE.FF1
  alias ExFPE.FF3_1
  alias ExFPE.FFX

  ## Constants

  @default_mode :ff1

  ## Types

  @enforce_keys [:algorithm, :codec]
  defstruct [:algorithm, :codec]

  @typedoc """
  An encryption/decryption context.

  Built by `new/3` (or `new!/3`) and passed to `encrypt!/3` and `decrypt!/3`.
  Bundles the chosen mode's `algorithm` (which holds the key) with the `codec`
  that maps between symbols and integers. Treat it as opaque.
  """
  @opaque t :: %__MODULE__{algorithm: Algorithm.t(), codec: Codec.t()}

  @typedoc "A supported FPE mode."
  @type mode :: :ff1 | :ff3_1

  @typedoc "An AES key: 16, 24, or 32 bytes (AES-128/192/256)."
  @type key :: FFX.key()

  @typedoc """
  The base the numerical strings are written in, from 2 up to 65536
  (or 65535 in the case of `ExFPE.FF3_1`).
  """
  @type radix :: FFX.radix()

  @typedoc """
  The ordered symbols of a custom alphabet, given as a string.

  Each symbol is a single Unicode codepoint, and the radix is amount of symbols
  (**not** graphemes). See `ExFPE.Codec.Custom` for the exact rules.
  """
  @type alphabet :: String.t()

  @typedoc "A codec mapping between symbols and integers; see `ExFPE.Codec`."
  @type codec :: Codec.t()

  @typedoc """
  A tweak: public data that varies the ciphertext for a given key and plaintext.

  Its length depends on the mode — variable for FF1, a fixed 7 bytes for FF3-1.
  """
  @type tweak :: binary()

  @typedoc """
  A value to encrypt or decrypt.

  Usually the numeral `String.t()` over the context's alphabet, but a codec may
  use its own representation (e.g. `ExFPE.Codec.NoSymbols` uses tagged
  integers). Ciphertext and plaintext share this type and the same length.
  """
  @type numerical_string :: FFX.numerical_string()

  @typedoc "A mode's inclusive bounds on input length, as returned by `constraints/1`."
  @type constraints :: %{min_length: pos_integer, max_length: pos_integer}

  ## API

  @doc """
  Like `new/3`, but returns the context directly and raises `ExFPE.ArgumentError`
  on failure.
  """
  @spec new!(key, mode, radix | alphabet | codec) :: ctx :: t
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
  `mode` (`:ff1` by default), and either a `radix`, an `alphabet`, or an
  `ExFPE.Codec`.

  Returns `{:error, reason}` if any argument is invalid.
  """
  @spec new(key, mode, radix | alphabet | codec) :: {:ok, ctx :: t} | {:error, term}
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
  def encrypt!(ctx, tweak, plaintext) do
    case encrypt(ctx, tweak, plaintext) do
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
  def encrypt(%__MODULE__{algorithm: algorithm} = _ctx, tweak, plaintext) do
    Algorithm.do_encrypt_or_decrypt(algorithm, tweak, plaintext, true)
  end

  @doc """
  Like `decrypt/3`, but returns the plaintext directly and raises
  `ExFPE.InputError` on failure.
  """
  @spec decrypt!(t, tweak, numerical_string) :: numerical_string
  def decrypt!(ctx, tweak, ciphertext) do
    case decrypt(ctx, tweak, ciphertext) do
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
  def decrypt(%__MODULE__{algorithm: algorithm} = _ctx, tweak, ciphertext) do
    Algorithm.do_encrypt_or_decrypt(algorithm, tweak, ciphertext, false)
  end

  @doc """
  Returns a `ctx`'s mode-specific length constraints (`min_length`/`max_length`).
  """
  @spec constraints(t) :: constraints
  def constraints(%__MODULE__{algorithm: algorithm} = _ctx) do
    algorithm.__struct__.constraints(algorithm)
  end

  @doc """
  Returns a `ctx`'s `ExFPE.Codec`, should you wish to further manipulate or
  prepare encryption and decryption inputs or outputs.
  """
  @spec codec(t) :: Codec.t()
  def codec(%__MODULE__{codec: codec} = _ctx), do: codec

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

  A module that declares `use ExFPE` gets:

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
      @spec codec() :: Codec.t()
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
