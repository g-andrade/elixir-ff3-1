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
  built-in and custom alphabets, tweaks, alphabet-free raw integers, choosing a
  mode, and the `use ExFPE` convenience for supervised contexts.
  """

  alias ExFPE.Algorithm
  alias ExFPE.Codec
  alias ExFPE.Codec.Raw.Numeral
  alias ExFPE.FF1
  alias ExFPE.FF3_1
  alias ExFPE.FFX

  ## Constants

  @default_mode :ff1

  ## Types

  @enforce_keys [:base_conf, :raw_codec, :algorithm]
  defstruct [:base_conf, :raw_codec, :algorithm]

  @typedoc """
  An encryption/decryption context.

  Built by `new/3` (or `new!/3`) and passed to `encrypt!/3` and `decrypt!/3`.
  Bundles the chosen mode's `algorithm` (which holds the key) with how inputs map
  to integers — an alphabet, or the raw integers of a `{:raw_only, radix}` context.
  """
  @opaque t :: %__MODULE__{base_conf: base_conf, raw_codec: Codec.t(), algorithm: Algorithm.t()}

  @typep base_conf :: {:codec, Codec.t()} | {:radix, FFX.radix()}

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

  Each symbol is a single Unicode codepoint, and the radix is the amount of
  symbols (**not** graphemes).

  For any alphabet not covered by `ExFPE.Codec.Builtin`, see
  `ExFPE.Codec.Custom` for the exact rules.
  """
  @type alphabet :: String.t()

  @typedoc """
  A tweak: public data that varies the ciphertext for a given key and plaintext.

  Its length depends on the mode — variable for FF1, a fixed 7 bytes for FF3-1.
  """
  @type tweak :: binary()

  @typedoc "A mode's inclusive bounds on input length, as returned by `constraints/1`."
  @type constraints :: %{min_length: pos_integer, max_length: pos_integer}

  ## API

  @doc """
  Like `new/3`, but returns the context directly and raises `ExFPE.ArgumentError`
  on failure.
  """
  @spec new!(key, mode, radix | alphabet | {:raw_only, radix}) :: ctx :: t
  def new!(key, mode \\ @default_mode, radix_or_alphabet) do
    case new(key, mode, radix_or_alphabet) do
      {:ok, ex_fpe} ->
        ex_fpe

      {:error, reason} ->
        raise ExFPE.ArgumentError, reason: reason
    end
  end

  @doc """
  Creates a context for both encryption and decryption from a `key`, an optional
  `mode` (`:ff1` by default), and either a `radix`, an `alphabet`, or
  `{:raw_only, radix}`.

  A `radix` or `alphabet` encrypts strings with `encrypt/3`/`decrypt/3`;
  `{:raw_only, radix}` skips symbols entirely and works with integers through
  `raw_encrypt/4`/`raw_decrypt/4`.

  Returns `{:error, reason}` if any argument is invalid.
  """
  @spec new(key, mode, radix | alphabet | {:raw_only, radix}) :: {:ok, ctx :: t} | {:error, term}
  def new(key, mode \\ @default_mode, radix_or_alphabet) do
    with {:ok, base_conf} <- base_conf(radix_or_alphabet),
         radix = base_conf_radix(base_conf),
         {:ok, algorithm} <- init_algorithm(mode, key, radix) do
      ex_fpe = %__MODULE__{
        base_conf: base_conf,
        raw_codec: Codec.Raw.new!(radix),
        algorithm: algorithm
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
  @spec encrypt!(t, tweak, plaintext) :: ciphertext
        when plaintext: String.t(), ciphertext: String.t()
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
  @spec encrypt(t, tweak, plaintext) :: {:ok, ciphertext} | {:error, term}
        when plaintext: String.t(), ciphertext: String.t()
  def encrypt(%__MODULE__{base_conf: base_conf, algorithm: algorithm} = _ctx, tweak, plaintext) do
    case base_conf do
      {:codec, codec} ->
        Algorithm.do_encrypt_or_decrypt(algorithm, tweak, codec, plaintext, true)

      {:radix, radix} ->
        {:error, {:raw_only_context, radix}}
    end
  end

  @doc """
  Like `decrypt/3`, but returns the plaintext directly and raises
  `ExFPE.InputError` on failure.
  """
  @spec decrypt!(t, tweak, ciphertext) :: plaintext
        when ciphertext: String.t(), plaintext: String.t()
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
  @spec decrypt(t, tweak, ciphertext) :: {:ok, plaintext} | {:error, term}
        when ciphertext: String.t(), plaintext: String.t()
  def decrypt(%__MODULE__{base_conf: base_conf, algorithm: algorithm} = _ctx, tweak, ciphertext) do
    case base_conf do
      {:codec, codec} ->
        Algorithm.do_encrypt_or_decrypt(algorithm, tweak, codec, ciphertext, false)

      {:radix, radix} ->
        {:error, {:raw_only_context, radix}}
    end
  end

  @doc """
  Like `raw_encrypt/4`, but returns the ciphertext value directly and raises
  `ExFPE.InputError` on failure.
  """
  @spec raw_encrypt!(t, tweak, plainval, length) :: cipherval
        when plainval: non_neg_integer(), length: pos_integer, cipherval: non_neg_integer()
  def raw_encrypt!(ctx, tweak, plainval, length) do
    case raw_encrypt(ctx, tweak, plainval, length) do
      {:ok, cipherval} ->
        cipherval

      {:error, reason} ->
        raise ExFPE.InputError, reason: reason
    end
  end

  @doc """
  Encrypts the integer `plainval` directly, skipping the symbol alphabet.

  This is the alphabet-free counterpart to `encrypt/3`: you hand it an integer
  and it hands an integer back, leaving the mapping between integers and
  whatever symbols they stand for up to you. Reach for it when your symbols
  aren't a single Unicode scalar each (so a custom alphabet can't accept them),
  when the value already lives as an integer in your system, or to avoid string
  encoding on a hot path.

  `plainval` is interpreted as `length` digits in the context's radix, most
  significant first. **`length` is significant** and must be passed explicitly:
  FPE treats leading zeroes as real symbols, so `{value: 42, length: 2}` ("42")
  and `{value: 42, length: 5}` ("00042") encrypt differently and can't be told
  apart from the value alone. The ciphertext preserves `length`.

  `plainval` must fit its declared length — that is,
  `0 <= plainval < radix ** length` — otherwise this returns
  `{:error, {:negative_value, plainval}}` or
  `{:error, {:value_is_larger_than_declared_length}}`.

  Any context supports this, including one built from an alphabet: it operates on
  the context's radix and ignores the alphabet. A context built with
  `{:raw_only, radix}` supports *only* these functions, not `encrypt/3`.

  Returns `{:error, reason}` if the tweak or input is invalid.
  """
  @spec raw_encrypt(t, tweak, plainval, length) :: {:ok, cipherval} | {:error, term}
        when plainval: non_neg_integer(), length: pos_integer, cipherval: non_neg_integer()
  def raw_encrypt(%__MODULE__{raw_codec: raw_codec, algorithm: algorithm} = _ctx, tweak, plainval, length) do
    plain_numeral = %Numeral{value: plainval, length: length}

    case Algorithm.do_encrypt_or_decrypt(algorithm, tweak, raw_codec, plain_numeral, true) do
      {:ok, %Numeral{value: cipherval}} ->
        {:ok, cipherval}

      {:error, _} = error ->
        error
    end
  end

  @doc """
  Like `raw_decrypt/4`, but returns the plaintext value directly and raises
  `ExFPE.InputError` on failure.
  """
  @spec raw_decrypt!(t, tweak, cipherval, length) :: plainval
        when cipherval: non_neg_integer(), length: pos_integer, plainval: non_neg_integer()
  def raw_decrypt!(ctx, tweak, cipherval, length) do
    case raw_decrypt(ctx, tweak, cipherval, length) do
      {:ok, plainval} ->
        plainval

      {:error, reason} ->
        raise ExFPE.InputError, reason: reason
    end
  end

  @doc """
  Decrypts the integer `cipherval` back into its plaintext value, skipping the
  symbol alphabet.

  The alphabet-free counterpart to `decrypt/3`; see `raw_encrypt/4` for how
  `length` and the `0 <= value < radix ** length` bound work.

  Returns `{:error, reason}` if the tweak or input is invalid.
  """
  @spec raw_decrypt(t, tweak, cipherval, length) :: {:ok, plainval} | {:error, term}
        when cipherval: non_neg_integer(), length: pos_integer, plainval: non_neg_integer()
  def raw_decrypt(%__MODULE__{raw_codec: raw_codec, algorithm: algorithm} = _ctx, tweak, cipherval, length) do
    cipher_numeral = %Numeral{value: cipherval, length: length}

    case Algorithm.do_encrypt_or_decrypt(algorithm, tweak, raw_codec, cipher_numeral, false) do
      {:ok, %Numeral{value: plainval}} ->
        {:ok, plainval}

      {:error, _} = error ->
        error
    end
  end

  @doc """
  Returns a `ctx`'s mode-specific length constraints (`min_length`/`max_length`).
  """
  @spec constraints(t) :: constraints
  def constraints(%__MODULE__{algorithm: algorithm} = _ctx) do
    algorithm.__struct__.constraints(algorithm)
  end

  ## Convenience: `use ExFPE`

  @doc """
  Returns the `Supervisor` child spec for the module that `use ExFPE`.

  Implement it by calling the generated `child_spec/2` or `child_spec/3` with
  your key, mode, and radix/alphabet (or `{:raw_only, radix}`) — see the moduledoc.
  """
  @callback child_spec() :: Supervisor.child_spec()

  @doc """
  Places an `ExFPE` context under your supervision tree so that you can encrypt
  and decrypt without threading the context through every call.

  A module that declares `use ExFPE` gets:

    * a `child_spec/2` / `child_spec/3` builder and a `start_link/3`, backed by
      a uniquely named process holding the context in a `:persistent_term`;
    * `encrypt/2`, `encrypt!/2`, `decrypt/2`, `decrypt!/2` that retrieve the
      context transparently; plus `constraints/0` and `ex_fpe!/0`.

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
      @spec child_spec(ExFPE.key(), ExFPE.mode(), radix | alphabet | {:raw_only, radix}) ::
              Supervisor.child_spec()
            when radix: ExFPE.radix(), alphabet: ExFPE.alphabet()
      def child_spec(key, mode \\ unquote(@default_mode), radix_or_alphabet) do
        ExFPE.Agent.child_spec(
          __MODULE__,
          {__MODULE__, :start_link, [key, mode, radix_or_alphabet]}
        )
      end

      @doc """
      Starts the process holding `#{inspect(__MODULE__)}`'s context.
      """
      @spec start_link(ExFPE.key(), ExFPE.mode(), radix | alphabet | {:raw_only, radix}) ::
              {:ok, pid} | {:error, term}
            when radix: ExFPE.radix(), alphabet: ExFPE.alphabet()
      def start_link(key, mode, radix_or_alphabet) do
        ExFPE.Agent.start_link(
          __MODULE__,
          {&ExFPE.new/3, [key, mode, radix_or_alphabet]}
        )
      end

      @doc "Like `ExFPE.encrypt/3`, retrieving `#{inspect(__MODULE__)}`'s context."
      @spec encrypt(ExFPE.tweak(), String.t()) ::
              {:ok, String.t()} | {:error, term}
      def encrypt(tweak, plaintext), do: ExFPE.encrypt(ex_fpe!(), tweak, plaintext)

      @doc "Like `ExFPE.encrypt!/3`, retrieving `#{inspect(__MODULE__)}`'s context."
      @spec encrypt!(ExFPE.tweak(), String.t()) :: String.t()
      def encrypt!(tweak, plaintext), do: ExFPE.encrypt!(ex_fpe!(), tweak, plaintext)

      @doc "Like `ExFPE.decrypt/3`, retrieving `#{inspect(__MODULE__)}`'s context."
      @spec decrypt(ExFPE.tweak(), String.t()) ::
              {:ok, String.t()} | {:error, term}
      def decrypt(tweak, ciphertext), do: ExFPE.decrypt(ex_fpe!(), tweak, ciphertext)

      @doc "Like `ExFPE.decrypt!/3`, retrieving `#{inspect(__MODULE__)}`'s context."
      @spec decrypt!(ExFPE.tweak(), String.t()) :: String.t()
      def decrypt!(tweak, ciphertext), do: ExFPE.decrypt!(ex_fpe!(), tweak, ciphertext)

      @doc "Like `ExFPE.raw_encrypt/4`, retrieving `#{inspect(__MODULE__)}`'s context."
      @spec raw_encrypt(ExFPE.tweak(), non_neg_integer(), pos_integer()) ::
              {:ok, non_neg_integer()} | {:error, term}
      def raw_encrypt(tweak, plainval, length), do: ExFPE.raw_encrypt(ex_fpe!(), tweak, plainval, length)

      @doc "Like `ExFPE.raw_encrypt!/4`, retrieving `#{inspect(__MODULE__)}`'s context."
      @spec raw_encrypt!(ExFPE.tweak(), non_neg_integer(), pos_integer()) :: non_neg_integer()
      def raw_encrypt!(tweak, plainval, length), do: ExFPE.raw_encrypt!(ex_fpe!(), tweak, plainval, length)

      @doc "Like `ExFPE.raw_decrypt/4`, retrieving `#{inspect(__MODULE__)}`'s context."
      @spec raw_decrypt(ExFPE.tweak(), non_neg_integer(), pos_integer()) ::
              {:ok, non_neg_integer()} | {:error, term}
      def raw_decrypt(tweak, cipherval, length), do: ExFPE.raw_decrypt(ex_fpe!(), tweak, cipherval, length)

      @doc "Like `ExFPE.raw_decrypt!/4`, retrieving `#{inspect(__MODULE__)}`'s context."
      @spec raw_decrypt!(ExFPE.tweak(), non_neg_integer(), pos_integer()) :: non_neg_integer()
      def raw_decrypt!(tweak, cipherval, length), do: ExFPE.raw_decrypt!(ex_fpe!(), tweak, cipherval, length)

      @doc "Like `ExFPE.constraints/1` for `#{inspect(__MODULE__)}`'s context."
      @spec constraints() :: ExFPE.constraints()
      def constraints, do: ExFPE.constraints(ex_fpe!())

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

  defp base_conf({:raw_only, radix}) when is_integer(radix) do
    {:ok, {:radix, radix}}
  end

  defp base_conf(radix_or_alphabet) when is_integer(radix_or_alphabet) or is_binary(radix_or_alphabet) do
    case Codec.Builtin.maybe_new(radix_or_alphabet) do
      {:ok, codec} ->
        {:ok, {:codec, codec}}

      nil when is_binary(radix_or_alphabet) ->
        alphabet = radix_or_alphabet

        case Codec.Custom.new(alphabet) do
          {:ok, codec} ->
            {:ok, {:codec, codec}}

          {:error, reason} ->
            {:error, {:bad_alphabet, reason}}
        end

      nil when is_integer(radix_or_alphabet) ->
        radix = radix_or_alphabet
        {:error, {:bad_radix, {radix, :need_alphabet_or_raw_only}}}
    end
  end

  ##

  defp base_conf_radix({:codec, codec}) do
    Codec.radix(codec)
  end

  defp base_conf_radix({:radix, radix}) do
    radix
  end

  ##

  defp init_algorithm(:ff1, key, radix) do
    FF1.new_ctx(key, radix)
  end

  defp init_algorithm(:ff3_1, key, radix) do
    FF3_1.new_ctx(key, radix)
  end

  defp init_algorithm(mode, _key, _radix) do
    {:error, {:unknown_mode, mode}}
  end
end
