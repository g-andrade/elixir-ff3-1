# credo:disable-for-this-file Credo.Check.Design.AliasUsage
# credo:disable-for-this-file Credo.Check.Readability.ModuleNames
defmodule FPE.FF3_1.Setup do
  @moduledoc false
  @type opts ::
          [
            key: FPE.FF3_1.key(),
            radix: FPE.FF3_1.radix()
          ]
          | [
              key: FPE.FF3_1.key(),
              alphabet: FPE.FF3_1.alphabet()
            ]
          | [
              key: FPE.FF3_1.key(),
              codec: FPE.FF3_1.codec()
            ]

  @doc false
  defmacro __using__(opts) do
    quote bind_quoted: [opts: opts] do
      ## API

      def child_spec do
        FPE.FF3_1.Setup.Server.child_spec(server_args())
      end

      def start_link do
        FPE.FF3_1.Setup.Server.start_link(server_args())
      end

      @doc """
      Encrypts numerical string `plaintext` using setup key and a 7-byte `tweak`.

      Returns numerical string `ciphertext` of length equal to `plaintext`.

      Minimum and maximum length of `plaintext` depend on radix (see `constraints/0`).
      """
      @spec encrypt!(tweak, plaintext) :: ciphertext
            when tweak: FPE.FF3_1.tweak(),
                 plaintext: FPE.FF3_1.numerical_string(),
                 ciphertext: FPE.FF3_1.numerical_string()
      def encrypt!(tweak, plaintext) do
        FPE.FF3_1.encrypt!(ctx(), tweak, plaintext)
      end

      @doc """
      Decrypts numerical string `ciphertext` using setup key and a 7-byte `tweak`.

      Returns numerical string `plaintext` of length equal to `ciphertext`**.

      Minimum and maximum length of `ciphertext` depend on radix (see `constraints/0`).
      """
      @spec decrypt!(tweak, ciphertext) :: plaintext
            when tweak: FPE.FF3_1.tweak(),
                 ciphertext: FPE.FF3_1.numerical_string(),
                 plaintext: FPE.FF3_1.numerical_string()
      def decrypt!(tweak, ciphertext) do
        FPE.FF3_1.decrypt!(ctx(), tweak, ciphertext)
      end

      @doc """
      Returns this setup's constraints.
      """
      @spec constraints :: FPE.FF3_1.constraints()
      def constraints do
        FPE.FF3_1.constraints(ctx())
      end

      @doc """
      Returns this setup's `FPE.FPE.FFX.Codec`, should you wish to further manipulate or
      prepare encryption and decryption inputs or outputs.
      """
      @spec codec :: FPE.FF3_1.codec()
      def codec do
        FPE.FF3_1.codec(ctx())
      end

      @doc """
      Returns this setup's `FPE.FF3_1.ctx`.
      """
      @spec ctx :: FPE.FF3_1.ctx()
      def ctx do
        {:ok, ctx} = FPE.FF3_1.Setup.Server.get_ctx(__MODULE__)
        ctx
      end

      ## Internal Functions

      defp server_args do
        opts = unquote(opts)

        %FPE.FF3_1.Setup.Server.Args{
          module: __MODULE__,
          key: opts[:key],
          radix_or_alphabet_or_codec: opts[:radix] || opts[:alphabet] || opts[:codec]
        }
      end
    end
  end
end
