defmodule FPE do
  @moduledoc "TODO"

  alias FPE.Algorithm
  alias FPE.FF1

  ## Constants

  @default_module FF1

  ## Types

  @enforce_keys [:algorithm]
  defstruct [:algorithm]

  @type t :: %__MODULE__{algorithm: Algorithm.t()}

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
    case module.new_ctx(key, radix_or_alphabet_or_codec) do
      {:ok, algorithm} ->
        fpe = %__MODULE__{algorithm: algorithm}
        {:ok, fpe}

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
end
