defmodule FPE do
  @moduledoc "TODO"

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
