defmodule FPE.UnsignedId do
  require Record
  import Bitwise

  alias FPE.FF3_1
  alias FPE.FFX.Codec

  ## Constants

  @default_radix 10

  ## Types

  @type max_id :: non_neg_integer | {:max, int_type}
  @type int_type :: :uint64 | :int64 | :uint32 | :int32

  # context

  Record.defrecordp(:fpe_unsigned_id, [
    :algo,
    :max_value,
    # length of encoded :max_value
    :encoded_length
  ])

  @opaque t ::
            record(:fpe_unsigned_id,
              algo: algo,
              max_value: non_neg_integer,
              encoded_length: pos_integer
            )

  @typep algo :: ff3_1_algo

  # FF3-1 algo

  Record.defrecord(:fpe_unsigned_id_ff3_1, [
    :ctx,
    :tweak
  ])

  @typep ff3_1_algo ::
           record(:fpe_unsigned_id_ff3_1,
             ctx: FF3_1.ctx(),
             tweak: FF3_1.tweak()
           )

  ## API

  def new_ff3_1(key, max_id, opts \\ []) when is_list(opts) do
    with {:ok, radix_or_alphabet} <- get_radix_or_alphabet(opts),
         {:ok, algo_ctx} <- FF3_1.new_ctx(key, radix_or_alphabet),
         {:ok, max_value} <- validate_max_id(max_id),
         {:ok, encoded_length} <- validate_max_ff3_1_value(max_value, algo_ctx) do
      ##
      ## FIXME: current approach doesn't work well because e.g. with a default
      ## radix of 10 and max id set to max uint64, the underlying FF3-1 domain
      ## will go beyond max uint64 when encrypted, which breaks the format-preserving
      ## aspect we're looking for.
      ##

      tweak = Keyword.get(opts, :tweak, <<0::56>>)
      algo = fpe_unsigned_id_ff3_1(ctx: algo_ctx, tweak: tweak)

      t =
        fpe_unsigned_id(
          algo: algo,
          max_value: max_value,
          encoded_length: encoded_length
        )

      {:ok, t}
    else
      {:error, _} = error -> error
    end
  end

  @spec encrypt!(t(), non_neg_integer) :: String.t()
  def encrypt!(
        fpe_unsigned_id(algo: algo, max_value: max_value, encoded_length: encoded_length),
        id
      )
      when is_integer(id) and id in 0..max_value do
    fpe_unsigned_id_ff3_1(ctx: algo_ctx, tweak: tweak) = algo
    codec = FF3_1.get_codec!(algo_ctx)
    plaintext = Codec.str_m_radix(codec, _m = encoded_length, id)
    padded_ciphertext = FF3_1.encrypt!(algo_ctx, tweak, plaintext)
    _ciphertext = Codec.strip_leading_zeroes(codec, padded_ciphertext)
  end

  @spec decrypt!(t(), String.t()) :: non_neg_integer
  def decrypt!(
        fpe_unsigned_id(algo: algo, max_value: max_value, encoded_length: encoded_length),
        ciphertext
      ) do
    fpe_unsigned_id_ff3_1(ctx: algo_ctx, tweak: tweak) = algo
    codec = FF3_1.get_codec!(algo_ctx)

    case Codec.num_radix(codec, ciphertext) do
      encrypted_id when encrypted_id not in 0..max_value ->
        {:error, {:encrypted_id_out_of_range, %{id: encrypted_id, max_value: max_value}}}

      encrypted_id ->
        padded_ciphertext = Codec.str_m_radix(codec, _m = encoded_length, encrypted_id)
        plaintext = FF3_1.decrypt!(algo_ctx, tweak, padded_ciphertext)
        _id = Codec.num_radix(codec, plaintext)
    end
  end

  ## Internal Functions

  defp get_radix_or_alphabet(opts) do
    case {Keyword.get(opts, :radix), Keyword.get(opts, :alphabet)} do
      {nil, nil} ->
        {:ok, @default_radix}

      {nil, alphabet} ->
        {:ok, alphabet}

      {radix, nil} ->
        {:ok, radix}

      {radix, alphabet} ->
        {:error, {:both_radix_and_alphabet_specified, [radix: radix, alphabet: alphabet]}}
    end
  end

  defp validate_max_id({:max, int_type}) do
    %{
      uint64: (1 <<< 64) - 1,
      int64: (1 <<< 63) - 1,
      uint32: (1 <<< 32) - 1,
      int32: (1 <<< 31) - 1
    }
    |> Map.fetch(int_type)
    |> case do
      {:ok, max_value} ->
        {:ok, max_value}

      :error ->
        {:error, {:invalid_max_id, {:unknown_int_type, int_type}}}
    end
  end

  defp validate_max_id(integer) when is_integer(integer) do
    case integer >= 0 do
      true -> {:ok, _max_value = integer}
      false -> {:error, {:negative_max_id, integer}}
    end
  end

  defp validate_max_id(invalid_max_id), do: {:error, {:invalid_max_id, invalid_max_id}}

  defp validate_max_ff3_1_value(max_value, algo_ctx) do
    {min_len, max_len} = FF3_1.get_min_and_maxlens!(algo_ctx)
    codec = FF3_1.get_codec!(algo_ctx)
    plaintext = Codec.str_m_radix(codec, _m = 0, max_value)

    case String.length(plaintext) do
      encoded_length when encoded_length in min_len..max_len ->
        {:ok, encoded_length}

      _ ->
        {:error,
         {:encoded_max_id_does_not_fit_ff3_1_domain,
          %{
            encoded_max_id: plaintext,
            min_len: min_len,
            max_len: max_len
          }}}
    end
  end
end
