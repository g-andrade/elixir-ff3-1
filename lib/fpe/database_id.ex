defmodule FPE.DatabaseId do
  require Record
  import Bitwise

  alias FPE.FF3_1
  alias FPE.FFX.Codec

  ## Constants

  @world_population_2022 7_942_000_000
  @default_carefree_threshold 100 * @world_population_2022

  ## Types

  Record.defrecordp(:fpe_database_id_ctx, [
    :algo,
    :header_shift,
    :body_mask,
    :body_len
  ])

  @type ctx ::
          record(:fpe_database_id_ctx,
            algo: algo,
            header_shift: non_neg_integer,
            body_mask: non_neg_integer,
            body_len: non_neg_integer
          )

  @typep algo :: ff3_1_algo

  # FF3-1 algo

  Record.defrecord(:fpe_database_id_ff3_1, [
    :ctx
  ])

  @typep ff3_1_algo ::
           record(:fpe_database_id_ff3_1,
             ctx: FF3_1.ctx()
           )

  ## API

  def new_ff3_1(key, carefree_threshold \\ @default_carefree_threshold)
      when is_integer(carefree_threshold) and carefree_threshold >= 0 do
    case FF3_1.new_ctx(key, _radix = 16) do
      {:ok, algo_ctx} ->
        header_shift = ceil(:math.log2(carefree_threshold) / 4) * 4
        body_mask = (1 <<< header_shift) - 1
        body_len = div(header_shift, 4)
        algo = fpe_database_id_ff3_1(ctx: algo_ctx)

        {:ok,
         fpe_database_id_ctx(
           algo: algo,
           header_shift: header_shift,
           body_mask: body_mask,
           body_len: body_len
         )}

      {:error, _} = error ->
        error
    end
  end

  def encrypt!(ctx, id) when id >= 0 do
    fpe_database_id_ctx(
      algo: algo,
      header_shift: header_shift,
      body_mask: body_mask,
      body_len: body_len
    ) = ctx

    fpe_database_id_ff3_1(ctx: algo_ctx) = algo
    codec = FF3_1.get_codec!(algo_ctx)

    header = id >>> header_shift
    tweak = <<header::56>>
    plaintext = Codec.str_m_radix(codec, _m = body_len, id &&& body_mask)
    ciphertext = FF3_1.encrypt!(algo_ctx, tweak, plaintext)
    ciphertext_int = Codec.num_radix(codec, ciphertext)

    bor(header <<< header_shift, ciphertext_int)
  end

  def decrypt!(ctx, encrypted_id) when encrypted_id >= 0 do
    fpe_database_id_ctx(
      algo: algo,
      header_shift: header_shift,
      body_mask: body_mask,
      body_len: body_len
    ) = ctx

    fpe_database_id_ff3_1(ctx: algo_ctx) = algo
    codec = FF3_1.get_codec!(algo_ctx)

    header = encrypted_id >>> header_shift
    tweak = <<header::56>>
    ciphertext = Codec.str_m_radix(codec, _m = body_len, encrypted_id &&& body_mask)
    plaintext = FF3_1.decrypt!(algo_ctx, tweak, ciphertext)
    plaintext_int = Codec.num_radix(codec, plaintext)

    bor(header <<< header_shift, plaintext_int)
  end
end
