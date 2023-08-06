defmodule SetupsBuilder do
  @keys %{
    "AES-128" => :crypto.strong_rand_bytes(16),
    #"AES-192" => :crypto.strong_rand_bytes(24),
    #"AES-256" => :crypto.strong_rand_bytes(32)
  }

  #@builtin_radices 2..36
  @builtin_radices [36]
  #@custom_radices Enum.to_list(2..36) ++ [37, 50, 100, 500, 30000]
  @custom_radices [36, 30000]
  @large_alphabet File.read!("test/data/alphabet_0xFFFF_symbols_long.txt")

  def build() do
    @keys
    |> Enum.reduce(_acc = %{}, &over_key/2)
  end

  defp over_key({cipher_type, key}, acc) do
    acc = @builtin_radices
          |> Enum.reduce(acc, &(over_radix(cipher_type, key, :builtin, &1, &2)))

    @custom_radices
    |> Enum.reduce(acc, &(over_radix(cipher_type, key, :custom, &1, &2)))
  end

  defp over_radix(cipher_type, key, builtin_or_custom, radix, acc) do
    ctx = new_ctx(key, builtin_or_custom, radix)

    setup_name = "#{cipher_type}: #{builtin_or_custom} radix #{radix}"
    setup_fun = new_setup_fun(ctx)
    Map.put(acc, setup_name, setup_fun)
  end

  defp new_ctx(key, :builtin, radix) do
    {:ok, ctx} = FF3_1.new_ctx(key, radix)
    ctx
  end

  defp new_ctx(key, :custom, radix) do
    slice_at = ((String.length(@large_alphabet) - radix) |> :rand.uniform()) - 1
    alphabet = String.slice(@large_alphabet, slice_at, radix)
    {:ok, ctx} = FF3_1.new_ctx(key, alphabet)
    ctx
  end

  defp new_setup_fun(ctx) do
    tweak = :crypto.strong_rand_bytes(7)
    codec = FF3_1.codec(ctx)
    %{min_length: min_length} = FF3_1.constraints(ctx)
    fn ->
        int = :rand.uniform(1_000_000_000)
        number_string = codec |> FF3_1.FFX.Codec.int_to_padded_string(int, min_length)
        FF3_1.encrypt!(ctx, tweak, number_string)
    end
  end
end

setups = SetupsBuilder.build()
Benchee.run(setups, warmup: 3, time: 1, parallel: 16)
