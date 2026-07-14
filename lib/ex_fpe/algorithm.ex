defprotocol ExFPE.Algorithm do
  @moduledoc false

  alias ExFPE.Codec

  @spec do_encrypt_or_decrypt(t, tweak, codec, input, encrypt?) :: {:ok, output} | {:error, reason}
        when tweak: binary(), codec: Codec.t(), input: term(), encrypt?: boolean, output: term(), reason: term()
  def do_encrypt_or_decrypt(t, tweak, codec, input, encrypt?)
end
