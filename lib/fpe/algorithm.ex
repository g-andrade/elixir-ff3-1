defprotocol FPE.Algorithm do
  @spec do_encrypt_or_decrypt(t, tweak, input, encrypt?) :: {:ok, output} | {:error, reason}
        when tweak: binary(), input: binary(), encrypt?: boolean, output: binary(), reason: term()
  def do_encrypt_or_decrypt(t, tweak, input, encrypt?)
end
