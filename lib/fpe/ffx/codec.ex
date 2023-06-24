defprotocol FPE.FFX.Codec do
  @moduledoc false

  # 4.5, Algorithm 1: NUM_radix(X) -> x
  @spec num_radix(t, String.t()) :: non_neg_integer
  def num_radix(codec, string)

  # 4.5, Algorithm 3: STR_m_radix(X) -> x
  @spec str_m_radix(t, pos_integer, non_neg_integer) :: String.t()
  def str_m_radix(codec, m, int)
end

