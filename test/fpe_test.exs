defmodule FpeTest do
  use ExUnit.Case

  test "test vector" do
    ## TODO more test vectors
    ## Got this one from ubiq-fpe-go:
    ## * https://github.com/ubiqsecurity/ubiq-fpe-go/blob/63af101126699b7438045844d0f25120e424789d/ff3_1_test.go

    key = <<
      0xad, 0x41, 0xec, 0x5d, 0x23, 0x56, 0xde, 0xae,
	  0x53, 0xae, 0x76, 0xf5, 0x0b, 0x4b, 0xa6, 0xd2
    >>
    tweak = <<0xcf, 0x29, 0xda, 0x1e, 0x18, 0xd9, 0x70>>

    {:ok, ctx} = FPE.FF3_1.new(key, 10)
    assert "4716569208" == FPE.FF3_1.encrypt!(ctx, tweak, "6520935496")
    assert "6520935496" == FPE.FF3_1.decrypt!(ctx, tweak, "4716569208")
  end
end
