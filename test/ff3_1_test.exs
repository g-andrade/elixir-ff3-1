# credo:disable-for-this-file Credo.Check.Design.AliasUsage
# credo:disable-for-this-file Credo.Check.Readability.ModuleNames
defmodule FF3_1_Test do
  use ExUnit.Case, async: true

  alias FPE.FF3_1.Setup.Server
  alias FPE.FFX.Codec.Custom

  doctest FPE.FF3_1

  # has different representations under different norms
  @letter_a_with_ring_above "Å"

  integer_otp_release = :otp_release |> :erlang.system_info() |> List.to_integer()

  ## I didn't find any official test vectors, so I copied the ones from ubiq-go:
  ## * https://github.com/ubiqsecurity/ubiq-fpe-go/blob/63af101126699b7438045844d0f25120e424789d/ff3_1_test.go

  test "ubiq-go TestFF3_1ACVP1" do
    check_test_vector(
      <<
        0xAD,
        0x41,
        0xEC,
        0x5D,
        0x23,
        0x56,
        0xDE,
        0xAE,
        0x53,
        0xAE,
        0x76,
        0xF5,
        0x0B,
        0x4B,
        0xA6,
        0xD2
      >>,
      <<
        0xCF,
        0x29,
        0xDA,
        0x1E,
        0x18,
        0xD9,
        0x70
      >>,
      "6520935496",
      "4716569208",
      10
    )
  end

  test "ubiq-go TestFF3_1ACVP2" do
    check_test_vector(
      <<
        0x3C,
        0x0A,
        0xBB,
        0x8C,
        0x4D,
        0x50,
        0x52,
        0x83,
        0x20,
        0xED,
        0x6E,
        0xF4,
        0xF5,
        0x36,
        0x37,
        0x1C
      >>,
      <<
        0x2E,
        0x0B,
        0x7E,
        0xE0,
        0x1C,
        0x13,
        0x70
      >>,
      "37411281822299620587806308530316674537844784195073078382",
      "45217408528208365340847148215470453887037524494034613315",
      10
    )
  end

  test "ubiq-go TestFF3_1ACV3" do
    check_test_vector(
      <<
        0xF0,
        0x09,
        0x75,
        0x94,
        0x80,
        0x5C,
        0xF9,
        0xB8,
        0x3B,
        0x86,
        0x5A,
        0xC2,
        0xE8,
        0x6A,
        0xAA,
        0x3B
      >>,
      <<
        0xA8,
        0x64,
        0xBF,
        0xDB,
        0x7A,
        0xB3,
        0xE4
      >>,
      "884423490276892452986545",
      "886740195115224033771281",
      10
    )
  end

  test "ubiq-go TestFF3_1ACVP4" do
    check_test_vector(
      <<
        0xA4,
        0xD5,
        0x91,
        0x50,
        0xBA,
        0x52,
        0x39,
        0x29,
        0xF2,
        0x53,
        0x6E,
        0x22,
        0xDC,
        0xD9,
        0x83,
        0x3A
      >>,
      <<
        0xC6,
        0x18,
        0xE4,
        0xB9,
        0xF1,
        0x02,
        0xA9
      >>,
      "5121915885157704276490198331789119695462135673546462",
      "8700695822600163129327075842807189794897935821179979",
      10
    )
  end

  test "ubiq-go TestFF3_1ACVP5" do
    check_test_vector(
      <<
        0x65,
        0xAE,
        0xC3,
        0x2C,
        0xD5,
        0x00,
        0x5E,
        0x9D,
        0x4F,
        0xE0,
        0x33,
        0x7D,
        0x75,
        0x0F,
        0x88,
        0x89
      >>,
      <<
        0x22,
        0x56,
        0x6B,
        0x02,
        0xCE,
        0x2B,
        0x29
      >>,
      "579835153593770625247573877144356016354",
      "139570038859733375828972899639612707646",
      10
    )
  end

  test "ubiq-go TestFF3_1ACVP6" do
    check_test_vector(
      <<
        0xDA,
        0x0C,
        0x33,
        0x07,
        0xFD,
        0x18,
        0x4C,
        0x1E,
        0x47,
        0xFF,
        0x9B,
        0x8A,
        0xCF,
        0xD7,
        0x53,
        0x05
      >>,
      <<
        0xD9,
        0xF1,
        0xAB,
        0xD9,
        0xC7,
        0xCE,
        0x64
      >>,
      "16554083965640402",
      "92429329291203011",
      10
    )
  end

  test "ubiq-go TestFF3_1ACVP7" do
    check_test_vector(
      <<
        0x96,
        0x04,
        0x0C,
        0x3B,
        0xD2,
        0x8C,
        0xAC,
        0xF5,
        0xBB,
        0xC1,
        0x04,
        0xE1,
        0x7B,
        0x71,
        0xC2,
        0x92
      >>,
      <<
        0x75,
        0xA8,
        0x90,
        0x2A,
        0x2C,
        0x33,
        0xAB
      >>,
      "673355560820242081637314985809466",
      "978822369712766543147569600748825",
      10
    )
  end

  test "ubiq-go TestFF3_1ACVP8" do
    check_test_vector(
      <<
        0x47,
        0xD6,
        0xFD,
        0x00,
        0x7E,
        0x50,
        0x02,
        0x42,
        0x40,
        0xB5,
        0xD5,
        0x02,
        0xDB,
        0x5B,
        0x4A,
        0x6A
      >>,
      <<
        0xD3,
        0x39,
        0x9B,
        0xF9,
        0x3C,
        0xC1,
        0x0C
      >>,
      "3136368918758657833514782148219054962724377646545",
      "8465961639246937993407777533030559401101453326524",
      10
    )
  end

  test "ubiq-go TestFF3_1ACVP9" do
    check_test_vector(
      <<
        0xA8,
        0x4B,
        0xB5,
        0x54,
        0x85,
        0x4D,
        0xCA,
        0xB9,
        0xCB,
        0xFD,
        0x9E,
        0x29,
        0x80,
        0x01,
        0x51,
        0x8C
      >>,
      <<
        0x7A,
        0x77,
        0x31,
        0x72,
        0xC3,
        0xF0,
        0xF1
      >>,
      "082360355025",
      "901934302943",
      10
    )
  end

  test "ubiq-go TestFF3_1ACVP10" do
    check_test_vector(
      <<
        0xA0,
        0x0F,
        0xCE,
        0xDF,
        0x1C,
        0xE6,
        0xE3,
        0x5C,
        0xF9,
        0x09,
        0x7E,
        0x98,
        0xDC,
        0x4D,
        0x28,
        0x4D
      >>,
      <<
        0x00,
        0x69,
        0x85,
        0xBC,
        0x0E,
        0x67,
        0x2C
      >>,
      "63987540055130890395",
      "73110711860320595989",
      10
    )
  end

  test "ubiq-go TestFF3_1Ubiq1" do
    check_test_vector(
      <<
        0xEF,
        0x43,
        0x59,
        0xD8,
        0xD5,
        0x80,
        0xAA,
        0x4F,
        0x7F,
        0x03,
        0x6D,
        0x6F,
        0x04,
        0xFC,
        0x6A,
        0x94
      >>,
      <<
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00
      >>,
      "890121234567890000",
      "075870132022772250",
      10
    )
  end

  test "ubiq-go TestFF3_1Ubiq2" do
    check_test_vector(
      <<
        0xEF,
        0x43,
        0x59,
        0xD8,
        0xD5,
        0x80,
        0xAA,
        0x4F,
        0x7F,
        0x03,
        0x6D,
        0x6F,
        0x04,
        0xFC,
        0x6A,
        0x94
      >>,
      <<
        0x39,
        0x38,
        0x37,
        0x36,
        0x35,
        0x34,
        0x33
      >>,
      "890121234567890000",
      "251467746185412673",
      10
    )
  end

  test "ubiq-go TestFF3_1Ubiq3" do
    check_test_vector(
      <<
        0xEF,
        0x43,
        0x59,
        0xD8,
        0xD5,
        0x80,
        0xAA,
        0x4F,
        0x7F,
        0x03,
        0x6D,
        0x6F,
        0x04,
        0xFC,
        0x6A,
        0x94
      >>,
      <<
        0x37,
        0x37,
        0x37,
        0x37,
        0x70,
        0x71,
        0x72
      >>,
      "89012123456789ABCDE",
      "DWB01MX9AA2LMI3HRFM",
      36
    )
  end

  test "ubiq-go TestFF3_1Ubiq4" do
    check_test_vector(
      <<
        0xEF,
        0x43,
        0x59,
        0xD8,
        0xD5,
        0x80,
        0xAA,
        0x4F,
        0x7F,
        0x03,
        0x6D,
        0x6F,
        0x04,
        0xFC,
        0x6A,
        0x94,
        0x3B,
        0x80,
        0x6A,
        0xEB,
        0x63,
        0x08,
        0x27,
        0x1F
      >>,
      <<
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00
      >>,
      "890121234567890000",
      "327701863379108161",
      10
    )
  end

  test "ubiq-go TestFF3_1Ubiq5" do
    check_test_vector(
      <<
        0xEF,
        0x43,
        0x59,
        0xD8,
        0xD5,
        0x80,
        0xAA,
        0x4F,
        0x7F,
        0x03,
        0x6D,
        0x6F,
        0x04,
        0xFC,
        0x6A,
        0x94,
        0x3B,
        0x80,
        0x6A,
        0xEB,
        0x63,
        0x08,
        0x27,
        0x1F
      >>,
      <<
        0x39,
        0x38,
        0x37,
        0x36,
        0x35,
        0x34,
        0x33
      >>,
      "890121234567890000",
      "738670454850774517",
      10
    )
  end

  test "ubiq-go TestFF3_1Ubiq6" do
    check_test_vector(
      <<
        0xEF,
        0x43,
        0x59,
        0xD8,
        0xD5,
        0x80,
        0xAA,
        0x4F,
        0x7F,
        0x03,
        0x6D,
        0x6F,
        0x04,
        0xFC,
        0x6A,
        0x94,
        0x3B,
        0x80,
        0x6A,
        0xEB,
        0x63,
        0x08,
        0x27,
        0x1F
      >>,
      <<
        0x37,
        0x37,
        0x37,
        0x37,
        0x70,
        0x71,
        0x72
      >>,
      "89012123456789ABCDE",
      "O3A1OG390B5UDUVWYW5",
      36
    )
  end

  test "ubiq-go TestFF3_1Ubiq7" do
    check_test_vector(
      <<
        0xEF,
        0x43,
        0x59,
        0xD8,
        0xD5,
        0x80,
        0xAA,
        0x4F,
        0x7F,
        0x03,
        0x6D,
        0x6F,
        0x04,
        0xFC,
        0x6A,
        0x94,
        0x3B,
        0x80,
        0x6A,
        0xEB,
        0x63,
        0x08,
        0x27,
        0x1F,
        0x65,
        0xCF,
        0x33,
        0xC7,
        0x39,
        0x1B,
        0x27,
        0xF7
      >>,
      <<
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00
      >>,
      "890121234567890000",
      "892299037726855422",
      10
    )
  end

  test "ubiq-go TestFF3_1Ubiq8" do
    check_test_vector(
      <<
        0xEF,
        0x43,
        0x59,
        0xD8,
        0xD5,
        0x80,
        0xAA,
        0x4F,
        0x7F,
        0x03,
        0x6D,
        0x6F,
        0x04,
        0xFC,
        0x6A,
        0x94,
        0x3B,
        0x80,
        0x6A,
        0xEB,
        0x63,
        0x08,
        0x27,
        0x1F,
        0x65,
        0xCF,
        0x33,
        0xC7,
        0x39,
        0x1B,
        0x27,
        0xF7
      >>,
      <<
        0x39,
        0x38,
        0x37,
        0x36,
        0x35,
        0x34,
        0x33
      >>,
      "890121234567890000",
      "045013216693726967",
      10
    )
  end

  test "ubiq-go TestFF3_1Ubiq9" do
    check_test_vector(
      <<
        0xEF,
        0x43,
        0x59,
        0xD8,
        0xD5,
        0x80,
        0xAA,
        0x4F,
        0x7F,
        0x03,
        0x6D,
        0x6F,
        0x04,
        0xFC,
        0x6A,
        0x94,
        0x3B,
        0x80,
        0x6A,
        0xEB,
        0x63,
        0x08,
        0x27,
        0x1F,
        0x65,
        0xCF,
        0x33,
        0xC7,
        0x39,
        0x1B,
        0x27,
        0xF7
      >>,
      <<
        0x37,
        0x37,
        0x37,
        0x37,
        0x70,
        0x71,
        0x72
      >>,
      "89012123456789ABCDE",
      "0SXAOOJ0JJJ5QQFOMH8",
      36
    )
  end

  ##

  if integer_otp_release < 27 do
    # Missing Unicode metadata
    @tag :skip
  end

  test "ubiq-go TestFF3_1UTF8" do
    check_test_vector(
      <<
        0x2B,
        0x7E,
        0x15,
        0x16,
        0x28,
        0xAE,
        0xD2,
        0xA6,
        0xAB,
        0xF7,
        0x15,
        0x88,
        0x09,
        0xCF,
        0x4F,
        0x3C,
        0xEF,
        0x43,
        0x59,
        0xD8,
        0xD5,
        0x80,
        0xAA,
        0x4F,
        0x7F,
        0x03,
        0x6D,
        0x6F,
        0x04,
        0xFC,
        0x6A,
        0x94
      >>,
      <<
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00
      >>,
      "こんにちは世界",
      "lscveにr",
      "abcdefghijklmnopqrstuvwxyzこんにちは世界"
    )
  end

  test "explicit alphabet matches builtin decimal" do
    check_test_vector(
      <<63, 89, 255, 222, 188, 211, 44, 18, 129, 227, 228, 6, 210, 23, 145, 98, 144, 216, 104, 61, 203, 144, 121, 253>>,
      <<10, 154, 124, 214, 232, 247, 159>>,
      "0000000000000",
      "0973773893290",
      "0123456789"
    )
  end

  test "explicit alphabet matches builtin base 11" do
    check_test_vector(
      <<63, 89, 255, 222, 188, 211, 44, 18, 129, 227, 228, 6, 210, 23, 145, 98, 144, 216, 104, 61, 203, 144, 121, 253>>,
      <<10, 154, 124, 214, 232, 247, 159>>,
      "0000000000000",
      "00A963AA50706",
      "0123456789A"
    )
  end

  test "explicit alphabet matches lower builtin base 11" do
    check_test_vector(
      <<63, 89, 255, 222, 188, 211, 44, 18, 129, 227, 228, 6, 210, 23, 145, 98, 144, 216, 104, 61, 203, 144, 121, 253>>,
      <<10, 154, 124, 214, 232, 247, 159>>,
      "0000000000000",
      "00a963aa50706",
      "0123456789a"
    )
  end

  test "explicit alphabet matches lower builtin hex" do
    check_test_vector(
      <<63, 89, 255, 222, 188, 211, 44, 18, 129, 227, 228, 6, 210, 23, 145, 98, 144, 216, 104, 61, 203, 144, 121, 253>>,
      <<10, 154, 124, 214, 232, 247, 159>>,
      "0000000000000",
      "ceedaa52eec58",
      "0123456789abcdef"
    )
  end

  test "explicit alphabet matches builtin base 36" do
    check_test_vector(
      <<63, 89, 255, 222, 188, 211, 44, 18, 129, 227, 228, 6, 210, 23, 145, 98, 144, 216, 104, 61, 203, 144, 121, 53>>,
      <<10, 154, 124, 214, 232, 247, 159>>,
      "0000000000000",
      "VYZB0ULDK6REY",
      "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    )
  end

  test "explicit alphabet matches lower builtin base 36" do
    check_test_vector(
      <<63, 89, 255, 222, 188, 211, 44, 18, 129, 227, 228, 6, 210, 23, 145, 98, 144, 216, 104, 61, 203, 144, 121, 25>>,
      <<10, 154, 124, 214, 232, 247, 159>>,
      "0000000000000",
      "3x981nkki3avx",
      "0123456789abcdefghijklmnopqrstuvwxyz"
    )
  end

  test "custom upper case alphabet for base 37" do
    check_test_vector(
      <<63, 89, 255, 222, 188, 211, 44, 18, 129, 227, 228, 6, 210, 23, 145, 98, 144, 216, 104, 61, 203, 14, 121, 53>>,
      <<10, 154, 124, 214, 232, 247, 159>>,
      "0000000000000",
      "RKEC2GGAPM@NI",
      "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ@"
    )
  end

  test "custom lower case alphabet for base 37" do
    check_test_vector(
      <<63, 89, 255, 22, 18, 211, 44, 18, 129, 227, 228, 6, 210, 23, 145, 98, 144, 216, 104, 61, 203, 14, 121, 53>>,
      <<10, 154, 124, 214, 232, 247, 159>>,
      "0000000000000",
      "8iq56yqgurap0",
      "0123456789abcdefghijklmnopqrstuvwxyz@"
    )
  end

  test "zero is not ?0" do
    check_test_vector(
      <<6, 89, 255, 22, 18, 211, 44, 18, 129, 227, 228, 6, 210, 23, 145, 98, 144, 216, 104, 61, 203, 14, 121, 53>>,
      <<10, 124, 124, 214, 232, 247, 159>>,
      "OOOOOO",
      "O41451",
      "O123456789"
    )
  end

  test "unibyte custom alphabet" do
    check_test_vector(
      <<63, 89, 255, 222, 188, 211, 44, 18, 129, 227, 228, 6, 210, 23, 145, 98, 144, 216, 104, 61, 203, 144, 121, 252>>,
      <<10, 154, 124, 214, 232, 247, 154>>,
      "0000000000000",
      "9638mpppt4t07",
      "a4t6p9m3780"
    )
  end

  test "alphabet with mergeable codepoints is rejected" do
    key =
      <<63, 89, 255, 222, 188, 211, 44, 18, 129, 227, 228, 6, 210, 23, 145, 98, 144, 216, 104, 61, 203, 144, 121, 251>>

    assert FPE.new(key, :ff3_1, "🙌🙌🏻🙌🏼🙌🏽🙌🏾🙌🏿") ===
             {:error,
              {:invalid_codepoints,
               [
                 {"🏻", :merges_with_adjacent_symbols},
                 {"🏼", :merges_with_adjacent_symbols},
                 {"🏽", :merges_with_adjacent_symbols},
                 {"🏾", :merges_with_adjacent_symbols},
                 {"🏿", :merges_with_adjacent_symbols}
               ]}}
  end

  test "builtin alphabet is case insensitive" do
    key = :crypto.strong_rand_bytes(32)
    {:ok, ctx} = FPE.new(key, :ff3_1, _radix = 16)
    tweak = :crypto.strong_rand_bytes(7)

    plaintext = "aabbcd1512f"
    ciphertext = FPE.encrypt!(ctx, tweak, plaintext)

    Enum.each(
      1..20,
      fn _attempt_nr ->
        modified_plaintext = randomly_change_case(plaintext)
        assert FPE.encrypt!(ctx, tweak, modified_plaintext) == ciphertext
      end
    )

    ciphertext = "aabbcd1512f"
    plaintext = FPE.decrypt!(ctx, tweak, ciphertext)

    Enum.each(
      1..20,
      fn _attempt_nr ->
        modified_ciphertext = randomly_change_case(ciphertext)
        assert FPE.decrypt!(ctx, tweak, modified_ciphertext) == plaintext
      end
    )
  end

  test "custom alphabet is case sensitive" do
    key = :crypto.strong_rand_bytes(32)
    alphabet = "abcdéfgHijk🪩lMnoPqRsTuV"
    {:ok, ctx} = FPE.new(key, :ff3_1, alphabet)
    tweak = :crypto.strong_rand_bytes(7)

    plaintext = "b🪩cdéfgHilMnoPqRsTuV"
    ciphertext = FPE.encrypt!(ctx, tweak, plaintext)

    Enum.each(
      1..20,
      fn _attempt_nr ->
        modified_plaintext = randomly_change_case(plaintext)

        if modified_plaintext == plaintext do
          assert FPE.encrypt!(ctx, tweak, modified_plaintext) == ciphertext
        else
          assert catch_error(FPE.encrypt!(ctx, tweak, modified_plaintext))
        end
      end
    )

    ciphertext = "b🪩cdéfgHilMnoPqRsTuV"
    plaintext = FPE.encrypt!(ctx, tweak, ciphertext)

    Enum.each(
      1..20,
      fn _attempt_nr ->
        modified_ciphertext = randomly_change_case(ciphertext)

        if modified_ciphertext == ciphertext do
          assert FPE.decrypt!(ctx, tweak, modified_ciphertext) == plaintext
        else
          assert catch_error(FPE.decrypt!(ctx, tweak, modified_ciphertext))
        end
      end
    )
  end

  test "custom alphabet is norm insensitive" do
    key = :crypto.strong_rand_bytes(32)
    alphabet = "abcdéfgHijk🪩lMnoP#{@letter_a_with_ring_above}qRsTuV"
    {:ok, ctx} = FPE.new(key, :ff3_1, alphabet)
    tweak = :crypto.strong_rand_bytes(7)

    plaintext = "b🪩cd#{@letter_a_with_ring_above}éfgHilMnoPqRsTuV"
    ciphertext = FPE.encrypt!(ctx, tweak, plaintext)

    Enum.each(
      1..20,
      fn _attempt_nr ->
        modified_plaintext = randomly_change_norm(plaintext)
        assert FPE.encrypt!(ctx, tweak, modified_plaintext) == ciphertext
      end
    )

    ciphertext = "b🪩cd#{@letter_a_with_ring_above}éfgHilMnoPqRsTuV"
    plaintext = FPE.decrypt!(ctx, tweak, ciphertext)

    Enum.each(
      1..20,
      fn _attempt_nr ->
        modified_ciphertext = randomly_change_norm(ciphertext)
        assert FPE.decrypt!(ctx, tweak, modified_ciphertext) == plaintext
      end
    )
  end

  test "invalid keys are rejected" do
    key = ~c"key"
    {:error, {:key_not_a_binary, ^key}} = FPE.new(key, :ff3_1, _radix = 10)

    Enum.each(
      1..100,
      fn key_size ->
        key = :crypto.strong_rand_bytes(key_size)

        if key_size in [16, 24, 32] do
          {:ok, _ctx} = FPE.new(key, :ff3_1, _radix = 10)
        else
          {:error, {:key_has_invalid_size, ^key_size}} = FPE.new(key, :ff3_1, _radix = 10)
        end
      end
    )
  end

  test "small alphabets and radixes" do
    key = :crypto.strong_rand_bytes(24)

    alphabet = ""
    {:error, {:alphabet_smaller_than_min_radix, 2}} = FPE.new(key, :ff3_1, alphabet)
    {:error, {:invalid_radix, {0, :less_than_minimum, 2}}} = FPE.new(key, :ff3_1, _radix = 0)

    alphabet = "0"
    {:error, {:alphabet_smaller_than_min_radix, 2}} = FPE.new(key, :ff3_1, alphabet)
    {:error, {:invalid_radix, {1, :less_than_minimum, 2}}} = FPE.new(key, :ff3_1, _radix = 1)

    alphabet = "01"
    {:ok, _ctx} = FPE.new(key, :ff3_1, alphabet)
    {:ok, _ctx} = FPE.new(key, :ff3_1, _radix = 2)
  end

  ##

  if integer_otp_release < 28 do
    # Missing Unicode metadata
    @tag :skip
  end

  test "large alphabets" do
    key = :crypto.strong_rand_bytes(24)

    alphabet = "test/data/alphabet_500_symbols_long.txt" |> File.read!() |> String.trim()
    {:ok, _ctx} = FPE.new(key, :ff3_1, alphabet)

    alphabet = "test/data/alphabet_1000_symbols_long.txt" |> File.read!() |> String.trim()
    {:ok, _ctx} = FPE.new(key, :ff3_1, alphabet)

    alphabet = "test/data/alphabet_10000_symbols_long.txt" |> File.read!() |> String.trim()
    {:ok, _ctx} = FPE.new(key, :ff3_1, alphabet)

    alphabet = "test/data/alphabet_0xFFFF_symbols_long.txt" |> File.read!() |> String.trim()
    {:ok, _ctx} = FPE.new(key, :ff3_1, alphabet)

    alphabet = "test/data/alphabet_0x10000_symbols_long.txt" |> File.read!() |> String.trim()
    {:error, {:alphabet_larger_than_max_radix, 0xFFFF}} = FPE.new(key, :ff3_1, alphabet)
  end

  test "alphabets with repeated symbols are rejected" do
    key = :crypto.strong_rand_bytes(16)
    alphabet = "01234567389"
    {:error, {:alphabet_has_repeated_symbols, ["3"]}} = FPE.new(key, :ff3_1, alphabet)
  end

  test "unknown symbols are rejected - builtin alphabet" do
    key = :crypto.strong_rand_bytes(24)
    tweak = :crypto.strong_rand_bytes(7)
    {:ok, ctx} = FPE.new(key, :ff3_1, _radix = 10)
    assert catch_error(FPE.encrypt!(ctx, tweak, "aaaaaaa"))
    assert catch_error(FPE.decrypt!(ctx, tweak, "aaaaaaa"))
  end

  test "unknown symbols are rejected - custom alphabet" do
    key = :crypto.strong_rand_bytes(24)
    tweak = :crypto.strong_rand_bytes(7)
    {:ok, ctx} = FPE.new(key, :ff3_1, _alphabet = "abcdefghijklmn")
    assert catch_error(FPE.encrypt!(ctx, tweak, "abcdefgzzzz"))
    assert catch_error(FPE.decrypt!(ctx, tweak, "abcdefgzzzz"))
  end

  describe "Custom.new/1 accepts" do
    test "plain ASCII digits and letters" do
      assert {:ok, _} = Custom.new("0123456789")
      assert {:ok, _} = Custom.new("abcXYZ")
    end

    test "single-codepoint symbols across scripts, incl. precomposed and standalone emoji" do
      # \u00E9, \u00C5, \uD83E\uDEA9, \uD83D\uDE4C, \uAC00 (precomposed Hangul syllable), \u4E00 (CJK),
      # \u03B1 (Greek), \u0431 (Cyrillic), \u20AC (currency)
      for codepoint <- [0x00E9, 0x00C5, 0x1FAA9, 0x1F64C, 0xAC00, 0x4E00, 0x03B1, 0x0431, 0x20AC] do
        assert {:ok, _} = Custom.new(<<codepoint::utf8>>),
               "expected U+#{Integer.to_string(codepoint, 16)} to be accepted"
      end
    end

    test "Custom.new/1 itself does not enforce a minimum radix (FPE.FF3_1.new_ctx does)" do
      # radix 0 and 1 are accepted here; the 2..0xFFFF bound lives in new_ctx.
      assert {:ok, _} = Custom.new("")
      assert {:ok, _} = Custom.new("x")
    end
  end

  describe "Custom.new/1 rejects" do
    test "unassigned, control, format and private-use codepoints (category :other)" do
      assert reason_for(0x0378) == {:invalid_category, {:other, :not_assigned}}
      assert reason_for(0x0007) == {:invalid_category, {:other, :control}}
      assert reason_for(0x200D) == {:invalid_category, {:other, :format}}
      assert reason_for(0xE000) == {:invalid_category, {:other, :private}}
    end

    test "whitespace and separators (categories Zs/Zl/Zp)" do
      # space, no-break space, ideographic space (Zs); line and paragraph
      # separators (Zl/Zp). All are lone, NFC-stable, standalone starters that
      # pass every other check but are rejected on practical grounds.
      assert reason_for(0x0020) == {:invalid_category, {:separator, :space}}
      assert reason_for(0x00A0) == {:invalid_category, {:separator, :space}}
      assert reason_for(0x3000) == {:invalid_category, {:separator, :space}}
      assert reason_for(0x2028) == {:invalid_category, {:separator, :line}}
      assert reason_for(0x2029) == {:invalid_category, {:separator, :paragraph}}
    end

    test "combining marks with a nonzero combining class" do
      assert reason_for(0x0301) == {:invalid_combining_class, 230}
      assert reason_for(0x030A) == {:invalid_combining_class, 230}
    end

    test "conjoining Hangul jamo across all three blocks" do
      # L, V, T in Hangul Jamo; L in Extended-A; V in Extended-B
      for codepoint <- [0x1100, 0x1161, 0x11A8, 0xA960, 0xD7B0] do
        assert reason_for(codepoint) == :conjoining_hangul_jamo
      end
    end

    test "codepoints that are not already in NFC form" do
      assert reason_for(0x2126) == :not_in_nfc_norm
      assert reason_for(0x212B) == :not_in_nfc_norm
    end

    test "the decomposed (NFD) form of an otherwise-valid symbol" do
      # Å is fine supplied precomposed (U+00C5) but not decomposed as
      # A + combining ring: the combining mark is rejected on its own.
      precomposed = :unicode.characters_to_nfc_binary(@letter_a_with_ring_above)
      decomposed = :unicode.characters_to_nfd_binary(@letter_a_with_ring_above)

      assert {:ok, _} = Custom.new("a#{precomposed}b")

      [_a, combining_ring] = String.codepoints(decomposed)

      assert Custom.new("a#{decomposed}b") ==
               {:error, {:invalid_codepoints, [{combining_ring, {:invalid_combining_class, 230}}]}}
    end

    test "codepoints that would merge with an adjacent symbol" do
      # emoji modifier and regional indicator (join via emoji rules), a prepend
      # letter (joins the following symbol), and combining-class-0 marks (VS16,
      # enclosing keycap, spacing mark) that slip the combining-class check but
      # are caught here.
      for codepoint <- [0x1F3FB, 0x1F1E6, 0x0D4E, 0xFE0F, 0x20E3, 0x093E] do
        assert reason_for(codepoint) == :merges_with_adjacent_symbols
      end
    end

    test "and collects every invalid codepoint, in order, each with its reason" do
      alphabet = "a" <> <<0x0301::utf8>> <> "b" <> <<0x200D::utf8>> <> "c"

      assert Custom.new(alphabet) ==
               {:error,
                {:invalid_codepoints,
                 [
                   {<<0x0301::utf8>>, {:invalid_combining_class, 230}},
                   {<<0x200D::utf8>>, {:invalid_category, {:other, :format}}}
                 ]}}
    end

    test "invalid UTF-8, before any per-codepoint check" do
      assert Custom.new(<<0xFF, 0xFE>>) == {:error, {:alphabet_not_valid_utf8, <<0xFF, 0xFE>>}}
    end

    test "repeated symbols" do
      assert Custom.new("abca") == {:error, {:alphabet_has_repeated_symbols, ["a"]}}

      raising_hands = <<0x1F64C::utf8>>

      assert Custom.new("ab" <> raising_hands <> raising_hands) ==
               {:error, {:alphabet_has_repeated_symbols, [raising_hands]}}
    end

    test "an invalid codepoint in preference to a repeat (codepoint validation runs first)" do
      # 'a' is repeated, but the combining mark fails before uniqueness is checked.
      assert Custom.new("ab" <> <<0x0301::utf8>> <> "a") ==
               {:error, {:invalid_codepoints, [{<<0x0301::utf8>>, {:invalid_combining_class, 230}}]}}
    end
  end

  test "the undocumented :unicode_util.lookup/1 shape the codec relies on is intact" do
    # We depend on OTP internals for category/combining-class; pin the shape so
    # an OTP change fails loudly here rather than silently in validation.
    assert %{category: {:mark, :non_spacing}, ccc: 230} = :unicode_util.lookup(0x0301)
    assert %{category: {:letter, :lowercase}, ccc: 0} = :unicode_util.lookup(?a)
    assert %{category: {:other, :not_assigned}} = :unicode_util.lookup(0x0378)
    assert %{category: {:separator, :space}} = :unicode_util.lookup(0x0020)
  end

  test "badly sized strings are rejected" do
    key = :crypto.strong_rand_bytes(24)
    tweak = :crypto.strong_rand_bytes(7)
    {:ok, ctx} = FPE.new(key, :ff3_1, _radix = 10)
    %{min_length: min_length, max_length: max_length} = FPE.FF3_1.constraints(ctx.algorithm)

    short_string = String.duplicate("0", min_length - 1)
    assert catch_error(FPE.encrypt!(ctx, tweak, short_string))
    assert catch_error(FPE.decrypt!(ctx, tweak, short_string))

    long_string = String.duplicate("0", max_length + 1)
    assert catch_error(FPE.encrypt!(ctx, tweak, long_string))
    assert catch_error(FPE.decrypt!(ctx, tweak, long_string))
  end

  test "custom alphabets: badly encoded strings are rejected" do
    key = :crypto.strong_rand_bytes(24)

    alphabet = "abcdefghijklmn"
    {:ok, ctx} = FPE.new(key, :ff3_1, alphabet)

    tweak = :crypto.strong_rand_bytes(7)
    input = "aaaaaaaaa" <> <<251, 251>>
    assert catch_error(FPE.encrypt!(ctx, tweak, input))
    assert catch_error(FPE.decrypt!(ctx, tweak, input))
  end

  test "invalid tweaks are rejected" do
    key = :crypto.strong_rand_bytes(24)
    {:ok, ctx} = FPE.new(key, :ff3_1, _radix = 10)
    input = "1234567"

    tweak = <<0::48>>
    assert catch_error(FPE.encrypt!(ctx, tweak, input))
    assert catch_error(FPE.decrypt!(ctx, tweak, input))

    tweak = <<0::64>>
    assert catch_error(FPE.encrypt!(ctx, tweak, input))
    assert catch_error(FPE.decrypt!(ctx, tweak, input))

    tweak = ~c"0000000"
    assert catch_error(FPE.encrypt!(ctx, tweak, input))
    assert catch_error(FPE.decrypt!(ctx, tweak, input))
  end

  test "builtin codec can be extracted and used" do
    alias FPE.FFX.Codec

    key = :crypto.strong_rand_bytes(24)
    {:ok, ctx} = FPE.new(key, :ff3_1, _radix = 10)

    codec = FPE.FF3_1.codec(ctx.algorithm)
    assert Codec.numerical_string_to_int(codec, "234234638") == {:ok, 234_234_638}
    assert Codec.int_to_padded_numerical_string(codec, 234_234_638, _padding = 10) == "0234234638"
  end

  test "custom codec can be extracted and used" do
    alias FPE.FFX.Codec

    key = :crypto.strong_rand_bytes(24)
    {:ok, ctx} = FPE.new(key, :ff3_1, _alphabet = "012345678x")

    codec = FPE.FF3_1.codec(ctx.algorithm)
    assert Codec.numerical_string_to_int(codec, ~c"234234638x") == {:ok, 2_342_346_389}
    assert Codec.int_to_padded_numerical_string(codec, 2_342_346_389, _padding = 12) == ~c"00234234638x"
  end

  test "setup modules working fine" do
    alias FF3_1_Test.Helper.SetupModules

    plaintext = "423423409017"
    test_setup_module(SetupModules.BuiltinBase10, plaintext)

    plaintext = "423423017AFDE"
    test_setup_module(SetupModules.BuiltinBase16, plaintext)

    plaintext = "abababcDcDfabi"
    test_setup_module(SetupModules.CustomBase10, plaintext)
  end

  test "setup modules with wrong opts" do
    alias FF3_1_Test.Helper.SetupModules

    _ = Process.flag(:trap_exit, true)

    assert match?(
             {:error, {:key_has_invalid_size, _}},
             SetupModules.WrongKeySize.start_link()
           )

    assert match?(
             {:error, {:invalid_radix, _}},
             SetupModules.InvalidRadix.start_link()
           )

    assert match?(
             {:error, {:alphabet_smaller_than_min_radix, _}},
             SetupModules.InvalidAlphabet.start_link()
           )
  end

  test "setup module server alternative termination flows" do
    alias FF3_1_Test.Helper.SetupModules

    _ = Process.flag(:trap_exit, true)

    {:ok, pid} = SetupModules.BuiltinBase10.start_link()
    assert match?({:ok, _ctx}, Server.get_ctx(SetupModules.BuiltinBase10))
    Server.stop(pid, :"everything's crashing")
    assert match?({:ok, _ctx}, Server.get_ctx(SetupModules.BuiltinBase10))

    {:ok, pid} = SetupModules.BuiltinBase10.start_link()
    Server.stop(pid, :shutdown)

    assert Server.get_ctx(SetupModules.BuiltinBase10) ==
             {:error, {:ctx_not_found_for_module, SetupModules.BuiltinBase10}}

    {:ok, pid} = SetupModules.BuiltinBase10.start_link()
    Server.stop(pid, {:shutdown, :detailed_reason})

    assert Server.get_ctx(SetupModules.BuiltinBase10) ==
             {:error, {:ctx_not_found_for_module, SetupModules.BuiltinBase10}}
  end

  test "no symbols" do
    alias FPE.FFX.Codec.NoSymbols

    key = :crypto.strong_rand_bytes(32)
    tweak = :crypto.strong_rand_bytes(7)

    Enum.each(
      1..100,
      fn _ ->
        radix = 1 + :rand.uniform(1000)

        Enum.each(
          1..100,
          fn _ ->
            {:ok, codec} = NoSymbols.new(radix)
            {:ok, ctx} = FPE.new(key, :ff3_1, codec)
            %{min_length: min_length, max_length: max_length} = FPE.FF3_1.constraints(ctx.algorithm)

            input_length = min_length + :rand.uniform(max_length - min_length + 1) - 1
            input_high = Integer.pow(radix, input_length - 1)
            input_low = :rand.uniform(input_high) - 1
            input = input_high + input_low

            input_num_string = %NoSymbols.NumString{value: input, length: input_length}
            ciphertext = FPE.encrypt!(ctx, tweak, input_num_string)
            assert ciphertext.length == input_num_string.length

            plaintext = FPE.decrypt!(ctx, tweak, ciphertext)
            assert plaintext == input_num_string
          end
        )
      end
    )
  end

  ## Helpers

  # The rejection reason for a single-codepoint alphabet, so per-codepoint
  # validation edge cases read as `assert reason_for(cp) == ...`.
  defp reason_for(codepoint) do
    {:error, {:invalid_codepoints, [{_symbol, reason}]}} = Custom.new(<<codepoint::utf8>>)
    reason
  end

  defp check_test_vector(key, tweak, plaintext, ciphertext, radix_or_alphabet) do
    {:ok, ctx} = FPE.new(key, :ff3_1, radix_or_alphabet)
    assert FPE.encrypt!(ctx, tweak, plaintext) == ciphertext
    assert FPE.decrypt!(ctx, tweak, ciphertext) == plaintext
  end

  defp randomly_change_case(string) do
    string
    |> String.graphemes()
    |> Enum.map(fn grapheme ->
      case :rand.uniform(3) do
        1 ->
          String.downcase(grapheme)

        2 ->
          String.upcase(grapheme)

        3 ->
          grapheme
      end
    end)
    |> List.to_string()
  end

  defp randomly_change_norm(string) do
    string
    |> String.graphemes()
    |> Enum.map(fn grapheme ->
      case :rand.uniform(12) do
        1 ->
          :unicode.characters_to_nfc_binary(grapheme)

        2 ->
          :unicode.characters_to_nfd_binary(grapheme)

        4 ->
          :unicode.characters_to_nfkc_binary(grapheme)

        5 ->
          :unicode.characters_to_nfkd_binary(grapheme)

        _ ->
          grapheme
      end
    end)
    |> List.to_string()
  end

  defp test_setup_module(module, plaintext) do
    assert Server.get_ctx(module) == {:error, {:ctx_not_found_for_module, module}}

    {:ok, pid} = module.start_link()
    {:ok, ctx} = Server.get_ctx(module)

    tweak = :crypto.strong_rand_bytes(7)
    ciphertext = module.encrypt!(tweak, plaintext)
    assert module.decrypt!(tweak, ciphertext) == plaintext

    assert ciphertext == FPE.encrypt!(ctx, tweak, plaintext)
    assert module.constraints() == FPE.FF3_1.constraints(ctx.algorithm)
    assert module.codec() == FPE.FF3_1.codec(ctx.algorithm)

    :ok = Server.stop(pid)
    assert Server.get_ctx(module) == {:error, {:ctx_not_found_for_module, module}}
  end
end
