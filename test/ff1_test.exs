# credo:disable-for-this-file Credo.Check.Design.AliasUsage
# credo:disable-for-this-file Credo.Check.Readability.ModuleNames
defmodule FF1_Test do
  use ExUnit.Case, async: true

  ## Official NIST FF1 sample vectors, from the "Examples with Intermediate
  ## Values" published for SP 800-38G:
  ## https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/FF1samples.pdf
  ##
  ## Cross-checked against capitalone/fpe's ff1_test.go. The radix-36 vectors use
  ## a lowercase plaintext/ciphertext in the source; here they are upcased because
  ## the Builtin base-36 codec is case-insensitive on input and canonicalizes its
  ## output to uppercase.

  test "NIST FF1 sample 1 (AES-128, radix 10, empty tweak)" do
    check_test_vector(
      hex("2B7E151628AED2A6ABF7158809CF4F3C"),
      "",
      "0123456789",
      "2433477484",
      10
    )
  end

  test "NIST FF1 sample 2 (AES-128, radix 10, 10-byte tweak)" do
    check_test_vector(
      hex("2B7E151628AED2A6ABF7158809CF4F3C"),
      hex("39383736353433323130"),
      "0123456789",
      "6124200773",
      10
    )
  end

  test "NIST FF1 sample 3 (AES-128, radix 36, 11-byte tweak)" do
    check_test_vector(
      hex("2B7E151628AED2A6ABF7158809CF4F3C"),
      hex("3737373770717273373737"),
      String.upcase("0123456789abcdefghi"),
      String.upcase("a9tv40mll9kdu509eum"),
      36
    )
  end

  test "NIST FF1 sample 4 (AES-192, radix 10, empty tweak)" do
    check_test_vector(
      hex("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F"),
      "",
      "0123456789",
      "2830668132",
      10
    )
  end

  test "NIST FF1 sample 5 (AES-192, radix 10, 10-byte tweak)" do
    check_test_vector(
      hex("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F"),
      hex("39383736353433323130"),
      "0123456789",
      "2496655549",
      10
    )
  end

  test "NIST FF1 sample 6 (AES-192, radix 36, 11-byte tweak)" do
    check_test_vector(
      hex("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F"),
      hex("3737373770717273373737"),
      String.upcase("0123456789abcdefghi"),
      String.upcase("xbj3kv35jrawxv32ysr"),
      36
    )
  end

  test "NIST FF1 sample 7 (AES-256, radix 10, empty tweak)" do
    check_test_vector(
      hex("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94"),
      "",
      "0123456789",
      "6657667009",
      10
    )
  end

  test "NIST FF1 sample 8 (AES-256, radix 10, 10-byte tweak)" do
    check_test_vector(
      hex("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94"),
      hex("39383736353433323130"),
      "0123456789",
      "1001623463",
      10
    )
  end

  test "NIST FF1 sample 9 (AES-256, radix 36, 11-byte tweak)" do
    check_test_vector(
      hex("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94"),
      hex("3737373770717273373737"),
      String.upcase("0123456789abcdefghi"),
      String.upcase("xs8a0azh2avyalyzuwd"),
      36
    )
  end

  ## Helpers

  defp check_test_vector(key, tweak, plaintext, ciphertext, radix_or_alphabet) do
    {:ok, fpe} = FPE.new(key, FPE.FF1, radix_or_alphabet)
    assert FPE.encrypt!(fpe, tweak, plaintext) == ciphertext
    assert FPE.decrypt!(fpe, tweak, ciphertext) == plaintext
  end

  defp hex(string), do: Base.decode16!(string, case: :mixed)
end
