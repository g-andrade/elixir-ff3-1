# credo:disable-for-this-file Credo.Check.Readability.ModuleNames
defmodule FPE.ExceptionsTest do
  use ExUnit.Case, async: true

  alias FPE.FFX.Codec.NoSymbols

  @key :crypto.strong_rand_bytes(32)

  defmodule Unstarted do
    @moduledoc false
    use FPE

    @impl true
    def child_spec, do: child_spec(:crypto.strong_rand_bytes(32), :ff3_1, 10)
  end

  # Every test below triggers a *real* error through the public API and asserts
  # on the humanized message of the raised exception. Together they exercise
  # every clause of `FPE.Error.humanize/1` end-to-end.

  describe "new! raises FPE.ArgumentError" do
    test "key is not a binary" do
      assert_raise FPE.ArgumentError, ~r/key must be a binary/, fn -> FPE.new!(:nope, 10) end
    end

    test "key has an invalid size" do
      err = assert_raise FPE.ArgumentError, ~r/must be 16, 24, or 32 bytes/, fn -> FPE.new!(<<0>>, 10) end
      assert err.reason == {:key_has_invalid_size, 1}
    end

    test "mode is unknown" do
      assert_raise FPE.ArgumentError, ~r/unknown mode :nope/, fn -> FPE.new!(@key, :nope, 10) end
    end

    test "radix needs an alphabet or codec" do
      assert_raise FPE.ArgumentError, ~r/needs an alphabet or a codec/, fn -> FPE.new!(@key, 100) end
    end

    test "radix is below the minimum (one-symbol alphabet)" do
      assert_raise FPE.ArgumentError, ~r/below the minimum/, fn -> FPE.new!(@key, "0") end
    end

    test "radix is above the maximum (NoSymbols codec)" do
      codec = NoSymbols.new!(0x10001)
      assert_raise FPE.ArgumentError, ~r/above the maximum/, fn -> FPE.new!(@key, :ff1, codec) end
    end

    test "alphabet is not valid UTF-8" do
      assert_raise FPE.ArgumentError, ~r/invalid alphabet — not valid UTF-8/, fn -> FPE.new!(@key, <<0xFF, 0xFE>>) end
    end

    test "alphabet has repeated symbols" do
      assert_raise FPE.ArgumentError, ~r/invalid alphabet — repeated symbols/, fn -> FPE.new!(@key, "αβγδεζηθια") end
    end

    test "alphabet has a combining character (invalid codepoints)" do
      assert_raise FPE.ArgumentError, ~r/invalid symbols.+combining character/, fn -> FPE.new!(@key, <<0x0301::utf8>>) end
    end

    test "alphabet has a control character (category :other)" do
      assert_raise FPE.ArgumentError, ~r/unassigned, control, format/, fn -> FPE.new!(@key, <<0x0007::utf8>>) end
    end

    test "alphabet has a separator character" do
      assert_raise FPE.ArgumentError, ~r/whitespace or separator/, fn -> FPE.new!(@key, " ") end
    end

    test "alphabet has conjoining Hangul jamo" do
      assert_raise FPE.ArgumentError, ~r/conjoining Hangul jamo/, fn -> FPE.new!(@key, <<0x1100::utf8>>) end
    end

    test "alphabet has a symbol that merges with its neighbour" do
      assert_raise FPE.ArgumentError, ~r/merges with an adjacent symbol/, fn -> FPE.new!(@key, <<0x1F3FB::utf8>>) end
    end
  end

  describe "NoSymbols.new! raises FPE.ArgumentError" do
    test "radix is not a valid radix" do
      assert_raise FPE.ArgumentError, ~r/must be an integer >= 2/, fn -> NoSymbols.new!(1) end
    end
  end

  describe "encrypt!/decrypt! raise FPE.InputError" do
    test "input length is out of bounds" do
      ctx = FPE.new!(@key, 10)
      err = assert_raise FPE.InputError, ~r/must be between 6 and/, fn -> FPE.encrypt!(ctx, "", "12345") end
      assert {:invalid_input, {:length_out_of_bounds, 5, {6, _}}} = err.reason
    end

    test "decrypt! also raises on an out-of-bounds length" do
      ctx = FPE.new!(@key, 10)
      assert_raise FPE.InputError, ~r/must be between 6 and/, fn -> FPE.decrypt!(ctx, "", "12345") end
    end

    test "FF3-1 tweak has the wrong bit size" do
      ctx = FPE.new!(@key, :ff3_1, 10)
      assert_raise FPE.InputError, ~r/tweak must be 56 bits/, fn -> FPE.encrypt!(ctx, <<0>>, "34436524") end
    end

    test "FF3-1 tweak is not a bitstring" do
      ctx = FPE.new!(@key, :ff3_1, 10)
      assert_raise FPE.InputError, ~r/tweak must be a bitstring/, fn -> FPE.encrypt!(ctx, :nope, "34436524") end
    end

    test "FF1 tweak is not a binary" do
      ctx = FPE.new!(@key, 10)
      assert_raise FPE.InputError, ~r/tweak must be a binary/, fn -> FPE.encrypt!(ctx, :nope, "123456") end
    end

    test "input has an out-of-alphabet symbol (built-in codec)" do
      ctx = FPE.new!(@key, 10)
      assert_raise FPE.InputError, ~r/not a numerical string/, fn -> FPE.encrypt!(ctx, "", "1234z6") end
    end

    test "input is an unknown symbol (custom codec)" do
      ctx = FPE.new!(@key, "abcdefghij")
      assert_raise FPE.InputError, ~r/unknown symbol for this alphabet/, fn -> FPE.encrypt!(ctx, "", "abcdez") end
    end

    test "input is not valid UTF-8 (custom codec)" do
      ctx = FPE.new!(@key, "abcdefghij")

      assert_raise FPE.InputError, ~r/not valid UTF-8/, fn ->
        FPE.encrypt!(ctx, "", <<0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA>>)
      end
    end

    test "NoSymbols value is negative" do
      ctx = FPE.new!(@key, :ff1, NoSymbols.new!(10))
      input = %NoSymbols.NumString{value: -1, length: 10}
      assert_raise FPE.InputError, ~r/value must be non-negative/, fn -> FPE.encrypt!(ctx, "", input) end
    end

    test "NoSymbols value does not fit its declared length" do
      ctx = FPE.new!(@key, :ff1, NoSymbols.new!(10))
      input = %NoSymbols.NumString{value: 9_999_999, length: 6}
      assert_raise FPE.InputError, ~r/does not fit in its declared length/, fn -> FPE.encrypt!(ctx, "", input) end
    end
  end

  describe "a use FPE module raises FPE.NotStartedError" do
    test "when its context is not under a supervision tree" do
      assert_raise FPE.NotStartedError, ~r/was not found/, fn -> Unstarted.encrypt!(<<0::56>>, "34436524") end
    end
  end

  # The two reasons below have no practical end-to-end trigger, so they are the
  # sole cases checked against `FPE.Error.humanize/1` directly:
  #
  #   * `:too_large` would need a tweak larger than FF1's maximum of 2^32-1 bytes;
  #   * the fallback clause only fires for a reason no lib function emits.
  describe "FPE.Error.humanize/1 (reasons with no end-to-end path)" do
    test "an oversized tweak" do
      message = FPE.Error.humanize({:invalid_tweak, {:too_large, 5_000_000_000, 4_294_967_295}})
      assert message =~ "tweak is too large"
    end

    test "falls back to inspect/1 for an unrecognized reason" do
      reason = {:some_future_reason, 42}
      assert FPE.Error.humanize(reason) == inspect(reason)
    end
  end

  describe "FPE.constraints/1 and FPE.codec/1" do
    test "expose the context's mode constraints and codec" do
      ctx = FPE.new!(@key, 10)

      assert %{min_length: 6, max_length: max} = FPE.constraints(ctx)
      assert is_integer(max)
      assert %FPE.FFX.Codec.Builtin{radix: 10} = FPE.codec(ctx)
    end
  end
end
