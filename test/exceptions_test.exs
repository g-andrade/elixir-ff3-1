# credo:disable-for-this-file Credo.Check.Readability.ModuleNames
defmodule ExFPE.ExceptionsTest do
  use ExUnit.Case, async: true

  @key :crypto.strong_rand_bytes(32)

  defmodule Unstarted do
    @moduledoc false
    use ExFPE

    @impl true
    def child_spec, do: child_spec(:crypto.strong_rand_bytes(32), :ff3_1, 10)
  end

  # Every test below triggers a *real* error through the public API and asserts
  # on the humanized message of the raised exception. Together they exercise
  # every clause of `ExFPE.Error.humanize/1` end-to-end.

  describe "new! raises ExFPE.ArgumentError" do
    test "key is not a binary" do
      assert_raise ExFPE.ArgumentError, ~r/key must be a binary/, fn -> ExFPE.new!(:nope, 10) end
    end

    test "key has an invalid size" do
      err = assert_raise ExFPE.ArgumentError, ~r/must be 16, 24, or 32 bytes/, fn -> ExFPE.new!(<<0>>, 10) end
      assert err.reason == {:key_has_invalid_size, 1}
    end

    test "mode is unknown" do
      assert_raise ExFPE.ArgumentError, ~r/unknown mode :nope/, fn -> ExFPE.new!(@key, :nope, 10) end
    end

    test "radix needs an alphabet or a raw-only context" do
      assert_raise ExFPE.ArgumentError, ~r/needs an alphabet.+or pass \{:raw_only/, fn -> ExFPE.new!(@key, 100) end
    end

    test "radix is below the minimum (one-symbol alphabet)" do
      assert_raise ExFPE.ArgumentError, ~r/below the minimum/, fn -> ExFPE.new!(@key, "0") end
    end

    test "radix is above the maximum (raw-only context)" do
      assert_raise ExFPE.ArgumentError, ~r/above the maximum/, fn -> ExFPE.new!(@key, :ff1, {:raw_only, 0x10001}) end
    end

    test "alphabet is not valid UTF-8" do
      assert_raise ExFPE.ArgumentError, ~r/invalid alphabet — not valid UTF-8/, fn -> ExFPE.new!(@key, <<0xFF, 0xFE>>) end
    end

    test "alphabet has repeated symbols" do
      assert_raise ExFPE.ArgumentError, ~r/invalid alphabet — repeated symbols/, fn -> ExFPE.new!(@key, "αβγδεζηθια") end
    end

    test "alphabet has a combining character (invalid codepoints)" do
      assert_raise ExFPE.ArgumentError, ~r/invalid symbols.+combining character/, fn ->
        ExFPE.new!(@key, <<0x0301::utf8>>)
      end
    end

    test "alphabet has a control character (category :other)" do
      assert_raise ExFPE.ArgumentError, ~r/unassigned, control, format/, fn -> ExFPE.new!(@key, <<0x0007::utf8>>) end
    end

    test "alphabet has a separator character" do
      assert_raise ExFPE.ArgumentError, ~r/whitespace or separator/, fn -> ExFPE.new!(@key, " ") end
    end

    test "alphabet has conjoining Hangul jamo" do
      assert_raise ExFPE.ArgumentError, ~r/conjoining Hangul jamo/, fn -> ExFPE.new!(@key, <<0x1100::utf8>>) end
    end

    test "alphabet has a symbol that merges with its neighbour" do
      assert_raise ExFPE.ArgumentError, ~r/merges with an adjacent symbol/, fn -> ExFPE.new!(@key, <<0x1F3FB::utf8>>) end
    end
  end

  describe "encrypt!/decrypt! raise ExFPE.InputError" do
    test "input length is out of bounds" do
      ctx = ExFPE.new!(@key, 10)
      err = assert_raise ExFPE.InputError, ~r/must be between 6 and/, fn -> ExFPE.encrypt!(ctx, "", "12345") end
      assert {:invalid_input, {:length_out_of_bounds, 5, {6, _}}} = err.reason
    end

    test "decrypt! also raises on an out-of-bounds length" do
      ctx = ExFPE.new!(@key, 10)
      assert_raise ExFPE.InputError, ~r/must be between 6 and/, fn -> ExFPE.decrypt!(ctx, "", "12345") end
    end

    test "FF3-1 tweak has the wrong bit size" do
      ctx = ExFPE.new!(@key, :ff3_1, 10)
      assert_raise ExFPE.InputError, ~r/tweak must be 56 bits/, fn -> ExFPE.encrypt!(ctx, <<0>>, "34436524") end
    end

    test "FF3-1 tweak is not a bitstring" do
      ctx = ExFPE.new!(@key, :ff3_1, 10)
      assert_raise ExFPE.InputError, ~r/tweak must be a bitstring/, fn -> ExFPE.encrypt!(ctx, :nope, "34436524") end
    end

    test "FF1 tweak is not a binary" do
      ctx = ExFPE.new!(@key, 10)
      assert_raise ExFPE.InputError, ~r/tweak must be a binary/, fn -> ExFPE.encrypt!(ctx, :nope, "123456") end
    end

    test "input has an out-of-alphabet symbol (built-in codec)" do
      ctx = ExFPE.new!(@key, 10)
      assert_raise ExFPE.InputError, ~r/not a numerical string/, fn -> ExFPE.encrypt!(ctx, "", "1234z6") end
    end

    test "input is an unknown symbol (custom codec)" do
      ctx = ExFPE.new!(@key, "abcdefghij")
      assert_raise ExFPE.InputError, ~r/unknown symbol for this alphabet/, fn -> ExFPE.encrypt!(ctx, "", "abcdez") end
    end

    test "input is not valid UTF-8 (custom codec)" do
      ctx = ExFPE.new!(@key, "abcdefghij")

      assert_raise ExFPE.InputError, ~r/not valid UTF-8/, fn ->
        ExFPE.encrypt!(ctx, "", <<0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA>>)
      end
    end

    test "raw value is negative" do
      ctx = ExFPE.new!(@key, :ff1, {:raw_only, 10})
      assert_raise ExFPE.InputError, ~r/value must be non-negative/, fn -> ExFPE.raw_encrypt!(ctx, "", -1, 10) end
    end

    test "raw value does not fit its declared length" do
      ctx = ExFPE.new!(@key, :ff1, {:raw_only, 10})

      assert_raise ExFPE.InputError, ~r/does not fit in its declared length/, fn ->
        ExFPE.raw_encrypt!(ctx, "", 9_999_999, 6)
      end
    end
  end

  describe "a use ExFPE module raises ExFPE.NotStartedError" do
    test "when its context is not under a supervision tree" do
      assert_raise ExFPE.NotStartedError, ~r/was not found/, fn -> Unstarted.encrypt!(<<0::56>>, "34436524") end
    end

    test "from a raw wrapper when its context is not under a supervision tree" do
      assert_raise ExFPE.NotStartedError, ~r/was not found/, fn -> Unstarted.raw_encrypt!(<<0::56>>, 34_436_524, 8) end
    end
  end

  # The two reasons below have no practical end-to-end trigger, so they are the
  # sole cases checked against `ExFPE.Error.humanize/1` directly:
  #
  #   * `:too_large` would need a tweak larger than FF1's maximum of 2^32-1 bytes;
  #   * the fallback clause only fires for a reason no lib function emits.
  describe "ExFPE.Error.humanize/1 (reasons with no end-to-end path)" do
    test "an oversized tweak" do
      message = ExFPE.Error.humanize({:invalid_tweak, {:too_large, 5_000_000_000, 4_294_967_295}})
      assert message =~ "tweak is too large"
    end

    test "falls back to inspect/1 for an unrecognized reason" do
      reason = {:some_future_reason, 42}
      assert ExFPE.Error.humanize(reason) == inspect(reason)
    end
  end

  describe "ExFPE.constraints/1" do
    test "exposes the context's mode constraints" do
      ctx = ExFPE.new!(@key, 10)

      assert %{min_length: 6, max_length: max} = ExFPE.constraints(ctx)
      assert is_integer(max)
    end
  end
end
