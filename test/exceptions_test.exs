# credo:disable-for-this-file Credo.Check.Readability.ModuleNames
defmodule FPE.ExceptionsTest do
  use ExUnit.Case, async: true

  @key :crypto.strong_rand_bytes(32)

  defmodule Unstarted do
    @moduledoc false
    use FPE

    @impl true
    def child_spec, do: child_spec(:crypto.strong_rand_bytes(32), :ff3_1, 10)
  end

  describe "FPE.ArgumentError (from new!)" do
    test "raises on an invalid key, humanized, keeping the structured reason" do
      err =
        assert_raise FPE.ArgumentError, ~r/key must be 16, 24, or 32 bytes/, fn ->
          FPE.new!(<<0>>, 10)
        end

      assert err.reason == {:key_has_invalid_size, 1}
    end

    test "raises on an unknown mode" do
      assert_raise FPE.ArgumentError, ~r/unknown mode :nope/, fn ->
        FPE.new!(@key, :nope, 10)
      end
    end
  end

  describe "FPE.InputError (from encrypt!/decrypt!)" do
    test "raises when the input length is out of bounds" do
      {:ok, ctx} = FPE.new(@key, 10)

      err =
        assert_raise FPE.InputError, ~r/must be between 6 and/, fn ->
          FPE.encrypt!(ctx, "", "12345")
        end

      assert {:invalid_input, {:length_out_of_bounds, 5, {6, _}}} = err.reason
    end

    test "raises on a wrong-size FF3-1 tweak" do
      {:ok, ctx} = FPE.new(@key, :ff3_1, 10)

      assert_raise FPE.InputError, ~r/tweak must be 56 bits/, fn ->
        FPE.encrypt!(ctx, <<0>>, "34436524")
      end
    end
  end

  describe "FPE.NotStartedError (from a use FPE module)" do
    test "raises when the context is not under a supervision tree" do
      assert_raise FPE.NotStartedError, ~r/was not found/, fn ->
        Unstarted.encrypt!(<<0::56>>, "34436524")
      end
    end
  end

  describe "FPE.constraints/1 and FPE.codec/1" do
    test "expose the context's mode constraints and codec" do
      {:ok, ctx} = FPE.new(@key, 10)

      assert %{min_length: 6, max_length: max} = FPE.constraints(ctx)
      assert is_integer(max)
      assert %FPE.FFX.Codec.Builtin{radix: 10} = FPE.codec(ctx)
    end
  end
end
