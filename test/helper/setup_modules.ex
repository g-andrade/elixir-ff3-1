# credo:disable-for-this-file Credo.Check.Readability.ModuleNames
defmodule FF3_1_Test.Helper.SetupModules do
  @moduledoc false

  defmodule BuiltinBase10 do
    @moduledoc false
    use ExFPE

    @impl true
    def child_spec, do: child_spec(:crypto.strong_rand_bytes(32), :ff3_1, 10)
  end

  defmodule BuiltinBase16 do
    @moduledoc false
    use ExFPE

    @impl true
    def child_spec, do: child_spec(:crypto.strong_rand_bytes(32), :ff3_1, 16)
  end

  defmodule CustomBase10 do
    @moduledoc false
    use ExFPE

    @impl true
    def child_spec, do: child_spec(:crypto.strong_rand_bytes(32), :ff3_1, "abcDefghij")
  end

  defmodule WrongKeySize do
    @moduledoc false
    use ExFPE

    @impl true
    def child_spec, do: child_spec(:crypto.strong_rand_bytes(31), :ff3_1, 10)
  end

  defmodule InvalidRadix do
    @moduledoc false
    use ExFPE

    @impl true
    def child_spec, do: child_spec(:crypto.strong_rand_bytes(32), :ff3_1, 1)
  end

  defmodule InvalidAlphabet do
    @moduledoc false
    use ExFPE

    @impl true
    def child_spec, do: child_spec(:crypto.strong_rand_bytes(32), :ff3_1, "0")
  end
end
