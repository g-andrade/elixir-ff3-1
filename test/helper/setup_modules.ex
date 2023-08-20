# credo:disable-for-this-file Credo.Check.Readability.ModuleNames
defmodule FF3_1_Test.Helper.SetupModules do
  @moduledoc false
  defmodule BuiltinBase10 do
    @moduledoc false
    use FF3_1.Setup,
      key: :crypto.strong_rand_bytes(32),
      radix: 10
  end

  defmodule BuiltinBase16 do
    @moduledoc false
    use FF3_1.Setup,
      key: :crypto.strong_rand_bytes(32),
      radix: 16
  end

  defmodule CustomBase10 do
    @moduledoc false
    use FF3_1.Setup,
      key: :crypto.strong_rand_bytes(32),
      alphabet: "abcDefghij"
  end

  defmodule WrongKeySize do
    @moduledoc false
    use FF3_1.Setup,
      key: :crypto.strong_rand_bytes(31),
      radix: 10
  end

  defmodule InvalidRadix do
    @moduledoc false
    use FF3_1.Setup,
      key: :crypto.strong_rand_bytes(32),
      radix: 1
  end

  defmodule InvalidAlphabet do
    @moduledoc false
    use FF3_1.Setup,
      key: :crypto.strong_rand_bytes(32),
      alphabet: "0"
  end
end
