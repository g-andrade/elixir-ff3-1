# credo:disable-for-this-file Credo.Check.Readability.ModuleNames
defmodule ExFPE_Test do
  use ExUnit.Case, async: true

  doctest ExFPE
end

# The usage guide (with its runnable examples) lives in the README; doctest it
# from there. `doctest_file/1` was added in Elixir 1.15.
if Version.match?(System.version(), "~> 1.15") do
  defmodule ExFPE_ReadmeTest do
    use ExUnit.Case, async: true

    doctest_file("README.md")
  end
end
