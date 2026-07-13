#!/usr/bin/env elixir
# Regenerate a fixture alphabet of N valid symbols:
#
#     mix run test/data/generate_alphabet.exs <count> <output_path>
#
# Each symbol is a single Unicode codepoint that the Custom codec accepts on its
# own. We gate candidates through `Custom.new/1` itself so the fixtures can never
# drift from the codec's actual acceptance rules. Separators are additionally
# skipped so the file has no whitespace that `String.trim/1` could eat at a
# boundary.

alias ExFPE.FFX.Codec.Custom

require Logger

defmodule AlphabetGenerator do
  @moduledoc false

  @max_codepoint 0x10FFFF
  @surrogates 0xD800..0xDFFF

  def generate(count) do
    ?0
    |> Stream.iterate(&(&1 + 1))
    |> Stream.take_while(&(&1 <= @max_codepoint))
    |> Stream.filter(&acceptable?/1)
    |> Enum.take(count)
    |> List.to_string()
  end

  defp acceptable?(codepoint) do
    codepoint not in @surrogates and
      not separator?(codepoint) and
      match?({:ok, _}, Custom.new(<<codepoint::utf8>>))
  end

  defp separator?(codepoint) do
    {principal_category, _} = :unicode_util.lookup(codepoint).category
    principal_category === :separator
  end
end

Logger.info("Generating alphabet")
[amount_str, output_filepath] = System.argv()

amount_str
|> String.to_integer()
|> AlphabetGenerator.generate()
|> then(fn alphabet -> File.write!(output_filepath, alphabet) end)
