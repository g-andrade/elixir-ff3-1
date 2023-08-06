#!/usr/bin/env elixir

# credo:disable-for-this-file Credo.Check.Refactor.Nesting
# credo:disable-for-this-file Credo.Check.Refactor.CyclomaticComplexity
defmodule AlphabetGenerator do
  @moduledoc false
  def generate(length) do
    generate_recur(
      _n = length,
      _current = "0",
      _codepoint = ?0,
      _acc = [],
      _acc_n = 0
    )
  end

  defp generate_recur(n, current, codepoint, acc, acc_n) do
    codepoint_after = calc_codepoint_after(codepoint)
    current = :unicode.characters_to_nfc_binary([current, codepoint_after])

    case String.graphemes(current) do
      [current] ->
        generate_recur(n, current, codepoint_after, acc, acc_n)

      [cluster, current] ->
        is_printable = String.printable?(cluster)

        case acc_n + String.length(cluster) do
          less when less < n and is_printable ->
            acc = [cluster, acc]
            acc_n = less
            generate_recur(n, current, codepoint_after, acc, acc_n)

          equal when equal === n and is_printable ->
            what_we_have =
              [cluster, acc]
              |> :unicode.characters_to_nfc_binary()
              |> String.graphemes()
              |> :lists.usort()
              |> :unicode.characters_to_nfc_binary()

            case String.length(what_we_have) do
              still_not_enough when still_not_enough < n ->
                # Some clusters got merged?
                generate_recur(n, current, codepoint_after, what_we_have, still_not_enough)

              _plenty ->
                String.slice(what_we_have, 0, n)
            end

          other when other > n or not is_printable ->
            generate_recur(n, current, codepoint_after, acc, acc_n)
        end
    end
  end

  defp calc_codepoint_after(codepoint) do
    if codepoint in (0xD800 - 1)..0xDFFF do
      # UTF-16 surrogate range
      0xDFFF + 1
    else
      codepoint + 1
    end
  end
end

System.argv()
|> hd()
|> String.to_integer()
|> AlphabetGenerator.generate()
|> IO.puts()
