# FF3_1: Format-preserving encryption for Elixir

Work in progress to provide format-preserving encryption through the FF3-1 algorithm,
[a revised version of FF3](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38Gr1-draft.pdf)
after security issues were uncovered.

I wrote this for the kicks - it is not a serious project.

```elixir
    key = <<
      0xAD, 0x41, 0xEC, 0x5D, 0x23, 0x56, 0xDE, 0xAE,
      0x53, 0xAE, 0x76, 0xF5, 0x0B, 0x4B, 0xA6, 0xD2
    >>
    tweak = <<0xCF, 0x29, 0xDA, 0x1E, 0x18, 0xD9, 0x70>>

    {:ok, ctx} = FF3_1.new_ctx(key, 10)
    assert "4716569208" == FF3_1.encrypt!(ctx, tweak, "6520935496")
    assert "6520935496" == FF3_1.decrypt!(ctx, tweak, "4716569208")
```

## Installation

If [available in Hex](https://hex.pm/docs/publish), the package can be installed
by adding `fpe` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:ff3_1, "~> 0.1.0"}
  ]
end
```

Documentation can be generated with [ExDoc](https://github.com/elixir-lang/ex_doc)
and published on [HexDocs](https://hexdocs.pm). Once published, the docs can
be found at <https://hexdocs.pm/fpe>.

