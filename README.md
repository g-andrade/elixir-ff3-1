# ExFPE: Format-preserving encryption for Elixir

ExFPE encrypts a numerical string into another of the **same length over the
same alphabet**. This is useful to e.g. store an encrypted credit card number
in a field that only accepts credit-card-shaped values, and other suchlike
applications.

`ExFPE` is the entry point. It wraps a concrete FPE mode behind a single API —
`new!/2`, `encrypt!/3`, `decrypt!/3`, and error-returning variants.

By default it uses **FF1** (`ExFPE.FF1`), the only mode approved by NIST in
[SP 800-38Gr1 2pd](https://csrc.nist.gov/pubs/sp/800/38/g/r1/2pd).
The examples below all use the default. The other mode is FF3-1
(`ExFPE.FF3_1`), which NIST removed — reach for it only to interoperate with
data that was already encrypted with FF3-1.

> **Mode-specific rules**
>
> The **tweak size** and the **length constraints** on inputs depend on the
> mode. FF1 (the default) accepts a variable-length tweak (it may even be
> empty); FF3-1 uses a fixed 7-byte (56-bit) tweak. See `ExFPE.FF1` and
> `ExFPE.FF3_1`.

## Installation

Add `ex_fpe` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:ex_fpe, "~> 0.1.0"}
  ]
end
```

The docs are published on [HexDocs](https://hexdocs.pm/ex_fpe).

## Usage

### Context

We start by creating a context with `new!/2`, passing it a cryptographic key
and a radix. With no mode given, the default (FF1) is used.

```elixir
iex> key = :crypto.strong_rand_bytes(32)
iex> _ctx = ExFPE.new!(key, _radix = 10)
```

Keys can be:
* 32 bytes long for AES-256
* 24 bytes long for AES-192
* 16 bytes long for AES-128

Radix is an integer between 2 and 36. For larger radixes up to 65535, a
custom alphabet is needed - more on that later.

### Encryption and decryption

We're going to `encrypt!/3` our `plaintext` numerical string, in base 10,
and get another of equal length, `ciphertext`, which we can `decrypt!/3`
to get the `plaintext` back.

A `tweak` is required, which we'll handwave for now. Its size depends on the
mode: FF1 (the default) accepts a variable-length byte string, so the 7-byte
tweak below is just one valid choice.

```elixir
iex> key = :crypto.strong_rand_bytes(32)
iex> ctx = ExFPE.new!(key, _radix = 10)
iex> tweak = "dev.env"
iex> plaintext = "34436524"
iex> ciphertext = ExFPE.encrypt!(ctx, tweak, plaintext)
iex> ^plaintext = ExFPE.decrypt!(ctx, tweak, ciphertext)
```

### Leading zeroes matter

⚠️ Keep in mind that **leading zeroes are significant**. Ciphertexts are always
of equal length to their respective plaintexts, and vice-versa.

```elixir
iex> key = :crypto.strong_rand_bytes(32)
iex> ctx = ExFPE.new!(key, _radix = 10)
iex> tweak = <<0::56>>
iex> plaintext1 =   "34436524"
iex> plaintext2 = "0034436524"
iex> ciphertext1 = ExFPE.encrypt!(ctx, tweak, plaintext1)
iex> ciphertext2 = ExFPE.encrypt!(ctx, tweak, plaintext2)
iex> false = (ciphertext2 == ciphertext1)
iex> true = (String.length(ciphertext1) == String.length(plaintext1))
iex> true = (String.length(ciphertext2) == String.length(plaintext2))
```

### Tweaks

Tweaks may be public information used to produce different ciphertexts for
the same plaintext.

**They are important in FPE modes**, since the number of possible strings may
be somewhat small. In such a scenario, the tweak should vary with each instance
of the encryption whenever possible.

```elixir
iex> key = :crypto.strong_rand_bytes(32)
iex> ctx = ExFPE.new!(key, _radix = 10)
iex> plaintext= "135522432"
iex> tweak1 = "dev.env"
iex> tweak2 = "prod.env"
iex> ciphertext1 = ExFPE.encrypt!(ctx, tweak1, plaintext)
iex> ciphertext2 = ExFPE.encrypt!(ctx, tweak2, plaintext)
iex> ciphertext2 != ciphertext1
```

### Built-in alphabet

For radix values between 2 and 36, if what `Integer.to_string/2` produces is
good enough, you only need to specify the `radix` when building your `ctx`.

Both `plaintext` and `ciphertext` will be encoded in the chosen base.

#### Base 8

```elixir
iex> key = :crypto.strong_rand_bytes(32)
iex> ctx = ExFPE.new!(key, _radix = 8)
iex> tweak = <<0::56>>
iex> plaintext = "34436524"
iex> ciphertext = ExFPE.encrypt!(ctx, tweak, plaintext)
iex> ^plaintext = ExFPE.decrypt!(ctx, tweak, ciphertext)
```

#### Base 16

```elixir
iex> key = :crypto.strong_rand_bytes(32)
iex> ctx = ExFPE.new!(key, _radix = 16)
iex> tweak = <<0::56>>
iex> plaintext = "AFD093902C"
iex> ciphertext = ExFPE.encrypt!(ctx, tweak, plaintext)
iex> ^plaintext = ExFPE.decrypt!(ctx, tweak, ciphertext)
```

#### Base 36

```elixir
iex> key = :crypto.strong_rand_bytes(32)
iex> ctx = ExFPE.new!(key, _radix = 36)
iex> tweak = <<0::56>>
iex> plaintext = "ZZZAFD093902CBZDE"
iex> ciphertext = ExFPE.encrypt!(ctx, tweak, plaintext)
iex> ^plaintext = ExFPE.decrypt!(ctx, tweak, ciphertext)
```

#### Case insensitivity to input

Even though the output of either `encrypt!/3` or `decrypt!/3` is
upper case, any case is accepted as input.

```elixir
iex> key = :crypto.strong_rand_bytes(32)
iex> radix = 16
iex> ctx = ExFPE.new!(key, radix)
iex> tweak = <<0::56>>
iex> input = "aBcDDFF01234eeEee"
iex> _ciphertext = ExFPE.encrypt!(ctx, tweak, input)
iex> _plaintext = ExFPE.decrypt!(ctx, tweak, input)
```

#### Lower case output

If you want to use the built-in alphabet but desire lower case outputs, you
can do it by declaring the alphabet when creating `ctx`.

```elixir
iex> key = :crypto.strong_rand_bytes(32)
iex> alphabet = "0123456789abcdef" # radix 16
iex> ctx = ExFPE.new!(key, alphabet)
iex> tweak = <<0::56>>
iex> input = "aBcDDFF01234eeEee"
iex> ciphertext = ExFPE.encrypt!(ctx, tweak, input)
iex> plaintext = ExFPE.decrypt!(ctx, tweak, input)
iex> ^ciphertext = String.downcase(ciphertext)
iex> ^plaintext = String.downcase(plaintext)
```

### Custom alphabets

Whether you need a radix larger than 36, or use symbols other than 0-9, A-Z
in your numerical strings (or use such symbols in a different order), custom
alphabets are supported.

Note that custom alphabets are norm insensitive but **case sensitive**.
The reasoning behind this can be found under `ExFPE.Codec.Custom`.

Each symbol must be a single Unicode codepoint that stands on its own as one
visual unit; alphabets are validated at construction. See
`ExFPE.Codec.Custom` for the exact rules and the guarantees they buy.

#### Base 20 with custom alphabet

```elixir
iex> key = :crypto.strong_rand_bytes(32)
iex> alphabet = "abcdefghij0123456789"
iex> ctx = ExFPE.new!(key, alphabet)
iex> tweak = <<0::56>>
iex> plaintext = "34534abcd32235"
iex> ciphertext = ExFPE.encrypt!(ctx, tweak, plaintext)
iex> ^plaintext = ExFPE.decrypt!(ctx, tweak, ciphertext)
```

#### Base 40 with custom alphabet

```elixir
iex> key = :crypto.strong_rand_bytes(32)
iex> alphabet = "0123456789abcdefghijklmnopqrstuvwxyz@#/*"
iex> ctx = ExFPE.new!(key, alphabet)
iex> tweak = <<0::56>>
iex> plaintext = "34534ab@@@@@/cd32235"
iex> ciphertext = ExFPE.encrypt!(ctx, tweak, plaintext)
iex> ^plaintext = ExFPE.decrypt!(ctx, tweak, ciphertext)
```

#### Unicode support

```elixir
iex> key = :crypto.strong_rand_bytes(32)
iex> alphabet = "🌕🌖🌗🌘🌑🌒🌓🌔"
iex> ctx = ExFPE.new!(key, alphabet)
iex> tweak = <<0::56>>
iex> plaintext = "🌖🌕🌘🌑🌓🌗🌔🌒🌒🌒🌒"
iex> ciphertext = ExFPE.encrypt!(ctx, tweak, plaintext)
iex> ^plaintext = ExFPE.decrypt!(ctx, tweak, ciphertext)
```

### No alphabet

If you wish to handle translation of integers into and from symbols yourself,
you can use `ExFPE.Codec.NoSymbols`. Encryption and decryption functions
will receive, and return, integer values with a length tag.

Encryption and decryption will act on inputs as if the integer value was
encoded in that radix.

#### Radix 10

```elixir
iex> alias ExFPE.Codec.NoSymbols
iex> key = :crypto.strong_rand_bytes(32)
iex> radix = 10
iex> codec = NoSymbols.new!(radix)
iex> ctx = ExFPE.new!(key, codec)
iex> tweak = <<0::56>>
iex> input = 1234567
iex> input_length = 10
iex>
iex> plaintext = %NoSymbols.NumString{value: input, length: input_length}
iex> ciphertext = ExFPE.encrypt!(ctx, tweak, plaintext)
iex> %NoSymbols.NumString{length: ^input_length} = ciphertext
iex> ^plaintext = ExFPE.decrypt!(ctx, tweak, ciphertext)
```

#### Radix 500

```elixir
iex> alias ExFPE.Codec.NoSymbols
iex> key = :crypto.strong_rand_bytes(32)
iex> radix = 500
iex> codec = NoSymbols.new!(radix)
iex> ctx = ExFPE.new!(key, codec)
iex> tweak = <<0::56>>
iex> input = 1234567
iex> input_length = 10
iex>
iex> plaintext = %NoSymbols.NumString{value: input, length: input_length}
iex> ciphertext = ExFPE.encrypt!(ctx, tweak, plaintext)
iex> %NoSymbols.NumString{length: ^input_length} = ciphertext
iex> ^plaintext = ExFPE.decrypt!(ctx, tweak, ciphertext)
```

#### Radix 65535

```elixir
iex> alias ExFPE.Codec.NoSymbols
iex> key = :crypto.strong_rand_bytes(32)
iex> radix = 65535
iex> codec = NoSymbols.new!(radix)
iex> ctx = ExFPE.new!(key, codec)
iex> tweak = <<0::56>>
iex> input = 1234567
iex> input_length = 10
iex>
iex> plaintext = %NoSymbols.NumString{value: input, length: input_length}
iex> ciphertext = ExFPE.encrypt!(ctx, tweak, plaintext)
iex> %NoSymbols.NumString{length: ^input_length} = ciphertext
iex> ^plaintext = ExFPE.decrypt!(ctx, tweak, ciphertext)
```

### Choosing a mode

Everything above uses the default mode, FF1. To select a mode explicitly,
pass it as the second argument to `new!/3`. The only other mode is FF3-1,
which is **no longer NIST-approved** (see `ExFPE.FF3_1`) — reach for it only to
interoperate with data that was already encrypted with FF3-1. It takes a
fixed 7-byte tweak.

```elixir
iex> key = :crypto.strong_rand_bytes(32)
iex> ctx = ExFPE.new!(key, :ff3_1, _radix = 10)
iex> tweak = <<0::56>>
iex> plaintext = "34436524"
iex> ciphertext = ExFPE.encrypt!(ctx, tweak, plaintext)
iex> ^plaintext = ExFPE.decrypt!(ctx, tweak, ciphertext)
```

## Convenience: `use ExFPE`

Having to thread a `ctx` through every `encrypt!/3` and `decrypt!/3` call can be
cumbersome. If you'd rather not, `use ExFPE` generates functions that retrieve
the context transparently, storing it in a uniquely named
[`persistent_term`](https://www.erlang.org/doc/man/persistent_term) managed by a
process placed under your supervision tree. See `ExFPE` for details.

```elixir
defmodule MyApp.CardCipher do
  use ExFPE

  @impl true
  def child_spec do
    child_spec(fetch_key(), _radix = 10)
  end

  defp fetch_key, do: Application.fetch_env!(:my_app, :fpe_key)
end

# in your application's supervision tree:
children = [
  MyApp.CardCipher.child_spec(),
  # ...
]

# then, anywhere:
plaintext = "34436524"
ciphertext = MyApp.CardCipher.encrypt!(tweak, plaintext)
^plaintext = MyApp.CardCipher.decrypt!(tweak, ciphertext)
```

## License

[MIT](LICENSE)
