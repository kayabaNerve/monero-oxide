# Monero EPEE

`epee` is a bespoke serialization format seen within the Monero project without
any official documentation. The best specification is available [here](
  https://github.com/jeffro256/serde_epee/tree/cbebe75475fb2c6073f7b2e058c88ceb2531de17PORTABLE_STORAGE.md
).

This library implements the `epee` 'portable storage' encoding, with the
following exceptions:
- We don't support the `Array` type (type 13) as it's unused and lacking
  documentation
- We may accept a _wider_ class of inputs than the `epee` library itself due to
  slight differences in depth limits on nested objects

We do not support:
- Encoding objects
- Decoding objects into typed data structures

Instead, we support iterating through `epee`-encoded values and finding all
instances of a field. This lets the caller jump to the binary blob representing
an encoded value, and decode it themselves, without us actually deserializing
the entire object. If we were to do that, we'd presumably require something
akin to `serde_json::Value` or a proc macro. This is sufficient for basic
needs, much simpler, and should be trivial to verify it won't panic/face
various exhaustion attacks. This library is implemented without recursion.

Because of this, we are also able to support no-`std` and no-`alloc`, without
any dependencies other than `core`, while only consuming approximately a
kibibyte of memory on the stack.

For a more functional library, please check out
[`cuprate-epee-encoding`](
  https://github.com/cuprate/cuprate/tree/9c2c942d2fcf26ed8916dc3f9be6db43d8d2ae78/net/epee-encoding
).
