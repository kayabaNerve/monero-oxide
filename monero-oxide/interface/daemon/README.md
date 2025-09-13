# Monero Daemon Interface

A trait for a connection to a Monero daemon, allowing flexibility over the
choice of transport.

This library is usable under no-std, with `alloc`, when the `std` feature (on by
default) is disabled.

### Cargo Features

- `std` (on by default): Enables `std` (and with it, more efficient internal
  implementations).
