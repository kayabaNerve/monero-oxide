#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]

use core::fmt::Debug;
#[allow(unused_imports)]
use std_shims::prelude::*;
use std_shims::io::{self, Read, Write};

use curve25519_dalek::{scalar::Scalar, edwards::EdwardsPoint};

mod varint;
pub use varint::*;

mod compressed_point;
pub use compressed_point::CompressedPoint;

/// Write a byte.
///
/// This is used as a building block within generic functions.
pub fn write_byte<W: Write>(byte: &u8, w: &mut W) -> io::Result<()> {
  w.write_all(&[*byte])
}

/// Write a scalar.
pub fn write_scalar<W: Write>(scalar: &Scalar, w: &mut W) -> io::Result<()> {
  w.write_all(&scalar.to_bytes())
}

/// Write a point.
pub fn write_point<W: Write>(point: &EdwardsPoint, w: &mut W) -> io::Result<()> {
  CompressedPoint(point.compress().to_bytes()).write(w)
}

/// Write a list of elements, without length-prefixing.
pub fn write_raw_vec<T, W: Write, F: FnMut(&T, &mut W) -> io::Result<()>>(
  mut f: F,
  values: &[T],
  w: &mut W,
) -> io::Result<()> {
  for value in values {
    f(value, w)?;
  }
  Ok(())
}

/// Write a list of elements, with length-prefixing.
pub fn write_vec<T, W: Write, F: FnMut(&T, &mut W) -> io::Result<()>>(
  f: F,
  values: &[T],
  w: &mut W,
) -> io::Result<()> {
  VarInt::write(&values.len(), w)?;
  write_raw_vec(f, values, w)
}

/// Read a constant amount of bytes.
pub fn read_bytes<R: Read, const N: usize>(r: &mut R) -> io::Result<[u8; N]> {
  let mut res = [0; N];
  r.read_exact(&mut res)?;
  Ok(res)
}

/// Read a single byte.
pub fn read_byte<R: Read>(r: &mut R) -> io::Result<u8> {
  Ok(read_bytes::<_, 1>(r)?[0])
}

/// Read a u16, little-endian encoded.
pub fn read_u16<R: Read>(r: &mut R) -> io::Result<u16> {
  read_bytes(r).map(u16::from_le_bytes)
}

/// Read a u32, little-endian encoded.
pub fn read_u32<R: Read>(r: &mut R) -> io::Result<u32> {
  read_bytes(r).map(u32::from_le_bytes)
}

/// Read a u64, little-endian encoded.
pub fn read_u64<R: Read>(r: &mut R) -> io::Result<u64> {
  read_bytes(r).map(u64::from_le_bytes)
}

/// Read a canonically-encoded scalar.
///
/// Some scalars within the Monero protocol are not enforced to be canonically encoded. For such
/// scalars, they should be represented as `[u8; 32]` and later converted to scalars as relevant.
pub fn read_scalar<R: Read>(r: &mut R) -> io::Result<Scalar> {
  Option::from(Scalar::from_canonical_bytes(read_bytes(r)?))
    .ok_or_else(|| io::Error::other("unreduced scalar"))
}

/// Read a canonically-encoded Ed25519 point.
///
/// This internally calls [`CompressedPoint::decompress`] and has the same definition of canonicity.
/// This function does not check the resulting point is within the prime-order subgroup.
pub fn read_point<R: Read>(r: &mut R) -> io::Result<EdwardsPoint> {
  CompressedPoint::read(r)?.decompress().ok_or_else(|| io::Error::other("invalid point"))
}

/// Read a variable-length list of elements, without length-prefixing.
pub fn read_raw_vec<R: Read, T, F: FnMut(&mut R) -> io::Result<T>>(
  mut f: F,
  len: usize,
  r: &mut R,
) -> io::Result<Vec<T>> {
  let mut res = vec![];
  for _ in 0 .. len {
    res.push(f(r)?);
  }
  Ok(res)
}

/// Read a constant-length list of elements.
pub fn read_array<R: Read, T: Debug, F: FnMut(&mut R) -> io::Result<T>, const N: usize>(
  f: F,
  r: &mut R,
) -> io::Result<[T; N]> {
  read_raw_vec(f, N, r).map(|vec| {
    vec.try_into().expect(
      "read vector of specific length yet couldn't transform to an array of the same length",
    )
  })
}

/// Read a length-prefixed variable-length list of elements.
///
/// An optional bound on the length of the result may be provided. If `None`, the returned `Vec`
/// will be of the length read off the reader, if successfully read. If `Some(_)`, an error will be
/// raised if the length read off the read is greater than the bound.
pub fn read_vec<R: Read, T, F: FnMut(&mut R) -> io::Result<T>>(
  f: F,
  length_bound: Option<usize>,
  r: &mut R,
) -> io::Result<Vec<T>> {
  let declared_length: usize = VarInt::read(r)?;
  if let Some(length_bound) = length_bound {
    if declared_length > length_bound {
      Err(io::Error::other("vector exceeds bound on length"))?;
    }
  }
  read_raw_vec(f, declared_length, r)
}
