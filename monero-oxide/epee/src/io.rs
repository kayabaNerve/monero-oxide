//! IO primitives around `&[u8]`.

use crate::EpeeError;

/// Read a fixed amount of bytes from the slice.
///
/// This will return `Ok(slice)` where `slice` is the expected length or `Err(_)`.
pub(crate) fn read_bytes<'a, const N: usize>(reader: &mut &'a [u8]) -> Result<&'a [u8], EpeeError> {
  if reader.len() < N {
    Err(EpeeError::Short(N))?;
  }
  let res = &reader[.. N];
  *reader = &reader[N ..];
  Ok(res)
}

pub(crate) fn read_byte(reader: &mut &[u8]) -> Result<u8, EpeeError> {
  Ok(read_bytes::<1>(reader)?[0])
}

/// Read a VarInt per EPEE's definition.
///
/// This does not require the VarInt is canonically encoded. It _may_ be malleated to have a larger
/// than necessary encoding.
// https://github.com/monero-project/monero/blob/8d4c625713e3419573dfcc7119c8848f47cabbaa
//   /contrib/epee/include/storages/portable_storage_from_bin.h#L237-L255
pub(crate) fn read_varint(reader: &mut &[u8]) -> Result<u64, EpeeError> {
  let vi_start = read_byte(reader)?;

  // https://github.com/monero-project/monero/blob/8d4c625713e3419573dfcc7119c8848f47cabbaa
  //  /contrib/epee/include/storages/portable_storage_base.h#L41
  let len = match vi_start & 0b11 {
    0 => 1,
    1 => 2,
    2 => 4,
    3 => 8,
    _ => unreachable!(),
  };

  let mut vi = u64::from(vi_start);
  for i in 1 .. len {
    vi |= u64::from(read_byte(reader)?) << (i * 8);
  }
  vi >>= 2;

  Ok(vi)
}
