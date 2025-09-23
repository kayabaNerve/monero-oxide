//! IO primitives around `&[u8]`.

use crate::EpeeError;

/// Read a fixed amount of bytes from the slice.
///
/// This will return `Ok(slice)` where `slice` is the expected length or `Err(_)`.
pub(crate) fn read_bytes<'a>(reader: &mut &'a [u8], bytes: usize) -> Result<&'a [u8], EpeeError> {
  if reader.len() < bytes {
    Err(EpeeError::Short(bytes))?;
  }
  let res = &reader[.. bytes];
  *reader = &reader[bytes ..];
  Ok(res)
}

pub(crate) fn read_byte(reader: &mut &[u8]) -> Result<u8, EpeeError> {
  Ok(read_bytes(reader, 1)?[0])
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

/// Read a string per EPEE's definition.
pub(crate) fn read_str<'a>(reader: &mut &'a [u8]) -> Result<&'a [u8], EpeeError> {
  let len = usize::try_from(read_varint(reader)?).map_err(|_| EpeeError::Short(usize::MAX))?;
  if reader.len() < len {
    Err(EpeeError::Short(len))?;
  }
  let res = &reader[.. len];
  *reader = &reader[len ..];
  Ok(res)
}
