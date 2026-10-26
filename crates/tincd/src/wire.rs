//! Bounds-checked access at fixed offsets for the packet parsers.
//! Every accessor returns `None` past the end, so callers drop the
//! packet with `?` instead of panicking on peer-controlled lengths.

#![forbid(unsafe_code)]

/// Byte at `off`.
#[inline]
pub(crate) fn u8_at(buf: &[u8], off: usize) -> Option<u8> {
    buf.get(off).copied()
}

/// Big-endian `u16` at `off`.
#[inline]
pub(crate) fn be16(buf: &[u8], off: usize) -> Option<u16> {
    array(buf, off).copied().map(u16::from_be_bytes)
}

/// `N` bytes at `off`.
#[inline]
pub(crate) fn array<const N: usize>(buf: &[u8], off: usize) -> Option<&[u8; N]> {
    buf.get(off..)?.first_chunk()
}

/// `N` mutable bytes at `off`.
#[inline]
pub(crate) fn array_mut<const N: usize>(buf: &mut [u8], off: usize) -> Option<&mut [u8; N]> {
    buf.get_mut(off..)?.first_chunk_mut()
}

/// Store `v` big-endian at `off`. Returns `None`, writing nothing, if short.
#[inline]
pub(crate) fn put_be16(buf: &mut [u8], off: usize, v: u16) -> Option<()> {
    *array_mut(buf, off)? = v.to_be_bytes();
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounds() {
        let mut b = [1u8, 2, 3];
        assert_eq!(be16(&b, 1), Some(0x0203));
        assert_eq!(be16(&b, 2), None);
        assert_eq!(be16(&b, usize::MAX), None);
        assert_eq!(array::<3>(&b, 0), Some(&[1, 2, 3]));
        assert_eq!(array::<0>(&b, 3), Some(&[]));
        assert_eq!(put_be16(&mut b, 2, 7), None);
        assert_eq!(b, [1, 2, 3]);
        assert_eq!(put_be16(&mut b, 0, 0xABCD), Some(()));
        assert_eq!(b, [0xAB, 0xCD, 3]);
    }
}
