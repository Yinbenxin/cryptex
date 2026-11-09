//! Shared PSI helpers: wire encoding (also used by PIR), truncation and
//! intersection.

use std::collections::{HashMap, HashSet};

use crate::{Error, Result};

/// Statistical security parameter: false-positive probability <= 2^-40.
pub(crate) const STAT_SECURITY_BITS: u32 = 40;

/// Bytes of a truncated PRF/hash output such that a false match happens
/// with probability <= 2^-λ over all `n * m` comparisons of one session, and
/// over all sessions of a job split into `sessions` parts (buckets):
/// `λ + log2(n) + log2(m) + log2(sessions)` bits, rounded up to bytes.
pub(crate) fn truncation_len(n: usize, m: usize, sessions: u32) -> usize {
    let log2 = |x: usize| usize::BITS - x.max(1).saturating_sub(1).leading_zeros();
    let bits = STAT_SECURITY_BITS + log2(n) + log2(m) + log2(sessions as usize);
    (bits as usize).div_ceil(8).min(32)
}

/// Indices `i` (ascending) such that the `i`-th `len`-byte chunk of
/// `receiver` occurs among the `len`-byte chunks of `sender`.
pub(crate) fn intersect(receiver: &[u8], sender: &[u8], len: usize) -> Vec<usize> {
    let set: HashSet<&[u8]> = sender.chunks_exact(len).collect();
    receiver
        .chunks_exact(len)
        .enumerate()
        .filter(|(_, v)| set.contains(v))
        .map(|(i, _)| i)
        .collect()
}

/// Like [`intersect`], also returning the matching positions in `sender`,
/// sorted ascending (so their order says nothing about the receiver's).
pub(crate) fn intersect_both(
    receiver: &[u8],
    sender: &[u8],
    len: usize,
) -> (Vec<usize>, Vec<usize>) {
    let map: HashMap<&[u8], usize> = sender
        .chunks_exact(len)
        .enumerate()
        .map(|(j, v)| (v, j))
        .collect();
    let (mut ri, mut si) = (Vec::new(), Vec::new());
    for (i, v) in receiver.chunks_exact(len).enumerate() {
        if let Some(&j) = map.get(v) {
            ri.push(i);
            si.push(j);
        }
    }
    si.sort_unstable();
    (ri, si)
}

/// Bytes per index into a list of `m` items: 4 when they fit in u32,
/// else 8. Both parties know `m`, so it is not sent.
fn index_width(m: usize) -> usize {
    if u32::try_from(m).is_ok() {
        4
    } else {
        8
    }
}

/// Encode sorted positions into a list of `m` items: count (u64), then
/// each position in [`index_width`] bytes, big-endian.
pub(crate) fn write_positions(w: &mut Writer, positions: &[usize], m: usize) {
    w.u64(positions.len());
    let width = index_width(m);
    for &p in positions {
        w.bytes(&(p as u64).to_be_bytes()[8 - width..]);
    }
}

/// Decode positions written by [`write_positions`], checking that they
/// are strictly increasing and below `m`.
pub(crate) fn read_positions(r: &mut Reader<'_>, m: usize) -> Result<Vec<usize>> {
    let k = r.u64()?;
    if k > m {
        return Err(malformed("more positions than items"));
    }
    let width = index_width(m);
    let raw = r.array(k, width)?;
    let mut out = Vec::with_capacity(k);
    for c in raw.chunks_exact(width) {
        let mut b = [0u8; 8];
        b[8 - width..].copy_from_slice(c);
        let p = usize::try_from(u64::from_be_bytes(b)).map_err(|_| malformed("bad position"))?;
        if p >= m || out.last().is_some_and(|&q| p <= q) {
            return Err(malformed("positions out of range or not increasing"));
        }
        out.push(p);
    }
    Ok(out)
}

/// Append-only message builder.
pub(crate) struct Writer(Vec<u8>);

impl Writer {
    pub(crate) fn new(tag: u8, capacity: usize) -> Self {
        let mut buf = Vec::with_capacity(capacity + 1);
        buf.push(tag);
        Self(buf)
    }

    pub(crate) fn u8(&mut self, v: u8) {
        self.0.push(v);
    }

    pub(crate) fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }

    pub(crate) fn u64(&mut self, v: usize) {
        self.0.extend_from_slice(&(v as u64).to_be_bytes());
    }

    pub(crate) fn bytes(&mut self, v: &[u8]) {
        self.0.extend_from_slice(v);
    }

    pub(crate) fn finish(self) -> Vec<u8> {
        self.0
    }
}

/// Bounds-checked message parser. Every malformed input is an
/// `InvalidInput` error, never a panic.
pub(crate) struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    /// Start parsing a message that must begin with `tag`.
    pub(crate) fn new(buf: &'a [u8], tag: u8) -> Result<Self> {
        match buf.split_first() {
            Some((&t, rest)) if t == tag => Ok(Self { buf: rest }),
            Some((&t, _)) => Err(malformed(&format!(
                "unexpected message type {t}, expected {tag}"
            ))),
            None => Err(malformed("empty message")),
        }
    }

    pub(crate) fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        if len > self.buf.len() {
            return Err(malformed("truncated message"));
        }
        let (head, tail) = self.buf.split_at(len);
        self.buf = tail;
        Ok(head)
    }

    pub(crate) fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    pub(crate) fn u32(&mut self) -> Result<u32> {
        let raw: [u8; 4] = self.take(4)?.try_into().expect("4 bytes");
        Ok(u32::from_be_bytes(raw))
    }

    pub(crate) fn u64(&mut self) -> Result<usize> {
        let raw: [u8; 8] = self.take(8)?.try_into().expect("8 bytes");
        usize::try_from(u64::from_be_bytes(raw)).map_err(|_| malformed("count too large"))
    }

    /// `count` items of `item_len` bytes each, as one slice.
    pub(crate) fn array(&mut self, count: usize, item_len: usize) -> Result<&'a [u8]> {
        let len = count
            .checked_mul(item_len)
            .ok_or_else(|| malformed("count too large"))?;
        self.take(len)
    }

    pub(crate) fn finish(self) -> Result<()> {
        if self.buf.is_empty() {
            Ok(())
        } else {
            Err(malformed("trailing bytes"))
        }
    }
}

fn malformed(what: &str) -> Error {
    Error::InvalidInput(format!("malformed protocol message: {what}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncation_len_grows_with_set_sizes() {
        assert_eq!(truncation_len(0, 0, 1), 5); // 40 bits
        assert_eq!(truncation_len(1, 1, 1), 5);
        assert_eq!(truncation_len(1 << 10, 1 << 10, 1), 8); // 60 bits
        assert_eq!(truncation_len(1 << 20, 1 << 20, 1), 10); // 80 bits
        assert_eq!(truncation_len(1 << 20, (1 << 20) + 1, 1), 11); // 81 bits
        assert_eq!(truncation_len(usize::MAX, usize::MAX, u32::MAX), 25);
        // 2^10 buckets of 2^10: 40 + 10 + 10 + 10 = 70 bits, versus 80 bits
        // for the same 2^20 x 2^20 job unbucketed.
        assert_eq!(truncation_len(1 << 10, 1 << 10, 1 << 10), 9);
        assert_eq!(truncation_len(0, 0, 0), 5); // 0 treated as 1
    }

    #[test]
    fn intersect_both_sorts_sender_positions() {
        let (r, s) = intersect_both(b"aabbccdd", b"ddxxaa", 2);
        assert_eq!(r, vec![0, 3]);
        assert_eq!(s, vec![0, 2]);
    }

    #[test]
    fn positions_round_trip_and_validate() {
        for m in [10usize, 1 << 40] {
            let mut w = Writer::new(9, 0);
            write_positions(&mut w, &[0, 3, 9], m);
            let msg = w.finish();
            let width = if m == 10 { 4 } else { 8 };
            assert_eq!(msg.len(), 1 + 8 + 3 * width);
            let mut r = Reader::new(&msg, 9).unwrap();
            assert_eq!(read_positions(&mut r, m).unwrap(), vec![0, 3, 9]);
            r.finish().unwrap();
        }
        for bad in [&[3usize, 3][..], &[5, 2], &[10]] {
            let mut w = Writer::new(9, 0);
            write_positions(&mut w, bad, 10);
            let msg = w.finish();
            assert!(read_positions(&mut Reader::new(&msg, 9).unwrap(), 10).is_err());
        }
        // More positions claimed than there are items.
        let mut w = Writer::new(9, 0);
        w.u64(11);
        let msg = w.finish();
        assert!(read_positions(&mut Reader::new(&msg, 9).unwrap(), 10).is_err());
    }

    #[test]
    fn intersect_returns_receiver_indices() {
        let r = b"aabbccdd";
        let s = b"ddxxaa";
        assert_eq!(intersect(r, s, 2), vec![0, 3]);
        assert!(intersect(r, b"", 2).is_empty());
    }

    #[test]
    fn reader_rejects_malformed_input() {
        let mut w = Writer::new(7, 0);
        w.u64(2);
        w.bytes(b"abcd");
        let msg = w.finish();

        let mut r = Reader::new(&msg, 7).unwrap();
        let n = r.u64().unwrap();
        assert_eq!(r.array(n, 2).unwrap(), b"abcd");
        r.finish().unwrap();

        assert!(Reader::new(&msg, 8).is_err());
        assert!(Reader::new(&[], 7).is_err());

        let mut r = Reader::new(&msg, 7).unwrap();
        r.u64().unwrap();
        assert!(r.array(3, 2).is_err()); // truncated
        let mut r = Reader::new(&msg, 7).unwrap();
        r.u64().unwrap();
        assert!(r.array(usize::MAX, 2).is_err()); // overflow
        let mut r = Reader::new(&msg, 7).unwrap();
        r.u64().unwrap();
        r.array(1, 2).unwrap();
        assert!(r.finish().is_err()); // trailing
    }
}
