//! On-disk bucket store for bucketed PSI runs.
//!
//! The input is read once and every value is appended to the file of its
//! bucket ([`bucket`](super::bucket)), so only one bucket needs to be in
//! memory at a time. A record is `position (u64 LE) ‖ length (u32 LE) ‖
//! bytes`, where `position` is the value's index in the input; records of a
//! bucket stay in input order. Equal values always land in the same
//! bucket, so dropping duplicates within each bucket (first occurrence
//! kept) deduplicates the whole input.
//!
//! The receiver tracks positions: after a bucket's PSI, [`mark`] sets the
//! bits of its matching positions in a bitmap over the whole input, from
//! which the result is written out in input order.
//!
//! [`mark`]: BucketStore::mark

use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

use crate::algorithms::psi::bucket::{self, BucketHash};
use crate::exec::Executor;
use crate::{Error, Result};

/// Record header: position (u64) and length (u32), little-endian.
const HEADER: usize = 12;
/// Buffered record bytes, over all buckets, before writing to disk.
const FLUSH_BYTES: usize = 32 << 20;
/// Values per batch when reading a text file.
const LINE_BATCH: usize = 1 << 16;

/// A bucket loaded into memory: distinct values, concatenated.
#[derive(Default)]
pub struct Loaded {
    /// Values back to back.
    pub data: Vec<u8>,
    /// Length of each value.
    pub lens: Vec<usize>,
}

/// Per-bucket files under one directory; see the module docs.
pub struct BucketStore {
    dir: PathBuf,
    hash: BucketHash,
    buckets: u32,
    exec: Executor,
    /// Record bytes not yet written, per bucket.
    buffers: Vec<Vec<u8>>,
    buffered: usize,
    /// Whether bucket `b` has a file.
    on_disk: Vec<bool>,
    total: u64,
    finished: bool,
    compacted: bool,
    /// Receiver: positions of loaded buckets awaiting `mark`, and the bitmap.
    track: bool,
    positions: HashMap<u32, Vec<u64>>,
    bitmap: Vec<u8>,
    marked: u64,
}

impl BucketStore {
    /// Store with `buckets` files under `dir`, which must exist and should
    /// be private to this run. `track`: keep input positions for
    /// [`mark`](Self::mark) (the receiver).
    pub(crate) fn new(
        dir: &Path,
        buckets: u32,
        hash: BucketHash,
        track: bool,
        exec: Executor,
    ) -> Result<Self> {
        bucket::bucket_of(hash, buckets, b"")?; // validates the count
        if !dir.is_dir() {
            return Err(Error::InvalidInput(format!(
                "{} is not a directory",
                dir.display()
            )));
        }
        let n = buckets as usize;
        Ok(Self {
            dir: dir.to_path_buf(),
            hash,
            buckets,
            exec,
            buffers: vec![Vec::new(); n],
            buffered: 0,
            on_disk: vec![false; n],
            total: 0,
            finished: false,
            compacted: false,
            track,
            positions: HashMap::new(),
            bitmap: Vec::new(),
            marked: 0,
        })
    }

    /// Values added so far.
    pub(crate) fn total(&self) -> u64 {
        self.total
    }

    /// Positions marked so far.
    pub(crate) fn marked(&self) -> u64 {
        self.marked
    }

    /// Append values, in input order.
    pub(crate) fn add(&mut self, items: &[&[u8]]) -> Result<()> {
        if self.finished {
            return Err(Error::InvalidState("bucket store already finished".into()));
        }
        if items.iter().any(|x| u32::try_from(x.len()).is_err()) {
            return Err(Error::InvalidInput("value longer than 4 GiB".into()));
        }
        let mut assigned = vec![0u32; items.len()];
        bucket::assign_into(self.hash, self.buckets, items, &mut assigned, &self.exec)?;
        for (x, &b) in items.iter().zip(&assigned) {
            let buf = &mut self.buffers[b as usize];
            buf.extend_from_slice(&self.total.to_le_bytes());
            buf.extend_from_slice(&(x.len() as u32).to_le_bytes());
            buf.extend_from_slice(x);
            self.buffered += HEADER + x.len();
            self.total += 1;
        }
        if self.buffered >= FLUSH_BYTES {
            self.flush()?;
        }
        Ok(())
    }

    /// Append the values of a UTF-8 text file, one per line, as the Python
    /// binding reads it: lines end at `\n`, `\r` or `\r\n`, surrounding
    /// whitespace (as Python's `str.strip`) is removed, empty values are
    /// skipped, and with `bom` a leading UTF-8 BOM is dropped (Python's
    /// `utf-8-sig`). Invalid UTF-8 is an error.
    pub(crate) fn add_lines(&mut self, path: &Path, bom: bool) -> Result<()> {
        let mut data = Vec::new();
        let mut ends = Vec::new();
        for_each_line(path, bom, |v| {
            data.extend_from_slice(v);
            ends.push(data.len());
            if ends.len() >= LINE_BATCH {
                self.add(&split_ends(&data, &ends))?;
                data.clear();
                ends.clear();
            }
            Ok(())
        })?;
        self.add(&split_ends(&data, &ends))
    }

    /// Write all buffered records to their files; one file open at a time,
    /// so large bucket counts do not hit the open-file limit.
    fn flush(&mut self) -> Result<()> {
        for (b, buf) in self.buffers.iter_mut().enumerate() {
            if buf.is_empty() {
                continue;
            }
            let path = bucket_path(&self.dir, b as u32);
            self.on_disk[b] = true;
            let mut f = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .map_err(|e| io_error(&path, e))?;
            f.write_all(buf).map_err(|e| io_error(&path, e))?;
            *buf = Vec::new();
        }
        self.buffered = 0;
        Ok(())
    }

    /// End of input: write everything out. Idempotent; implied by
    /// [`compact`](Self::compact) and [`load`](Self::load).
    pub(crate) fn finish(&mut self) -> Result<()> {
        if self.finished {
            return Ok(());
        }
        self.flush()?;
        self.buffers = Vec::new();
        self.finished = true;
        if self.track {
            self.bitmap = vec![0u8; self.total.div_ceil(8) as usize];
        }
        Ok(())
    }

    /// Drop duplicates from every bucket file and return the distinct count
    /// per bucket, so a party can announce exact sizes before the PSI. One
    /// bucket in memory at a time.
    pub(crate) fn compact(&mut self) -> Result<Vec<u64>> {
        self.finish()?;
        let mut sizes = Vec::with_capacity(self.buckets as usize);
        for b in 0..self.buckets {
            if !self.on_disk[b as usize] {
                sizes.push(0);
                continue;
            }
            let path = bucket_path(&self.dir, b);
            let buf = fs::read(&path).map_err(|e| io_error(&path, e))?;
            let records = parse(&buf, &path)?;
            let keep = distinct(&buf, &records);
            sizes.push(keep.len() as u64);
            if keep.len() < records.len() {
                let mut out = Vec::with_capacity(buf.len());
                for &i in &keep {
                    let (start, _, end) = records[i];
                    out.extend_from_slice(&buf[start..end]);
                }
                fs::write(&path, &out).map_err(|e| io_error(&path, e))?;
            }
        }
        self.compacted = true;
        Ok(sizes)
    }

    /// Read bucket `b` into memory and delete its file: its distinct values
    /// in input order. With tracking, their positions are kept for
    /// [`mark`](Self::mark).
    pub(crate) fn load(&mut self, b: u32) -> Result<Loaded> {
        self.finish()?;
        if b >= self.buckets {
            return Err(Error::InvalidInput(format!("bucket {b} out of range")));
        }
        if !self.on_disk[b as usize] {
            return Ok(Loaded::default());
        }
        let path = bucket_path(&self.dir, b);
        let buf = fs::read(&path).map_err(|e| io_error(&path, e))?;
        fs::remove_file(&path).map_err(|e| io_error(&path, e))?;
        self.on_disk[b as usize] = false;
        let records = parse(&buf, &path)?;
        let keep: Vec<usize> = if self.compacted {
            (0..records.len()).collect()
        } else {
            distinct(&buf, &records)
        };
        let mut out = Loaded {
            data: Vec::with_capacity(buf.len() - HEADER * records.len()),
            lens: Vec::with_capacity(keep.len()),
        };
        for &i in &keep {
            let (start, _, end) = records[i];
            out.data.extend_from_slice(&buf[start + HEADER..end]);
            out.lens.push(end - start - HEADER);
        }
        if self.track && !keep.is_empty() {
            let pos = keep.iter().map(|&i| records[i].1).collect();
            self.positions.insert(b, pos);
        }
        Ok(out)
    }

    /// Record that the values at `indices` of loaded bucket `b` matched.
    /// Buckets are marked in increasing order; positions of lower buckets
    /// still held (loaded but given no result, e.g. skipped by the protocol
    /// because the peer's side was empty) are released.
    pub(crate) fn mark(&mut self, b: u32, indices: &[usize]) -> Result<()> {
        if !self.track {
            return Err(Error::InvalidState(
                "bucket store does not track positions".into(),
            ));
        }
        let pos = self.positions.remove(&b).unwrap_or_default();
        self.positions.retain(|&k, _| k > b);
        for &i in indices {
            let &p = pos.get(i).ok_or_else(|| {
                Error::InvalidInput(format!("index {i} out of range for bucket {b}"))
            })?;
            let (byte, bit) = ((p / 8) as usize, 1u8 << (p % 8));
            if self.bitmap[byte] & bit == 0 {
                self.bitmap[byte] |= bit;
                self.marked += 1;
            }
        }
        Ok(())
    }

    /// The match bitmap over input positions (bit `p % 8` of byte `p / 8`).
    pub(crate) fn bitmap(&self) -> &[u8] {
        &self.bitmap
    }

    /// Copy the matched values of the text file `input` (read as in
    /// [`add_lines`](Self::add_lines)) to `output`, one per line, in input
    /// order. Returns the number written. Fails if `input` no longer has
    /// the number of values that was added.
    pub(crate) fn write_lines(&self, input: &Path, bom: bool, output: &Path) -> Result<u64> {
        if !self.track || !self.finished {
            return Err(Error::InvalidState(
                "bucket store has no results to write".into(),
            ));
        }
        let file = File::create(output).map_err(|e| io_error(output, e))?;
        let mut w = BufWriter::new(file);
        let (mut pos, mut written) = (0u64, 0u64);
        for_each_line(input, bom, |v| {
            if pos < self.total && self.bitmap[(pos / 8) as usize] & (1 << (pos % 8)) != 0 {
                w.write_all(v)
                    .and_then(|()| w.write_all(b"\n"))
                    .map_err(|e| io_error(output, e))?;
                written += 1;
            }
            pos += 1;
            Ok(())
        })?;
        if pos != self.total {
            return Err(Error::OperationFailed(format!(
                "input changed during PSI: read {pos} values, expected {}",
                self.total
            )));
        }
        w.flush().map_err(|e| io_error(output, e))?;
        Ok(written)
    }
}

impl Drop for BucketStore {
    /// Remove the bucket files that are left (after an error, or buckets
    /// that were never loaded).
    fn drop(&mut self) {
        for (b, &present) in self.on_disk.iter().enumerate() {
            if present {
                let _ = fs::remove_file(bucket_path(&self.dir, b as u32));
            }
        }
    }
}

fn bucket_path(dir: &Path, b: u32) -> PathBuf {
    dir.join(format!("bucket-{b:07}.bin"))
}

fn io_error(path: &Path, e: std::io::Error) -> Error {
    Error::OperationFailed(format!("{}: {e}", path.display()))
}

/// Records of a bucket file as `(start, position, end)` byte offsets.
fn parse(buf: &[u8], path: &Path) -> Result<Vec<(usize, u64, usize)>> {
    let corrupt = || Error::OperationFailed(format!("corrupt bucket file {}", path.display()));
    let mut out = Vec::new();
    let mut off = 0;
    while off < buf.len() {
        let head = buf.get(off..off + HEADER).ok_or_else(corrupt)?;
        let pos = u64::from_le_bytes(head[..8].try_into().expect("8"));
        let len = u32::from_le_bytes(head[8..].try_into().expect("4")) as usize;
        let end = off + HEADER + len;
        if end > buf.len() {
            return Err(corrupt());
        }
        out.push((off, pos, end));
        off = end;
    }
    Ok(out)
}

/// Indices of the records whose value was not seen before, in order.
fn distinct(buf: &[u8], records: &[(usize, u64, usize)]) -> Vec<usize> {
    let mut seen = HashSet::with_capacity(records.len());
    (0..records.len())
        .filter(|&i| {
            let (start, _, end) = records[i];
            seen.insert(&buf[start + HEADER..end])
        })
        .collect()
}

/// Values of `data`, the `i`-th ending at `ends[i]`.
fn split_ends<'a>(data: &'a [u8], ends: &[usize]) -> Vec<&'a [u8]> {
    let mut start = 0;
    ends.iter()
        .map(|&end| {
            let v = &data[start..end];
            start = end;
            v
        })
        .collect()
}

/// Python's `str.isspace` (and thus `str.strip`): Unicode White_Space plus
/// the ASCII separators U+001C..U+001F.
fn is_py_space(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

/// Call `f` with each non-empty, stripped value of a UTF-8 text file.
fn for_each_line(path: &Path, bom: bool, mut f: impl FnMut(&[u8]) -> Result<()>) -> Result<()> {
    let file = File::open(path).map_err(|e| io_error(path, e))?;
    let mut r = BufReader::with_capacity(1 << 20, file);
    let mut line = Vec::new();
    let mut first = true;
    loop {
        line.clear();
        let n = r
            .read_until(b'\n', &mut line)
            .map_err(|e| io_error(path, e))?;
        if n == 0 {
            return Ok(());
        }
        let mut chunk = &line[..];
        if first && bom {
            chunk = chunk.strip_prefix(b"\xef\xbb\xbf").unwrap_or(chunk);
        }
        first = false;
        // `\r` never occurs inside a multi-byte UTF-8 sequence, so splitting
        // the bytes on it is the same as splitting the text.
        for part in chunk.split(|&c| c == b'\r') {
            let s = std::str::from_utf8(part)
                .map_err(|_| Error::InvalidInput(format!("{}: not valid UTF-8", path.display())))?;
            let v = s.trim_matches(is_py_space);
            if !v.is_empty() {
                f(v.as_bytes())?;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// A fresh directory under the system temp dir, removed on drop.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            static N: AtomicU32 = AtomicU32::new(0);
            let p = std::env::temp_dir().join(format!(
                "cryptex-store-test-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&p).unwrap();
            Self(p)
        }

        fn files(&self) -> usize {
            fs::read_dir(&self.0).unwrap().count()
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn store(dir: &TempDir, buckets: u32, track: bool) -> BucketStore {
        BucketStore::new(
            &dir.0,
            buckets,
            BucketHash::Sha256,
            track,
            Executor::default(),
        )
        .unwrap()
    }

    fn values(l: &Loaded) -> Vec<Vec<u8>> {
        let mut off = 0;
        l.lens
            .iter()
            .map(|&n| {
                off += n;
                l.data[off - n..off].to_vec()
            })
            .collect()
    }

    fn add(s: &mut BucketStore, xs: &[String]) {
        let items: Vec<&[u8]> = xs.iter().map(|x| x.as_bytes()).collect();
        s.add(&items).unwrap();
    }

    fn write(dir: &TempDir, name: &str, bytes: &[u8]) -> PathBuf {
        let p = dir.0.join(name);
        fs::write(&p, bytes).unwrap();
        p
    }

    /// Partition, compact, load, mark: every value lands in its bucket
    /// once, duplicates are dropped (first position kept), and the bitmap
    /// covers exactly the marked positions.
    #[test]
    fn partition_compact_load_mark() {
        let dir = TempDir::new();
        let mut s = store(&dir, 7, true);
        // 1000 values; the second batch repeats values 0..300.
        let a: Vec<String> = (0..700).map(|i| format!("v{i}")).collect();
        let b: Vec<String> = (0..300).map(|i| format!("v{i}")).collect();
        add(&mut s, &a);
        add(&mut s, &b);
        assert_eq!(s.total(), 1000);
        let sizes = s.compact().unwrap();
        assert_eq!(sizes.iter().sum::<u64>(), 700);

        let mut seen = HashSet::new();
        for bk in 0..7 {
            let l = s.load(bk).unwrap();
            let vs = values(&l);
            assert_eq!(vs.len() as u64, sizes[bk as usize]);
            let idx: Vec<usize> = (0..vs.len())
                .filter(|&i| vs[i].starts_with(b"v1"))
                .collect();
            for v in &vs {
                assert_eq!(bucket::bucket_of(BucketHash::Sha256, 7, v).unwrap(), bk);
                assert!(seen.insert(v.clone()), "duplicate {v:?}");
            }
            s.mark(bk, &idx).unwrap();
        }
        // Marked: the first occurrences (positions < 700) of v1*.
        let expect: Vec<u64> = (0..700u64)
            .filter(|&p| p.to_string().starts_with('1'))
            .collect();
        assert_eq!(s.marked(), expect.len() as u64);
        let bm = s.bitmap();
        for p in 0..1000u64 {
            let set = bm[(p / 8) as usize] & (1 << (p % 8)) != 0;
            assert_eq!(set, expect.contains(&p), "position {p}");
        }
        assert_eq!(dir.files(), 0);
    }

    /// Without compaction, `load` still drops duplicates.
    #[test]
    fn load_dedupes_without_compaction() {
        let dir = TempDir::new();
        let mut s = store(&dir, 1, false);
        let items: [&[u8]; 5] = [b"a", b"b", b"a", b"", b""];
        s.add(&items).unwrap();
        let l = s.load(0).unwrap();
        assert_eq!(values(&l), vec![b"a".to_vec(), b"b".to_vec(), vec![]]);
        assert!(s.load(0).unwrap().lens.is_empty());
        assert!(s.mark(0, &[]).is_err()); // not tracking
    }

    /// Positions of loaded buckets that never get a result are released
    /// when a later bucket is marked.
    #[test]
    fn skipped_buckets_are_released() {
        let dir = TempDir::new();
        let mut s = store(&dir, 4, true);
        let xs: Vec<String> = (0..100).map(|i| i.to_string()).collect();
        add(&mut s, &xs);
        for b in 0..4 {
            s.load(b).unwrap();
        }
        assert_eq!(s.positions.len(), 4);
        s.mark(2, &[0]).unwrap();
        assert_eq!(s.positions.keys().copied().collect::<Vec<_>>(), vec![3]);
        assert!(s.mark(3, &[1 << 20]).is_err()); // index out of range
    }

    /// Bucket files left over (error paths, buckets never loaded) are
    /// removed when the store is dropped.
    #[test]
    fn drop_removes_files() {
        let dir = TempDir::new();
        let mut s = store(&dir, 5, false);
        let xs: Vec<String> = (0..50).map(|i| i.to_string()).collect();
        add(&mut s, &xs);
        s.finish().unwrap();
        assert!(dir.files() > 0);
        s.load(0).unwrap();
        drop(s);
        assert_eq!(dir.files(), 0);
    }

    /// Line splitting and stripping match the Python binding: expected
    /// values taken from `_data.iter_file_items` (Python 3.9) on the same
    /// bytes, with encoding `utf-8-sig` and `utf-8`.
    #[test]
    fn lines_match_python() {
        let dir = TempDir::new();
        let p = write(
            &dir,
            "in.txt",
            b"\xef\xbb\xbf a \r\nb\rc\n\n \t\n\x1cd\x1f\n\xe3\x80\x80e\xe3\x80\x80\n\
              \xef\xbb\xbff\nlast",
        );
        let read = |bom| {
            let mut out = Vec::new();
            for_each_line(&p, bom, |v| {
                out.push(String::from_utf8(v.to_vec()).unwrap());
                Ok(())
            })
            .unwrap();
            out
        };
        assert_eq!(read(true), ["a", "b", "c", "d", "e", "\u{feff}f", "last"]);
        assert_eq!(
            read(false),
            ["\u{feff} a", "b", "c", "d", "e", "\u{feff}f", "last"]
        );

        let bad = write(&dir, "bad.txt", b"ok\n\xff\n");
        let mut s = store(&dir, 1, false);
        assert!(matches!(
            s.add_lines(&bad, true),
            Err(Error::InvalidInput(_))
        ));
    }

    /// `is_py_space` equals CPython's `str.isspace` over all code points.
    #[test]
    fn whitespace_matches_python() {
        const PY: &[u32] = &[
            0x9, 0xa, 0xb, 0xc, 0xd, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x85, 0xa0, 0x1680, 0x2000,
            0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200a, 0x2028,
            0x2029, 0x202f, 0x205f, 0x3000,
        ];
        let ours: Vec<u32> = (0..=0x10ffffu32)
            .filter_map(char::from_u32)
            .filter(|&c| is_py_space(c))
            .map(u32::from)
            .collect();
        assert_eq!(ours, PY);
    }

    /// Text file in, matched lines out, in input order; a changed input
    /// file is detected.
    #[test]
    fn write_lines_round_trip() {
        let dir = TempDir::new();
        let work = TempDir::new();
        let input = write(&dir, "in.txt", b"x1\n x2 \n\nx1\nx3\r\nx4");
        let mut s = store(&work, 3, true);
        s.add_lines(&input, true).unwrap();
        assert_eq!(s.total(), 5); // x1 x2 x1 x3 x4
        s.compact().unwrap();
        for b in 0..3 {
            let l = s.load(b).unwrap();
            let idx: Vec<usize> = values(&l)
                .iter()
                .enumerate()
                .filter(|(_, v)| v.as_slice() != b"x2")
                .map(|(i, _)| i)
                .collect();
            s.mark(b, &idx).unwrap();
        }
        let out = dir.0.join("out.txt");
        assert_eq!(s.write_lines(&input, true, &out).unwrap(), 3);
        assert_eq!(fs::read(&out).unwrap(), b"x1\nx3\nx4\n");

        fs::write(&input, b"x1\n").unwrap();
        assert!(matches!(
            s.write_lines(&input, true, &out),
            Err(Error::OperationFailed(_))
        ));
    }

    #[test]
    fn rejects_bad_arguments() {
        let dir = TempDir::new();
        let exec = Executor::default;
        let new = |b, d: &Path| BucketStore::new(d, b, BucketHash::Sm3, false, exec());
        assert!(new(0, &dir.0).is_err());
        assert!(new(bucket::MAX_BUCKETS + 1, &dir.0).is_err());
        assert!(new(1, &dir.0.join("missing")).is_err());
        let mut s = new(2, &dir.0).unwrap();
        assert!(s.load(2).is_err());
        s.finish().unwrap();
        assert!(matches!(s.add(&[b"x"]), Err(Error::InvalidState(_))));
    }
}
