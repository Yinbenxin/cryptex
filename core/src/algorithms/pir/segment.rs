//! Segment files: records sorted by id, written once, never modified.
//!
//! Layout (integers little-endian):
//!
//! ```text
//! header  "CPIRSG" ‖ version (u8) ‖ 0 (u8) ‖ live (u64) ‖ tombstones (u64) ‖
//!         index_offset (u64)                                    (32 bytes)
//! data    records in strictly increasing id order:
//!         id (16) ‖ kind (u8: 0 = record, 1 = tombstone) ‖ body_len (u32) ‖ body
//! index   one entry per INDEX_EVERY records: id prefix (u32, big-endian
//!         order as a number) ‖ offset of that record (u64)
//! ```
//!
//! The sparse index finds the records of an id-prefix range with one
//! binary search and one read of at most `INDEX_EVERY` extra records on
//! each side.

use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use super::ID_LEN;
use crate::{Error, Result};

const MAGIC: &[u8; 6] = b"CPIRSG";
const VERSION: u8 = 1;
const HEADER_LEN: u64 = 32;
/// Records per index entry.
const INDEX_EVERY: u64 = 64;
const INDEX_ENTRY: usize = 12;
/// Record header: id, kind, body length.
pub(crate) const RECORD_HEADER: usize = ID_LEN + 1 + 4;

pub(crate) const KIND_RECORD: u8 = 0;
pub(crate) const KIND_TOMBSTONE: u8 = 1;

pub(crate) fn io_error(path: &Path, e: std::io::Error) -> Error {
    Error::OperationFailed(format!("{}: {e}", path.display()))
}

fn corrupt(path: &Path, what: &str) -> Error {
    Error::InvalidInput(format!(
        "{}: not a valid PIR segment ({what})",
        path.display()
    ))
}

/// One record; `body` is empty for a tombstone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Record {
    pub(crate) id: [u8; ID_LEN],
    pub(crate) kind: u8,
    pub(crate) body: Vec<u8>,
}

pub(crate) fn prefix(id: &[u8; ID_LEN]) -> u32 {
    u32::from_be_bytes(id[..4].try_into().expect("4 bytes"))
}

/// Writes a segment from records given in strictly increasing id order.
/// The file appears under its final name only on [`finish`](Self::finish).
pub(crate) struct SegmentWriter {
    tmp: PathBuf,
    path: PathBuf,
    out: BufWriter<File>,
    offset: u64,
    live: u64,
    tombstones: u64,
    index: Vec<u8>,
    last: Option<[u8; ID_LEN]>,
}

impl SegmentWriter {
    pub(crate) fn create(path: &Path) -> Result<Self> {
        let mut tmp = path.as_os_str().to_os_string();
        tmp.push(".tmp");
        let tmp = PathBuf::from(tmp);
        let file = File::create(&tmp).map_err(|e| io_error(&tmp, e))?;
        let mut out = BufWriter::with_capacity(1 << 20, file);
        out.write_all(&[0u8; HEADER_LEN as usize])
            .map_err(|e| io_error(&tmp, e))?;
        Ok(Self {
            tmp,
            path: path.to_path_buf(),
            out,
            offset: HEADER_LEN,
            live: 0,
            tombstones: 0,
            index: Vec::new(),
            last: None,
        })
    }

    pub(crate) fn push(&mut self, id: &[u8; ID_LEN], kind: u8, body: &[u8]) -> Result<()> {
        if self.last.is_some_and(|l| l >= *id) {
            return Err(Error::OperationFailed(
                "PIR: segment records out of order".into(),
            ));
        }
        self.last = Some(*id);
        if (self.live + self.tombstones).is_multiple_of(INDEX_EVERY) {
            self.index.extend_from_slice(&prefix(id).to_le_bytes());
            self.index.extend_from_slice(&self.offset.to_le_bytes());
        }
        let tmp = &self.tmp;
        let w =
            |out: &mut BufWriter<File>, b: &[u8]| out.write_all(b).map_err(|e| io_error(tmp, e));
        w(&mut self.out, id)?;
        w(&mut self.out, &[kind])?;
        w(&mut self.out, &(body.len() as u32).to_le_bytes())?;
        w(&mut self.out, body)?;
        self.offset += (RECORD_HEADER + body.len()) as u64;
        if kind == KIND_TOMBSTONE {
            self.tombstones += 1;
        } else {
            self.live += 1;
        }
        Ok(())
    }

    /// Write the index and header, sync, and move the file into place.
    pub(crate) fn finish(mut self) -> Result<(u64, u64)> {
        let tmp = self.tmp.clone();
        let err = |e| io_error(&tmp, e);
        self.out.write_all(&self.index).map_err(err)?;
        let mut file = self
            .out
            .into_inner()
            .map_err(|e| io_error(&tmp, e.into_error()))?;
        let mut h = [0u8; HEADER_LEN as usize];
        h[..6].copy_from_slice(MAGIC);
        h[6] = VERSION;
        h[8..16].copy_from_slice(&self.live.to_le_bytes());
        h[16..24].copy_from_slice(&self.tombstones.to_le_bytes());
        h[24..32].copy_from_slice(&self.offset.to_le_bytes());
        file.seek(SeekFrom::Start(0)).map_err(err)?;
        file.write_all(&h).map_err(err)?;
        file.sync_all().map_err(err)?;
        drop(file);
        fs::rename(&tmp, &self.path).map_err(|e| io_error(&self.path, e))?;
        Ok((self.live, self.tombstones))
    }
}

/// An open segment: header and sparse index in memory.
pub(crate) struct Segment {
    file: File,
    path: PathBuf,
    pub(crate) tombstones: u64,
    data_end: u64,
    /// (id prefix, offset) every INDEX_EVERY records.
    index: Vec<(u32, u64)>,
}

fn read_header(path: &Path, file: &mut File) -> Result<(u64, u64, u64)> {
    let mut h = [0u8; HEADER_LEN as usize];
    file.read_exact(&mut h)
        .map_err(|_| corrupt(path, "too short"))?;
    if &h[..6] != MAGIC || h[6] != VERSION {
        return Err(corrupt(path, "bad magic or version"));
    }
    let u = |i: usize| u64::from_le_bytes(h[i..i + 8].try_into().expect("8 bytes"));
    Ok((u(8), u(16), u(24)))
}

impl Segment {
    pub(crate) fn open(path: &Path) -> Result<Self> {
        let mut file = File::open(path).map_err(|e| io_error(path, e))?;
        let size = file.metadata().map_err(|e| io_error(path, e))?.len();
        let (live, tombstones, data_end) = read_header(path, &mut file)?;
        let count = live
            .checked_add(tombstones)
            .ok_or_else(|| corrupt(path, "counts"))?;
        let entries = count.div_ceil(INDEX_EVERY);
        if data_end < HEADER_LEN || data_end.checked_add(entries * INDEX_ENTRY as u64) != Some(size)
        {
            return Err(corrupt(path, "size mismatch"));
        }
        let mut raw = vec![0u8; (size - data_end) as usize];
        read_at(&file, &mut raw, data_end).map_err(|e| io_error(path, e))?;
        let index: Vec<(u32, u64)> = raw
            .as_chunks::<INDEX_ENTRY>()
            .0
            .iter()
            .map(|c| {
                (
                    u32::from_le_bytes(c[..4].try_into().expect("4 bytes")),
                    u64::from_le_bytes(c[4..].try_into().expect("8 bytes")),
                )
            })
            .collect();
        if index
            .windows(2)
            .any(|w| w[0].0 > w[1].0 || w[0].1 >= w[1].1)
            || index.last().is_some_and(|l| l.1 >= data_end)
        {
            return Err(corrupt(path, "bad index"));
        }
        Ok(Self {
            file,
            path: path.to_path_buf(),
            tombstones,
            data_end,
            index,
        })
    }

    /// Records whose id prefix (top 32 bits) lies in `lo..=hi`, in id order.
    pub(crate) fn range(&self, lo: u32, hi: u32) -> Result<Vec<Record>> {
        // Last entry strictly below lo: every record before it is < lo.
        let start = match self.index.partition_point(|e| e.0 < lo) {
            0 => HEADER_LEN,
            i => self.index[i - 1].1,
        };
        // First entry strictly above hi: it and everything after are > hi.
        let end = match self.index.partition_point(|e| e.0 <= hi) {
            i if i == self.index.len() => self.data_end,
            i => self.index[i].1,
        };
        if start >= end {
            return Ok(Vec::new());
        }
        let mut buf = vec![0u8; (end - start) as usize];
        read_at(&self.file, &mut buf, start).map_err(|e| io_error(&self.path, e))?;
        let mut out = Vec::new();
        let mut at = 0;
        while at < buf.len() {
            let (rec, used) =
                parse_record(&buf[at..]).ok_or_else(|| corrupt(&self.path, "record"))?;
            at += used;
            let p = prefix(&rec.id);
            if p > hi {
                break;
            }
            if p >= lo {
                out.push(rec);
            }
        }
        Ok(out)
    }

    /// Sequential reader over all records.
    pub(crate) fn reader(&self) -> Result<SegmentReader> {
        let mut file = self.file.try_clone().map_err(|e| io_error(&self.path, e))?;
        file.seek(SeekFrom::Start(HEADER_LEN))
            .map_err(|e| io_error(&self.path, e))?;
        Ok(SegmentReader {
            input: BufReader::with_capacity(1 << 20, file),
            left: self.data_end - HEADER_LEN,
            path: self.path.clone(),
        })
    }
}

/// Parse one record at the start of `buf`; `None` if malformed.
fn parse_record(buf: &[u8]) -> Option<(Record, usize)> {
    let head = buf.get(..RECORD_HEADER)?;
    let id: [u8; ID_LEN] = head[..ID_LEN].try_into().ok()?;
    let kind = head[ID_LEN];
    let len = u32::from_le_bytes(head[ID_LEN + 1..].try_into().ok()?) as usize;
    if kind > KIND_TOMBSTONE {
        return None;
    }
    let body = buf.get(RECORD_HEADER..RECORD_HEADER + len)?.to_vec();
    Some((Record { id, kind, body }, RECORD_HEADER + len))
}

/// Streams a segment's records in id order.
pub(crate) struct SegmentReader {
    input: BufReader<File>,
    left: u64,
    path: PathBuf,
}

impl SegmentReader {
    pub(crate) fn next_record(&mut self) -> Result<Option<Record>> {
        if self.left == 0 {
            return Ok(None);
        }
        let bad = |what| corrupt(&self.path, what);
        let mut head = [0u8; RECORD_HEADER];
        self.input
            .read_exact(&mut head)
            .map_err(|_| bad("truncated record"))?;
        let id: [u8; ID_LEN] = head[..ID_LEN].try_into().expect("16 bytes");
        let kind = head[ID_LEN];
        let len = u32::from_le_bytes(head[ID_LEN + 1..].try_into().expect("4 bytes")) as usize;
        // Bound by the bytes left in the data area, so a corrupt length
        // cannot make us allocate more than the file holds.
        if kind > KIND_TOMBSTONE || (RECORD_HEADER + len) as u64 > self.left {
            return Err(bad("record"));
        }
        let mut body = vec![0u8; len];
        self.input
            .read_exact(&mut body)
            .map_err(|_| bad("truncated record"))?;
        self.left = self
            .left
            .checked_sub((RECORD_HEADER + len) as u64)
            .ok_or_else(|| bad("record past data"))?;
        Ok(Some(Record { id, kind, body }))
    }
}

#[cfg(unix)]
fn read_at(file: &File, buf: &mut [u8], offset: u64) -> std::io::Result<()> {
    use std::os::unix::fs::FileExt;
    file.read_exact_at(buf, offset)
}

#[cfg(windows)]
fn read_at(file: &File, mut buf: &mut [u8], mut offset: u64) -> std::io::Result<()> {
    use std::os::windows::fs::FileExt;
    while !buf.is_empty() {
        match file.seek_read(buf, offset)? {
            0 => return Err(std::io::ErrorKind::UnexpectedEof.into()),
            n => {
                buf = &mut buf[n..];
                offset += n as u64;
            }
        }
    }
    Ok(())
}
