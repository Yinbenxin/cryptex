//! PIR database directory: a manifest and immutable segments.
//!
//! ```text
//! <dir>/MANIFEST          current state, replaced atomically
//! <dir>/seg-<n>.pir       segments (see `segment`), oldest first in the manifest
//! <dir>/LOCK              held by the one open writer
//! <dir>/work-<random>/    spill files of an uncommitted batch
//! ```
//!
//! Manifest (little-endian): `"CPIRDB" ‖ version (u8) ‖ curve (u8) ‖
//! key_check (16) ‖ generation (u64) ‖ next_segment (u64) ‖ records (u64) ‖
//! max_label_len (u32) ‖ metadata_len (u32) ‖ metadata ‖ count (u32) ‖
//! segment numbers (u64 each)`.
//!
//! Writes go to a batch: [`Database::upsert`] and [`Database::delete`]
//! encrypt and spread the operations over [`PARTITIONS`] spill files by the
//! first id byte, so a batch never has to fit in memory; within a batch the
//! last operation on a key wins. [`Database::commit`] sorts one partition
//! at a time into a new segment and publishes it. A later segment overrides
//! earlier ones for the same id; a tombstone deletes. [`Database::compact`]
//! merges all segments into one and drops tombstones.

use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use rand::RngExt;
use rayon::prelude::*;
use zeroize::Zeroize;

use super::segment::{
    io_error, Segment, SegmentReader, SegmentWriter, KIND_RECORD, KIND_TOMBSTONE,
};
use super::suite::{self, ServerKey};
use super::{check_key, Curve, DbInfo, ID_LEN, LEN_PREFIX, MAX_LABEL_LEN, MAX_METADATA_LEN};
use crate::exec::Executor;
use crate::primitives::rand::csprng;
use crate::{Error, Result};

const MAGIC: &[u8; 6] = b"CPIRDB";
const VERSION: u8 = 2;
const MANIFEST: &str = "MANIFEST";
const LOCK: &str = "LOCK";

/// Spill partitions of a batch, by the first id byte.
const PARTITIONS: usize = 256;
/// Buffered spill bytes, over all partitions, before writing to disk.
const FLUSH_BYTES: usize = 64 << 20;
/// Spill record header: id, kind, sequence number (u64), body length (u32).
const SPILL_HEADER: usize = ID_LEN + 1 + 8 + 4;

pub(crate) fn curve_code(curve: Curve) -> u8 {
    match curve {
        Curve::Ristretto255 => 0,
        Curve::P256 => 1,
        Curve::Sm2 => 2,
        Curve::FourQ => 3,
    }
}

pub(crate) fn curve_from_code(code: u8) -> Result<Curve> {
    Ok(match code {
        0 => Curve::Ristretto255,
        1 => Curve::P256,
        2 => Curve::Sm2,
        3 => Curve::FourQ,
        c => return Err(Error::InvalidInput(format!("unknown PIR curve {c}"))),
    })
}

fn corrupt(path: &Path, what: &str) -> Error {
    Error::InvalidInput(format!(
        "{}: not a valid PIR database ({what})",
        path.display()
    ))
}

/// Contents of the manifest.
#[derive(Clone)]
pub(crate) struct Manifest {
    pub(crate) curve: Curve,
    pub(crate) key_check: [u8; 16],
    pub(crate) generation: u64,
    next_segment: u64,
    pub(crate) records: u64,
    pub(crate) max_label_len: u32,
    pub(crate) metadata: Vec<u8>,
    pub(crate) segments: Vec<u64>,
}

impl Manifest {
    fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(64 + self.metadata.len() + 8 * self.segments.len());
        b.extend_from_slice(MAGIC);
        b.push(VERSION);
        b.push(curve_code(self.curve));
        b.extend_from_slice(&self.key_check);
        b.extend_from_slice(&self.generation.to_le_bytes());
        b.extend_from_slice(&self.next_segment.to_le_bytes());
        b.extend_from_slice(&self.records.to_le_bytes());
        b.extend_from_slice(&self.max_label_len.to_le_bytes());
        b.extend_from_slice(&(self.metadata.len() as u32).to_le_bytes());
        b.extend_from_slice(&self.metadata);
        b.extend_from_slice(&(self.segments.len() as u32).to_le_bytes());
        for s in &self.segments {
            b.extend_from_slice(&s.to_le_bytes());
        }
        b
    }

    fn decode(path: &Path, b: &[u8]) -> Result<Self> {
        let bad = |what| corrupt(path, what);
        let mut at = 0;
        let mut take = |n: usize| -> Result<&[u8]> {
            let s = b.get(at..at + n).ok_or_else(|| bad("truncated manifest"))?;
            at += n;
            Ok(s)
        };
        if take(6)? != MAGIC {
            return Err(bad("bad magic"));
        }
        if take(1)?[0] != VERSION {
            return Err(bad("unsupported version"));
        }
        let curve = curve_from_code(take(1)?[0]).map_err(|_| bad("unknown curve"))?;
        let key_check = take(16)?.try_into().expect("16 bytes");
        let u64_ = |s: &[u8]| u64::from_le_bytes(s.try_into().expect("8 bytes"));
        let u32_ = |s: &[u8]| u32::from_le_bytes(s.try_into().expect("4 bytes"));
        let generation = u64_(take(8)?);
        let next_segment = u64_(take(8)?);
        let records = u64_(take(8)?);
        let max_label_len = u32_(take(4)?);
        let meta_len = u32_(take(4)?) as usize;
        if meta_len > MAX_METADATA_LEN {
            return Err(bad("parameters out of range"));
        }
        let metadata = take(meta_len)?.to_vec();
        let count = u32_(take(4)?) as usize;
        let mut segments = Vec::with_capacity(count.min(1 << 16));
        for _ in 0..count {
            segments.push(u64_(take(8)?));
        }
        if at != b.len() || segments.iter().any(|&s| s >= next_segment) {
            return Err(bad("bad segment list"));
        }
        Ok(Self {
            curve,
            key_check,
            generation,
            next_segment,
            records,
            max_label_len,
            metadata,
            segments,
        })
    }

    pub(crate) fn read(dir: &Path) -> Result<Self> {
        let path = dir.join(MANIFEST);
        let raw = fs::read(&path).map_err(|e| io_error(&path, e))?;
        Self::decode(&path, &raw)
    }

    fn write(&self, dir: &Path) -> Result<()> {
        let tmp = dir.join(format!("{MANIFEST}.tmp"));
        let mut f = File::create(&tmp).map_err(|e| io_error(&tmp, e))?;
        f.write_all(&self.encode()).map_err(|e| io_error(&tmp, e))?;
        f.sync_all().map_err(|e| io_error(&tmp, e))?;
        drop(f);
        let path = dir.join(MANIFEST);
        fs::rename(&tmp, &path).map_err(|e| io_error(&path, e))?;
        // Make the rename durable where directories can be synced.
        if let Ok(d) = File::open(dir) {
            let _ = d.sync_all();
        }
        Ok(())
    }

    pub(crate) fn info(&self) -> DbInfo {
        DbInfo {
            curve: self.curve,
            records: self.records,
            segments: self.segments.len() as u32,
            max_label_len: self.max_label_len,
            generation: self.generation,
            metadata: self.metadata.clone(),
        }
    }
}

pub(crate) fn segment_path(dir: &Path, n: u64) -> PathBuf {
    dir.join(format!("seg-{n:08}.pir"))
}

/// Open the segments of `m`, oldest first.
pub(crate) fn open_segments(dir: &Path, m: &Manifest) -> Result<Vec<Segment>> {
    m.segments
        .iter()
        .map(|&n| Segment::open(&segment_path(dir, n)))
        .collect()
}

/// Server key from `seed`, checked against the manifest.
pub(crate) fn checked_key(dir: &Path, m: &Manifest, seed: &[u8; 32]) -> Result<Box<dyn ServerKey>> {
    let key = suite::server_key(m.curve, seed);
    if key.key_check() != m.key_check {
        return Err(Error::InvalidInput(format!(
            "{}: the seed does not match this PIR database",
            dir.display()
        )));
    }
    Ok(key)
}

/// Uncommitted operations, spilled by partition.
struct Batch {
    dir: PathBuf,
    buffers: Vec<Vec<u8>>,
    buffered: usize,
    on_disk: Vec<bool>,
    seq: u64,
    max_label: usize,
}

impl Batch {
    fn new(db_dir: &Path) -> Result<Self> {
        let suffix: u64 = csprng()?.random();
        let dir = db_dir.join(format!("work-{suffix:016x}"));
        fs::create_dir(&dir).map_err(|e| io_error(&dir, e))?;
        Ok(Self {
            dir,
            buffers: vec![Vec::new(); PARTITIONS],
            buffered: 0,
            on_disk: vec![false; PARTITIONS],
            seq: 0,
            max_label: 0,
        })
    }

    fn push(&mut self, id: &[u8; ID_LEN], kind: u8, body: &[u8]) {
        let buf = &mut self.buffers[id[0] as usize];
        buf.extend_from_slice(id);
        buf.push(kind);
        buf.extend_from_slice(&self.seq.to_le_bytes());
        buf.extend_from_slice(&(body.len() as u32).to_le_bytes());
        buf.extend_from_slice(body);
        self.buffered += SPILL_HEADER + body.len();
        self.seq += 1;
    }

    fn part_path(&self, p: usize) -> PathBuf {
        self.dir.join(format!("part-{p:03}"))
    }

    fn flush(&mut self, limit: usize) -> Result<()> {
        if self.buffered < limit {
            return Ok(());
        }
        for p in 0..PARTITIONS {
            if self.buffers[p].is_empty() {
                continue;
            }
            let path = self.part_path(p);
            let mut f = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .map_err(|e| io_error(&path, e))?;
            f.write_all(&self.buffers[p])
                .map_err(|e| io_error(&path, e))?;
            self.buffers[p] = Vec::new();
            self.on_disk[p] = true;
        }
        self.buffered = 0;
        Ok(())
    }

    fn take(&mut self, p: usize) -> Result<Vec<u8>> {
        let mut data = std::mem::take(&mut self.buffers[p]);
        if self.on_disk[p] {
            let path = self.part_path(p);
            let mut disk = fs::read(&path).map_err(|e| io_error(&path, e))?;
            fs::remove_file(&path).map_err(|e| io_error(&path, e))?;
            disk.extend_from_slice(&data);
            data = disk;
        }
        Ok(data)
    }
}

impl Drop for Batch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// A spilled operation: id, kind, sequence number, body.
type Spilled<'a> = ([u8; ID_LEN], u8, u64, &'a [u8]);

fn parse_spill(buf: &[u8]) -> Result<Vec<Spilled<'_>>> {
    let bad = || Error::OperationFailed("PIR: corrupt spill file".into());
    let mut out = Vec::new();
    let mut at = 0;
    while at < buf.len() {
        let head = buf.get(at..at + SPILL_HEADER).ok_or_else(bad)?;
        let id = head[..ID_LEN].try_into().expect("16 bytes");
        let kind = head[ID_LEN];
        let seq = u64::from_le_bytes(head[ID_LEN + 1..ID_LEN + 9].try_into().expect("8 bytes"));
        let len = u32::from_le_bytes(head[ID_LEN + 9..].try_into().expect("4 bytes")) as usize;
        at += SPILL_HEADER;
        let body = buf.get(at..at + len).ok_or_else(bad)?;
        at += len;
        out.push((id, kind, seq, body));
    }
    Ok(out)
}

/// A database opened for writing. Only one writer per directory at a
/// time (enforced with a lock file); servers may read concurrently and
/// see each commit as a new snapshot.
pub struct Database {
    dir: PathBuf,
    key: Box<dyn ServerKey>,
    manifest: Manifest,
    exec: Executor,
    batch: Option<Batch>,
    /// Holds the writer lock while open.
    _lock: File,
}

fn lock(dir: &Path) -> Result<File> {
    let path = dir.join(LOCK);
    let f = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&path)
        .map_err(|e| io_error(&path, e))?;
    f.try_lock().map_err(|_| {
        Error::InvalidState(format!(
            "{}: the PIR database is open for writing elsewhere",
            dir.display()
        ))
    })?;
    Ok(f)
}

impl Database {
    /// Create an empty database in `dir`, which must not exist or be empty,
    /// under the server key derived from `seed` (the long-term secret; keep
    /// it to open the database later). `metadata` is stored as is and given
    /// to clients. `threads` as in PSI (0 = rayon's global pool).
    pub fn create(
        dir: &Path,
        curve: Curve,
        seed: &[u8; 32],
        metadata: Vec<u8>,
        threads: usize,
    ) -> Result<Self> {
        Self::create_with(dir, curve, seed, metadata, Executor::new(threads)?)
    }

    pub(crate) fn create_with(
        dir: &Path,
        curve: Curve,
        seed: &[u8; 32],
        metadata: Vec<u8>,
        exec: Executor,
    ) -> Result<Self> {
        if metadata.len() > MAX_METADATA_LEN {
            return Err(Error::InvalidInput(format!(
                "PIR: metadata longer than {MAX_METADATA_LEN} bytes"
            )));
        }
        match fs::read_dir(dir) {
            Ok(mut entries) => {
                if entries.next().is_some() {
                    return Err(Error::InvalidInput(format!(
                        "{} is not empty",
                        dir.display()
                    )));
                }
            }
            Err(_) => fs::create_dir(dir).map_err(|e| io_error(dir, e))?,
        }
        let lock = lock(dir)?;
        let key = suite::server_key(curve, seed);
        let manifest = Manifest {
            curve,
            key_check: key.key_check(),
            generation: 0,
            next_segment: 0,
            records: 0,
            max_label_len: 0,
            metadata,
            segments: Vec::new(),
        };
        manifest.write(dir)?;
        Ok(Self {
            dir: dir.to_path_buf(),
            key,
            manifest,
            exec,
            batch: None,
            _lock: lock,
        })
    }

    /// Open an existing database for writing with the seed it was created
    /// with. Removes leftovers of interrupted writes.
    pub fn open(dir: &Path, seed: &[u8; 32], threads: usize) -> Result<Self> {
        Self::open_with(dir, seed, Executor::new(threads)?)
    }

    pub(crate) fn open_with(dir: &Path, seed: &[u8; 32], exec: Executor) -> Result<Self> {
        let lock = lock(dir)?;
        let manifest = Manifest::read(dir)?;
        let key = checked_key(dir, &manifest, seed)?;
        let db = Self {
            dir: dir.to_path_buf(),
            key,
            manifest,
            exec,
            batch: None,
            _lock: lock,
        };
        db.remove_orphans();
        Ok(db)
    }

    /// Remove work directories, temporary files and segments not in the
    /// manifest. Best effort: a segment still open by a server may not be
    /// removable on some platforms.
    fn remove_orphans(&self) {
        let Ok(entries) = fs::read_dir(&self.dir) else {
            return;
        };
        let live: Vec<PathBuf> = self
            .manifest
            .segments
            .iter()
            .map(|&n| segment_path(&self.dir, n))
            .collect();
        for e in entries.flatten() {
            let path = e.path();
            let name = e.file_name().to_string_lossy().into_owned();
            if name.starts_with("work-") {
                let _ = fs::remove_dir_all(&path);
            } else if name.ends_with(".tmp") || (name.starts_with("seg-") && !live.contains(&path))
            {
                let _ = fs::remove_file(&path);
            }
        }
    }

    /// Current state (committed operations only).
    pub fn info(&self) -> DbInfo {
        self.manifest.info()
    }

    /// Operations added since the last commit.
    pub fn pending(&self) -> u64 {
        self.batch.as_ref().map_or(0, |b| b.seq)
    }

    fn batch(&mut self) -> Result<&mut Batch> {
        if self.batch.is_none() {
            self.batch = Some(Batch::new(&self.dir)?);
        }
        Ok(self.batch.as_mut().expect("just set"))
    }

    /// Insert or replace records: `keys[i]` maps to `labels[i]`, labels of
    /// any length (the formats' 32-bit length fields cap a label at
    /// [`MAX_LABEL_LEN`], about 4 GiB). Takes effect on
    /// [`commit`](Self::commit).
    pub fn upsert(&mut self, keys: &[&[u8]], labels: &[&[u8]]) -> Result<()> {
        if keys.len() != labels.len() {
            return Err(Error::InvalidInput(
                "PIR: key and label counts differ".into(),
            ));
        }
        for (k, l) in keys.iter().zip(labels) {
            check_key(k)?;
            if l.len() > MAX_LABEL_LEN {
                return Err(Error::InvalidInput(format!(
                    "PIR: label of {} bytes exceeds the format limit {MAX_LABEL_LEN}",
                    l.len()
                )));
            }
        }
        let (curve, key) = (self.manifest.curve, &*self.key);
        let sealed: Vec<([u8; ID_LEN], Vec<u8>)> = self.exec.install(|| {
            keys.par_iter()
                .zip(labels.par_iter())
                .map(|(k, l)| {
                    let rk = key.record_key(k);
                    (rk.id, suite::seal(curve, &rk, l))
                })
                .collect()
        });
        let batch = self.batch()?;
        for (id, body) in &sealed {
            batch.push(id, KIND_RECORD, body);
            batch.max_label = batch.max_label.max(body.len() - LEN_PREFIX);
        }
        batch.flush(FLUSH_BYTES)
    }

    /// Delete records by key (missing keys are ignored). Takes effect on
    /// [`commit`](Self::commit).
    pub fn delete(&mut self, keys: &[&[u8]]) -> Result<()> {
        for k in keys {
            check_key(k)?;
        }
        let key = &*self.key;
        let ids: Vec<[u8; ID_LEN]> = self
            .exec
            .install(|| keys.par_iter().map(|k| key.record_key(k).id).collect());
        let batch = self.batch()?;
        for id in &ids {
            batch.push(id, KIND_TOMBSTONE, &[]);
        }
        batch.flush(FLUSH_BYTES)
    }

    /// Discard the operations added since the last commit.
    pub fn rollback(&mut self) {
        self.batch = None;
    }

    /// Write the pending operations as a new segment and publish it. No-op
    /// without pending operations.
    pub fn commit(&mut self) -> Result<DbInfo> {
        let Some(mut batch) = self.batch.take() else {
            return Ok(self.info());
        };
        let n = self.manifest.next_segment;
        let path = segment_path(&self.dir, n);
        let mut w = SegmentWriter::create(&path)?;
        for p in 0..PARTITIONS {
            let data = batch.take(p)?;
            if data.is_empty() {
                continue;
            }
            let mut ops = parse_spill(&data)?;
            // By id, the last operation on an id first.
            self.exec
                .install(|| ops.par_sort_unstable_by(|a, b| a.0.cmp(&b.0).then(b.2.cmp(&a.2))));
            let mut prev: Option<[u8; ID_LEN]> = None;
            for (id, kind, _, body) in ops {
                if prev != Some(id) {
                    w.push(&id, kind, body)?;
                    prev = Some(id);
                }
            }
        }
        let (live, dead) = w.finish()?;
        let mut m = self.manifest.clone();
        m.next_segment = n + 1;
        m.segments.push(n);
        m.generation += 1;
        m.records = (m.records + live).saturating_sub(dead);
        m.max_label_len = m.max_label_len.max(batch.max_label as u32);
        if let Err(e) = m.write(&self.dir) {
            let _ = fs::remove_file(&path);
            return Err(e);
        }
        self.manifest = m;
        Ok(self.info())
    }

    /// Merge all segments into one, dropping deleted and replaced records;
    /// makes `records` and `max_label_len` exact. Commits pending operations
    /// first.
    pub fn compact(&mut self) -> Result<DbInfo> {
        self.commit()?;
        if self.manifest.segments.len() <= 1
            && open_segments(&self.dir, &self.manifest)?
                .iter()
                .all(|s| s.tombstones == 0)
        {
            return Ok(self.info());
        }
        let old = self.manifest.segments.clone();
        let segments = open_segments(&self.dir, &self.manifest)?;
        let n = self.manifest.next_segment;
        let path = segment_path(&self.dir, n);
        let mut w = SegmentWriter::create(&path)?;
        let max_label = merge(&segments, |rec| w.push(&rec.id, KIND_RECORD, &rec.body))?;
        let (live, _) = w.finish()?;
        drop(segments);
        let mut m = self.manifest.clone();
        m.next_segment = n + 1;
        m.segments = vec![n];
        m.generation += 1;
        m.records = live;
        m.max_label_len = max_label as u32;
        if let Err(e) = m.write(&self.dir) {
            let _ = fs::remove_file(&path);
            return Err(e);
        }
        self.manifest = m;
        for s in old {
            let _ = fs::remove_file(segment_path(&self.dir, s));
        }
        Ok(self.info())
    }
}

/// K-way merge of `segments` (oldest first): calls `emit` with the newest
/// version of every live id in id order; returns the longest label.
fn merge(
    segments: &[Segment],
    mut emit: impl FnMut(&super::segment::Record) -> Result<()>,
) -> Result<usize> {
    let mut readers: Vec<SegmentReader> = segments
        .iter()
        .map(Segment::reader)
        .collect::<Result<_>>()?;
    let mut heads = Vec::with_capacity(readers.len());
    // Min-heap on (id, newest segment first).
    let mut heap = BinaryHeap::new();
    for (i, r) in readers.iter_mut().enumerate() {
        let rec = r.next_record()?;
        if let Some(rec) = &rec {
            heap.push(Reverse((rec.id, Reverse(i))));
        }
        heads.push(rec);
    }
    let mut max_label = 0;
    while let Some(Reverse((id, Reverse(i)))) = heap.pop() {
        let rec = heads[i].take().expect("head present");
        // Older versions of the same id.
        while let Some(&Reverse((other, Reverse(j)))) = heap.peek() {
            if other != id {
                break;
            }
            heap.pop();
            heads[j] = readers[j].next_record()?;
            if let Some(r) = &heads[j] {
                heap.push(Reverse((r.id, Reverse(j))));
            }
        }
        if rec.kind == KIND_RECORD {
            max_label = max_label.max(rec.body.len().saturating_sub(LEN_PREFIX));
            emit(&rec)?;
        }
        heads[i] = readers[i].next_record()?;
        if let Some(r) = &heads[i] {
            heap.push(Reverse((r.id, Reverse(i))));
        }
    }
    Ok(max_label)
}

impl Drop for Database {
    fn drop(&mut self) {
        if let Some(b) = &mut self.batch {
            for buf in &mut b.buffers {
                buf.zeroize();
            }
        }
    }
}

#[cfg(test)]
impl Database {
    /// Spill every write to disk.
    pub(crate) fn spill_always(&mut self) -> Result<()> {
        self.batch()?.flush(0)
    }
}
