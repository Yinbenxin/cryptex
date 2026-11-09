//! End-to-end tests: write a database, answer queries in memory.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use super::*;
use crate::Error;

/// A fresh path under the system temp dir, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        static N: AtomicU32 = AtomicU32::new(0);
        let p = std::env::temp_dir().join(format!(
            "cryptex-pir-test-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&p);
        Self(p)
    }

    fn files(&self) -> Vec<String> {
        let mut v: Vec<String> = fs::read_dir(&self.0)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        v.sort();
        v
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

const SEED: [u8; 32] = [7; 32];
const CURVES: [Curve; 4] = [Curve::Ristretto255, Curve::P256, Curve::Sm2, Curve::FourQ];

fn key(i: u64) -> Vec<u8> {
    format!("id-{i:08}").into_bytes()
}

fn label(i: u64) -> Vec<u8> {
    // Lengths 0..=40 so variable lengths are exercised.
    format!("label {i} ").repeat((i % 5) as usize).into_bytes()
}

fn upsert(db: &mut Database, range: std::ops::Range<u64>, f: impl Fn(u64) -> Vec<u8>) {
    let keys: Vec<Vec<u8>> = range.clone().map(key).collect();
    let labels: Vec<Vec<u8>> = range.map(f).collect();
    let k: Vec<&[u8]> = keys.iter().map(Vec::as_slice).collect();
    let l: Vec<&[u8]> = labels.iter().map(Vec::as_slice).collect();
    db.upsert(&k, &l).unwrap();
}

fn delete(db: &mut Database, ids: &[u64]) {
    let keys: Vec<Vec<u8>> = ids.iter().copied().map(key).collect();
    let k: Vec<&[u8]> = keys.iter().map(Vec::as_slice).collect();
    db.delete(&k).unwrap();
}

fn create(dir: &TempDir, curve: Curve, n: u64) -> Database {
    let mut db = Database::create(&dir.0, curve, &SEED, b"meta".to_vec(), 0).unwrap();
    upsert(&mut db, 0..n, label);
    db.commit().unwrap();
    db
}

struct Run {
    out: Vec<Option<Vec<u8>>>,
    keywords: usize,
    buckets: Vec<u32>,
    /// Bytes of each chunk message.
    chunks: Vec<usize>,
}

/// One query in memory against `server`.
fn query(server: &Server, keywords: &[Vec<u8>]) -> Run {
    let mut s = server.session().unwrap();
    let mut c = Client::new(s.params(), keywords.to_vec(), 0).unwrap();
    let eval = s.query(&c.query().unwrap(), 0).unwrap();
    let fetch = c.receive(&eval).unwrap().expect("fetch message");
    s.fetch(&fetch).unwrap();
    let mut chunks = Vec::new();
    while let Some(m) = s.next_chunk().unwrap() {
        assert!(!c.is_done(), "client finished before the server");
        assert!(c.receive(&m).unwrap().is_none());
        chunks.push(m.len());
    }
    assert!(c.is_done());
    let out = c
        .results()
        .unwrap()
        .into_iter()
        .map(|r| r.map(<[u8]>::to_vec))
        .collect();
    Run {
        out,
        keywords: s.keywords(),
        buckets: s.buckets().to_vec(),
        chunks,
    }
}

fn open(dir: &TempDir, bucket_size: u64) -> Server {
    Server::open(&dir.0, &SEED, bucket_size, Padding::Max, 0).unwrap()
}

#[test]
fn all_curves_round_trip() {
    for curve in CURVES {
        let dir = TempDir::new();
        let info = create(&dir, curve, 500).info();
        assert_eq!((info.records, info.segments, info.curve), (500, 1, curve));
        let longest = (0..500).map(|i| label(i).len()).max().unwrap();
        assert_eq!(info.max_label_len, longest as u32);
        let server = open(&dir, 16);
        let p = server.params();
        assert_eq!((p.log2_buckets, p.padded_len), (5, 4 + longest as u32));
        assert_eq!(p.metadata, b"meta");
        let kws = vec![
            key(3),
            b"nope".to_vec(),
            key(499),
            key(3),
            b"".to_vec(),
            key(0),
        ];
        let run = query(&server, &kws);
        assert_eq!(run.keywords, 5, "{curve:?}: duplicates are sent once");
        assert!(run.buckets.len() <= 5);
        assert_eq!(
            run.out,
            vec![
                Some(label(3)),
                None,
                Some(label(499)),
                Some(label(3)),
                None,
                Some(label(0))
            ],
            "{curve:?}"
        );
    }
}

#[test]
fn append_update_delete() {
    let dir = TempDir::new();
    let mut db = create(&dir, Curve::Sm2, 100);
    let server = open(&dir, 8);
    let gen0 = server.params().generation;

    // Append 100..150, update 10..20 to longer labels, delete 0..5 and a
    // key that does not exist.
    upsert(&mut db, 100..150, label);
    upsert(&mut db, 10..20, |i| {
        format!("updated {i} ").repeat(30).into_bytes()
    });
    delete(&mut db, &[0, 1, 2, 3, 4, 999]);
    assert_eq!(db.pending(), 66);
    let info = db.commit().unwrap();
    assert_eq!(info.segments, 2);

    // The open server keeps its snapshot until reload.
    let kws: Vec<Vec<u8>> = [0, 5, 10, 120].into_iter().map(key).collect();
    assert_eq!(
        query(&server, &kws).out,
        vec![Some(label(0)), Some(label(5)), Some(label(10)), None]
    );
    assert!(server.reload().unwrap());
    assert!(!server.reload().unwrap());
    assert!(server.params().generation > gen0);
    let updated = |i: u64| Some(format!("updated {i} ").repeat(30).into_bytes());
    assert_eq!(
        query(&server, &kws).out,
        vec![None, Some(label(5)), updated(10), Some(label(120))]
    );

    // Delete then re-insert within one batch: the last operation wins.
    delete(&mut db, &[7]);
    upsert(&mut db, 7..8, |_| b"back".to_vec());
    upsert(&mut db, 8..9, |_| b"gone".to_vec());
    delete(&mut db, &[8]);
    db.commit().unwrap();
    server.reload().unwrap();
    let r = query(&server, &[key(7), key(8)]).out;
    assert_eq!(r, vec![Some(b"back".to_vec()), None]);

    // Compaction keeps the same content and makes the counts exact.
    let info = db.compact().unwrap();
    assert_eq!(info.segments, 1);
    assert_eq!(info.records, 150 - 5 - 1);
    assert_eq!(info.max_label_len, updated(19).unwrap().len() as u32);
    server.reload().unwrap();
    let all: Vec<Vec<u8>> = (0..150).map(key).collect();
    let out = query(&server, &all).out;
    for (i, r) in out.into_iter().enumerate() {
        let i = i as u64;
        let want = match i {
            0..=4 | 8 => None,
            7 => Some(b"back".to_vec()),
            10..=19 => updated(i),
            _ => Some(label(i)),
        };
        assert_eq!(r, want, "key {i}");
    }
    // Old segments are gone; nothing but the manifest, lock and one segment.
    let files = dir.files();
    assert_eq!(files.len(), 3, "{files:?}");
    assert!(files.contains(&"MANIFEST".to_string()));
}

#[test]
fn large_batches_spill_to_disk() {
    let dir = TempDir::new();
    let mut db = Database::create(&dir.0, Curve::Ristretto255, &SEED, Vec::new(), 2).unwrap();
    for lo in (0..3000).step_by(500) {
        upsert(&mut db, lo..lo + 500, label);
        db.spill_always().unwrap();
    }
    db.commit().unwrap();
    let server = open(&dir, 7);
    // 3000 / 7 → 2^9 = 512 buckets.
    assert_eq!(server.params().log2_buckets, 9);
    let kws: Vec<Vec<u8>> = (0..3000).map(key).collect();
    let run = query(&server, &kws);
    // ~6 keys per bucket: almost every bucket is fetched.
    assert!(run.buckets.len() > 500 && run.buckets.len() <= 512);
    for (i, r) in run.out.iter().enumerate() {
        assert_eq!(r.as_deref(), Some(label(i as u64).as_slice()), "key {i}");
    }
}

#[test]
fn padding_modes() {
    let dir = TempDir::new();
    let mut db = Database::create(&dir.0, Curve::P256, &SEED, Vec::new(), 0).unwrap();
    db.upsert(&[b"a", b"b"], &[b"x", &[b'y'; 1000]]).unwrap();
    db.commit().unwrap();
    let size = |padding| {
        let server = Server::open(&dir.0, &SEED, 1 << 20, padding, 0).unwrap();
        let run = query(&server, &[b"a".to_vec()]);
        assert_eq!(run.out, vec![Some(b"x".to_vec())]);
        run.chunks.iter().sum::<usize>()
    };
    let header = 1 + 1 + 8 + 2 * (16 + 4);
    assert_eq!(size(Padding::Max), header + 2 * (4 + 1000));
    assert_eq!(size(Padding::None), header + (4 + 1) + (4 + 1000));
}

#[test]
fn large_reply_is_chunked() {
    let dir = TempDir::new();
    let mut db = Database::create(&dir.0, Curve::P256, &SEED, Vec::new(), 0).unwrap();
    upsert(&mut db, 0..1000, |i| vec![i as u8; 20_000]);
    db.commit().unwrap();
    let server = open(&dir, 1 << 20);
    let run = query(&server, &[key(10), key(999)]);
    assert_eq!(run.buckets, vec![0]);
    assert_eq!(
        run.out,
        vec![Some(vec![10; 20_000]), Some(vec![231; 20_000])]
    );
}

#[test]
fn empty_cases() {
    let dir = TempDir::new();
    let db = Database::create(&dir.0, Curve::Sm2, &SEED, Vec::new(), 0).unwrap();
    assert_eq!(db.info().records, 0);
    let server = open(&dir, 100);
    assert_eq!(query(&server, &[key(1)]).out, vec![None]);
    // No keywords: one empty last chunk.
    let run = query(&server, &[]);
    assert!(run.out.is_empty() && run.buckets.is_empty());
    assert_eq!(run.chunks.len(), 1);
}

#[test]
fn writer_lock_seed_and_orphans() {
    let dir = TempDir::new();
    let mut db = create(&dir, Curve::FourQ, 20);
    // One writer at a time; servers are fine.
    assert!(matches!(
        Database::open(&dir.0, &SEED, 0),
        Err(Error::InvalidState(_))
    ));
    open(&dir, 10);
    // Uncommitted work is dropped with the writer.
    upsert(&mut db, 20..30, label);
    db.spill_always().unwrap();
    drop(db);
    assert_eq!(dir.files().len(), 3);
    let mut db = Database::open(&dir.0, &SEED, 0).unwrap();
    assert_eq!(db.info().records, 20);
    upsert(&mut db, 20..30, label);
    db.rollback();
    assert_eq!(db.commit().unwrap().generation, 1);
    drop(db);

    assert!(Database::open(&dir.0, &[8; 32], 0).is_err());
    assert!(Server::open(&dir.0, &[8; 32], 10, Padding::Max, 0).is_err());
    // Creating over a non-empty directory is refused.
    assert!(Database::create(&dir.0, Curve::P256, &SEED, Vec::new(), 0).is_err());
    // A leftover segment not in the manifest is removed on open.
    fs::write(dir.0.join("seg-99999999.pir"), b"junk").unwrap();
    Database::open(&dir.0, &SEED, 0).unwrap();
    assert!(!dir.files().contains(&"seg-99999999.pir".to_string()));
}

#[test]
fn rejects_bad_writes() {
    let dir = TempDir::new();
    let mut db = Database::create(&dir.0, Curve::P256, &SEED, Vec::new(), 0).unwrap();
    assert!(db.upsert(&[b"k"], &[]).is_err());
    assert!(db.upsert(&[&[0u8; MAX_KEY_LEN + 1]], &[b""]).is_err());
    assert!(db.delete(&[&[0u8; MAX_KEY_LEN + 1]]).is_err());
    let other = TempDir::new();
    assert!(Database::create(
        &other.0,
        Curve::P256,
        &SEED,
        vec![0; MAX_METADATA_LEN + 1],
        0
    )
    .is_err());
    assert!(Server::open(&dir.0, &SEED, 0, Padding::Max, 0).is_err());
}

#[test]
fn corrupt_files_are_rejected() {
    let dir = TempDir::new();
    drop(create(&dir, Curve::P256, 50));
    let seg = dir
        .files()
        .into_iter()
        .find(|f| f.starts_with("seg-"))
        .unwrap();
    let seg = dir.0.join(seg);
    let good = fs::read(&seg).unwrap();
    for bad in [good[..good.len() - 1].to_vec(), [b"X", &good[1..]].concat()] {
        fs::write(&seg, &bad).unwrap();
        assert!(Server::open(&dir.0, &SEED, 10, Padding::Max, 0).is_err());
    }
    fs::write(&seg, &good).unwrap();
    let manifest = dir.0.join("MANIFEST");
    let m = fs::read(&manifest).unwrap();
    fs::write(&manifest, &m[..m.len() - 1]).unwrap();
    assert!(Server::open(&dir.0, &SEED, 10, Padding::Max, 0).is_err());
}

#[test]
fn server_checks_messages() {
    let dir = TempDir::new();
    drop(create(&dir, Curve::P256, 100));
    let server = open(&dir, 10);
    let start = || {
        let s = server.session().unwrap();
        let c = Client::new(s.params(), vec![key(1), key(2), key(3)], 0).unwrap();
        (s, c)
    };
    let (mut s, mut c) = start();
    let q = c.query().unwrap();
    assert!(s.query(&q, 2).is_err());
    let (mut s, _) = start();
    assert!(s.query(&q[..q.len() - 1], 0).is_err());
    let (mut s, _) = start();
    assert!(matches!(s.fetch(b"x"), Err(Error::InvalidState(_))));

    // A valid query, then hand-made fetch messages.
    let gen = server.params().generation;
    let fetch = |buckets: &[u32]| {
        let mut w = Writer::new(MSG_FETCH, 0);
        w.u64(gen as usize);
        w.u64(buckets.len());
        for &b in buckets {
            w.u32(b);
        }
        w.finish()
    };
    let total = server.params().buckets();
    for (bad, ok) in [
        (vec![2, 1], false),
        (vec![1, 1], false),
        (vec![total], false),
        (vec![0, 1, 2, 3], false), // more buckets than keywords
        (vec![0, 1, 2], true),
    ] {
        let (mut s, mut c) = start();
        s.query(&c.query().unwrap(), 0).unwrap();
        assert_eq!(s.fetch(&fetch(&bad)).is_ok(), ok, "{bad:?}");
    }
    // A query for an older snapshot is rejected after a reload.
    let (mut s, mut c) = start();
    let q = c.query().unwrap();
    let mut db = Database::open(&dir.0, &SEED, 0).unwrap();
    upsert(&mut db, 200..201, label);
    db.commit().unwrap();
    server.reload().unwrap();
    assert!(server.session().unwrap().query(&q, 0).is_err());
    // The pinned session still answers it.
    assert!(s.query(&q, 0).is_ok());
}

#[test]
fn client_checks_replies() {
    let dir = TempDir::new();
    drop(create(&dir, Curve::Ristretto255, 100));
    let server = open(&dir, 10);
    let mut c = Client::new(server.session().unwrap().params(), vec![key(1)], 0).unwrap();
    assert!(matches!(c.receive(b"x"), Err(Error::InvalidState(_))));
    assert!(c.results().is_err());
    c.query().unwrap();
    assert!(matches!(c.query(), Err(Error::InvalidState(_))));

    let mut s = server.session().unwrap();
    let mut c = Client::new(s.params(), vec![key(1), key(50)], 0).unwrap();
    let mut eval = s.query(&c.query().unwrap(), 0).unwrap();
    eval[8] ^= 1; // count
    assert!(c.receive(&eval).is_err());
    assert!(Client::new(b"\x31\x09", vec![], 0).is_err());
    assert!(Client::new(&[], vec![], 0).is_err());
}

/// Nothing in clear: not in the files, the query, or the reply.
#[test]
fn nothing_in_clear() {
    let dir = TempDir::new();
    let mut db = Database::create(&dir.0, Curve::Sm2, &SEED, Vec::new(), 0).unwrap();
    db.upsert(&[b"secret-keyword-1"], &[b"secret-label-1"])
        .unwrap();
    db.commit().unwrap();
    for f in dir.files() {
        if let Ok(bytes) = fs::read(dir.0.join(&f)) {
            assert!(!bytes.windows(14).any(|w| w == b"secret-label-1"), "{f}");
            assert!(!bytes.windows(16).any(|w| w == b"secret-keyword-1"), "{f}");
        }
    }
    let server = open(&dir, 10);
    let run = query(&server, &[b"secret-keyword-1".to_vec()]);
    assert_eq!(run.out, vec![Some(b"secret-label-1".to_vec())]);
}

/// The record format the user asked for: id = F(key)[0..16], body =
/// CTR_{F(key)[16..32]}(IV 0, ...). An update reuses the keystream.
#[test]
fn update_reuses_keystream() {
    let dir = TempDir::new();
    let mut db = Database::create(&dir.0, Curve::P256, &SEED, Vec::new(), 0).unwrap();
    db.upsert(&[b"k"], &[b"AAAA"]).unwrap();
    db.commit().unwrap();
    db.upsert(&[b"k"], &[b"ABCD"]).unwrap();
    db.commit().unwrap();
    let segs: Vec<Vec<u8>> = dir
        .files()
        .into_iter()
        .filter(|f| f.starts_with("seg-"))
        .map(|f| fs::read(dir.0.join(f)).unwrap())
        .collect();
    // Body = last 8 bytes of the data area (before the 12-byte index).
    let body = |s: &Vec<u8>| s[s.len() - 12 - 8..s.len() - 12].to_vec();
    let (a, b) = (body(&segs[0]), body(&segs[1]));
    let x: Vec<u8> = a.iter().zip(&b).map(|(p, q)| p ^ q).collect();
    assert_eq!(x, [0, 0, 0, 0, 0, b'A' ^ b'B', b'A' ^ b'C', b'A' ^ b'D']);
}

#[test]
fn params_round_trip() {
    let p = Params {
        curve: Curve::FourQ,
        log2_buckets: 17,
        records: 1 << 33,
        padded_len: 304,
        generation: 9,
        metadata: b"{\"columns\":[]}".to_vec(),
    };
    assert_eq!(Params::decode(&p.encode()).unwrap(), p);
    let mut bad = p.encode();
    bad[1] = 9; // version
    assert!(Params::decode(&bad).is_err());
    assert!(Params::decode(&p.encode()[..20]).is_err());
}

#[test]
fn bucket_count_is_power_of_two() {
    assert_eq!(log2_buckets(0, 10).unwrap(), 0);
    assert_eq!(log2_buckets(10, 10).unwrap(), 0);
    assert_eq!(log2_buckets(11, 10).unwrap(), 1);
    assert_eq!(log2_buckets(1000, 10).unwrap(), 7); // 1000/128 = 7.8
    assert_eq!(log2_buckets(u64::MAX, 1).unwrap(), MAX_LOG2_BUCKETS);
    assert!(log2_buckets(1, 0).is_err());
}

/// Timings. `cargo test --release pir_timing -- --ignored --nocapture`;
/// PIR_RECORDS (default 1e6), PIR_CURVE (ristretto255 | sm2 | both),
/// 300-byte labels, 1024 records per bucket.
#[test]
#[ignore]
fn pir_timing() {
    use std::time::Instant;
    let n: u64 = std::env::var("PIR_RECORDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1_000_000);
    let curves = match std::env::var("PIR_CURVE").as_deref() {
        Ok("sm2") => vec![Curve::Sm2],
        Ok("ristretto255") => vec![Curve::Ristretto255],
        _ => vec![Curve::Ristretto255, Curve::Sm2],
    };
    let phone = |i: u64| format!("{:011}", 13_000_000_000 + i).into_bytes();
    let add = |db: &mut Database, lo: u64, hi: u64, fill: u8| {
        let label = vec![fill; 300];
        for start in (lo..hi).step_by(100_000) {
            let keys: Vec<Vec<u8>> = (start..(start + 100_000).min(hi)).map(phone).collect();
            let k: Vec<&[u8]> = keys.iter().map(Vec::as_slice).collect();
            db.upsert(&k, &vec![&label[..]; k.len()]).unwrap();
        }
    };
    for curve in curves {
        let dir = TempDir::new();
        let mut db = Database::create(&dir.0, curve, &SEED, Vec::new(), 0).unwrap();
        let t = Instant::now();
        add(&mut db, 0, n, b'x');
        db.commit().unwrap();
        let build = t.elapsed();
        // Increment: 1% new, 1% updated, 0.1% deleted.
        let t = Instant::now();
        add(&mut db, n, n + n / 100, b'y');
        add(&mut db, 0, n / 100, b'z');
        let gone: Vec<Vec<u8>> = (n / 2..n / 2 + n / 1000).map(phone).collect();
        db.delete(&gone.iter().map(Vec::as_slice).collect::<Vec<_>>())
            .unwrap();
        db.commit().unwrap();
        let incr = t.elapsed();
        let server = Server::open(&dir.0, &SEED, 1024, Padding::Max, 0).unwrap();
        let q_before = {
            let kws: Vec<Vec<u8>> = (0..1000u64).map(|i| phone(i * (n / 1000))).collect();
            let t = Instant::now();
            let run = query(&server, &kws);
            (t.elapsed(), run.chunks.iter().sum::<usize>())
        };
        let t = Instant::now();
        let info = db.compact().unwrap();
        let compact = t.elapsed();
        server.reload().unwrap();
        for q in [1_000u64, 10_000] {
            let kws: Vec<Vec<u8>> = (0..q).map(|i| phone(i * (n / q))).collect();
            let t = Instant::now();
            let run = query(&server, &kws);
            let took = t.elapsed();
            assert!(run.out.iter().filter(|r| r.is_none()).count() <= (q / 1000) as usize + 1);
            println!(
                "{curve:?} n={n} records={} buckets={} build={build:.1?} incr(3.1%)={incr:.1?} compact={compact:.1?} \
                 | q=1000 two segments: {:.2?} down={:.1}MiB | q={q} buckets_hit={} down={:.1}MiB compute={took:.2?}",
                info.records,
                server.params().buckets(),
                q_before.0,
                q_before.1 as f64 / 1048576.0,
                run.buckets.len(),
                run.chunks.iter().sum::<usize>() as f64 / 1048576.0,
            );
        }
    }
}

/// No label size cap: an 8 MiB label next to small ones, both padding
/// modes. The reply is split inside the bucket, one large record per chunk.
#[test]
fn large_labels() {
    let dir = TempDir::new();
    let mut db = Database::create(&dir.0, Curve::Ristretto255, &SEED, Vec::new(), 0).unwrap();
    let big: Vec<u8> = (0..8 << 20).map(|i| (i % 251) as u8).collect();
    db.upsert(&[b"big", b"a", b"b"], &[&big, b"x", b"y"])
        .unwrap();
    db.commit().unwrap();
    assert_eq!(db.info().max_label_len, 8 << 20);
    for padding in [Padding::Max, Padding::None] {
        let server = Server::open(&dir.0, &SEED, 1 << 20, padding, 0).unwrap();
        let run = query(&server, &[b"a".to_vec(), b"big".to_vec()]);
        assert_eq!(run.out, vec![Some(b"x".to_vec()), Some(big.clone())]);
        // One bucket of 3 records; every message stays near CHUNK_BYTES
        // except those holding a single large record.
        assert_eq!(run.buckets, vec![0]);
        let is_big = |c: &usize| *c > 8 << 20;
        if padding == Padding::Max {
            // Every record is padded to 8 MiB: one per chunk.
            assert_eq!(run.chunks.len(), 3, "{padding:?}: {:?}", run.chunks);
            assert!(run.chunks.iter().all(is_big), "{:?}", run.chunks);
        } else {
            // The bucket is shuffled, so the two small records share a
            // chunk unless the big one lands between them: 2 or 3 chunks,
            // the big one alone, never two small chunks in a row.
            assert_eq!(run.chunks.iter().filter(|c| is_big(c)).count(), 1);
            assert!(
                matches!(run.chunks.len(), 2 | 3)
                    && run
                        .chunks
                        .windows(2)
                        .all(|w| is_big(&w[0]) || is_big(&w[1])),
                "{padding:?}: {:?}",
                run.chunks
            );
        }
    }
}
