# Cryptex

[中文](README.md) | English

A cross-platform cryptography library. The core is written in Rust and exposed to other languages through a C ABI. It currently provides private set intersection (PSI) and keyword private information retrieval (PIR), with maintained Python bindings.

The name comes from the cipher cylinder (cryptex) in *The Da Vinci Code*. Here it also reads as Crypto + Cortex: the hub of cryptographic computation, where all the cryptography happens while upper-layer services only handle scheduling and integration.

## Documentation

The detailed documents are currently written in Chinese.

| Document | Audience | Contents |
| --- | --- | --- |
| `README.en.md` (this file) | Everyone | Overview, supported algorithms, performance summary, quick start, build |
| [docs/operators.md](docs/operators.md) | Everyone | One-page overview of the operators: what is done, core references, representative performance |
| [bindings/python/README.md](bindings/python/README.md) | Python users | Parameters, data input, transport integration, bucketing, logging, concurrency, low-level API |
| [docs/algorithm/psi.md](docs/algorithm/psi.md) | Security reviewers, protocol implementers | ECDH-PSI and VOLE-PSI: design, message formats, parameters, performance; sessions, bucketing, references, security and interfaces shared by all three PSI protocols |
| [docs/algorithm/psi-oprf.md](docs/algorithm/psi-oprf.md) | Same | OPRF-PSI: design, suites, message formats, performance (including an unbalanced comparison of the three protocols) |
| [docs/algorithm/pir.md](docs/algorithm/pir.md) | Same | Keyword PIR: design, incremental storage, message formats, performance, leakage analysis |
| [docs/algorithm/](docs/algorithm/README.md) | Same | Index of algorithm documents and writing conventions |
| [docs/optimization.md](docs/optimization.md) | Contributors, performance tuners | Completed and planned optimizations (including the unbalanced setting) |

## Supported algorithms

| Algorithm | Implementation | Main references | Status |
| --- | --- | --- | --- |
| ECDH-PSI | Ristretto255 / P-256 / SM2 / FourQ, with concurrency and bucketing | Meadows (IEEE S&P 1986); RFC 9380, RFC 9496; GB/T 32918, GB/T 32905; FourQ (ASIACRYPT 2015) | Implemented |
| VOLE-PSI | Ferret silent OT + GF(2^128) VOLE + RB-OKVS; one setup shared by all buckets, full-duplex pipeline | Rindal–Schoppmann (Eurocrypt 2021), Raghuraman–Rindal (CCS 2022); Ferret (CCS 2020); RB-OKVS (USENIX Security 2023) | Implemented |
| OPRF-PSI (unbalanced) | 2HashDH OPRF over Ristretto255 / P-256 / SM2 / FourQ; the sender only sends sorted truncated values, and the receiver's group operations scale with its own set size only; no caching, fresh key per session | Jarecki–Kiayias–Krawczyk (ASIACRYPT 2014); RFC 9497 (Ristretto255 and P-256 pass the RFC test vectors) | Implemented; offline caching planned |
| Keyword PIR | A key → label database encrypted under a 2HashDH OPRF (long-term key), supporting append, update and delete with labels of any length; the client downloads ciphertexts by bucket and can only decrypt the keywords it queried; Ristretto255 / P-256 / SM2 (with SM3, SM4) / FourQ; leaks the queried buckets, and updates leak the XOR of old and new labels | Jarecki–Kiayias–Krawczyk (ASIACRYPT 2014); RFC 9497; NIST SP 800-38A; GB/T 32907 | Implemented |
| Crypto utilities | Hashing, AEAD, signatures | FIPS 180-4, FIPS 197, FIPS 186-5; GB/T 32905, GB/T 32907, GB/T 32918 | Planned |

All three PSI protocols are secure against semi-honest adversaries. By default only the receiver learns the intersection; ECDH-PSI and VOLE-PSI can optionally let the sender learn it as well ([result sharing](docs/algorithm/psi.md#结果共享)), OPRF-PSI cannot. Whether each component is based on a standard, a paper or a library-specific design, and how each is verified, is listed in [psi.md, "依据" (References)](docs/algorithm/psi.md#依据).

Choosing a protocol:

- Without a Chinese national cryptography (SM / guomi) requirement, use **VOLE-PSI** for both balanced and unbalanced sets: computation is more than an order of magnitude faster, and in the balanced case communication is about half that of ECDH-PSI. Even at 10 thousand vs. 10 million it is about 6× faster than OPRF-PSI.
- With an SM requirement and sets of similar size, use **ECDH-PSI + SM2**.
- With an SM requirement and very different set sizes (e.g. 10 thousand vs. 10 million), use **OPRF-PSI + SM2**, with the smaller set as the receiver. Under the same conditions it is about 1.8× faster than ECDH-PSI, and the sender's communication is about 1/3 of ECDH's.
- When NIST curves are required, use ECDH-PSI or OPRF-PSI with P-256.

## Performance summary

Apple M5 (10 cores), one process per party, 5 threads per party. Items are 11-digit numeric strings; half of them are in the intersection.

| Scenario | Time |
| --- | --- |
| VOLE-PSI, 1M × 1M, 100 Mbps | 6.4 s |
| VOLE-PSI, 10M × 10M, 100 Mbps, 1M per bucket | 44.1 s |
| VOLE-PSI, 100M × 100M, 100 Mbps, 1M per bucket, text file input | 444.2 s |
| ECDH-PSI (Ristretto255), 1M × 1M, 100 Mbps | 26.0 s |
| ECDH-PSI (Ristretto255), 10M × 10M, 100 Mbps | 280.7 s |
| ECDH-PSI (SM2), 10M × 10M, unthrottled, single process, 10 threads | 947.9 s |
| PIR (Ristretto255), 10M records, 300-byte labels: initial write / one incremental update (3.1%) / query 1,000 keywords (computation only, no network; 185 MiB downloaded) | 48.2 s / 0.99 s / 0.15 s |
| Unbalanced 10K × 10M, 100 Mbps, no bucketing: VOLE-PSI / OPRF-PSI (Ristretto255) / ECDH-PSI (Ristretto255) | 14.2 s / 83.7 s / 149.3 s |

Memory (VOLE-PSI, text file input): at 10M items with the default 1M per bucket, peak memory per party is about 0.6–0.7 GiB; with 100K per bucket, about 0.15–0.17 GiB. Memory for the unbalanced setting is in psi-oprf.md.

Test methodology, communication volume, memory and more sizes are in the "性能" (Performance) and "内存" (Memory) sections of [psi.md](docs/algorithm/psi.md) and the "性能" section of [psi-oprf.md](docs/algorithm/psi-oprf.md). This table is an excerpt; those two documents are authoritative.

## Quick start (Python)

```bash
cd core && cargo build --release
cd ../bindings/python && pip install -e .
```

```python
from cryptex import Protocol, Psi, Role, TcpChannel

# Receiver: listens on a port and learns the intersection
with TcpChannel.listen("0.0.0.0", 9000) as ch:
    with Psi(Protocol.VOLE, Role.RECEIVER, ch) as psi:          # bucketed by default, 1M per bucket
        count = psi.run("ids.csv", column="phone", output="result.txt")

# Sender: connects to the peer and learns nothing by default
with TcpChannel.connect("receiver-host", 9000, timeout=60) as ch:
    with Psi(Protocol.VOLE, Role.SENDER, ch) as psi:
        psi.run("ids.txt")
```

By default only the receiver learns the intersection. To let the sender learn it too, both parties pass `share_result=True`; the sender's `run` then also returns the intersection (and also accepts `output`). Enabling it on only one side fails during the handshake.

For the unbalanced setting (small set vs. large set), still use `Protocol.VOLE` with the smaller set as the receiver; when SM algorithms are required, switch to `Protocol.OPRF` and pass `curve=Curve.SM2`.

Keyword PIR: the server maintains a key → label database that supports insert, update and delete, and the client queries keywords in batches:

```python
from cryptex import PirClient, PirDatabase, PirServer
from cryptex.pir import generate_seed

seed = generate_seed()                                   # server's long-term secret, keep it safe
with PirDatabase.create("users.pir", seed) as db:        # offline write; upsert / delete / commit later
    db.load("users.csv", key_column="phone")

with PirServer("users.pir", seed) as server:             # server: once per connection
    server.serve(channel)

labels = PirClient(channel).query(["13800000001"])       # client: [b"..."] or [None]
```

`TcpChannel` is only a reference implementation. To plug in your own transport, and for the full parameter reference, see the [Python binding documentation](bindings/python/README.md).

## Build

Requirements: Rust (latest stable), Python 3.8+. The Go and Java bindings are not maintained at the moment.

```bash
cd core
cargo build --release
```

Artifacts are in `core/target/release/`:

| Platform | Shared library       | Static library    |
| -------- | -------------------- | ----------------- |
| Linux    | `libcryptex.so`      | `libcryptex.a`    |
| macOS    | `libcryptex.dylib`   | `libcryptex.a`    |
| Windows  | `cryptex.dll`        | `cryptex.lib`     |

Cross-compiling (ARM64 / AMD64):

```bash
rustup target add aarch64-unknown-linux-gnu x86_64-unknown-linux-gnu
cargo build --release --target aarch64-unknown-linux-gnu
cargo build --release --target x86_64-unknown-linux-gnu
```

Artifacts are in `core/target/<target>/release/`. All dependencies are pure Rust and need no C libraries; linking a Linux target requires a linker for that platform.

Python wheel (bundles the core library for the current platform; `CRYPTEX_LIB` points to a prebuilt library, `--plat-name` sets the platform tag):

```bash
cd bindings/python && python -m build --wheel
```

Tests:

```bash
cd core && cargo test
cd bindings/python && python3 -m unittest discover -s tests -v
```

## Security notes

- All three PSI protocols and PIR are secure against **semi-honest** adversaries only; they do not defend against an actively malicious peer.
- Protocol messages are neither encrypted nor authenticated; protect them with TLS or a similar transport layer.
- PSI cannot stop the receiver from enumerating a small value space (e.g. phone numbers); this has to be constrained at the business level.
- With `share_result` enabled (ECDH-PSI, VOLE-PSI), the sender's result is reported by the receiver and cannot be verified by the sender (semi-honest assumption).
- When bucketing, the temporary directory holds a plaintext copy of the input data.
- The SM2 hash-to-curve is a library-specific suite and only interoperates with this library.
- The FourQ curve arithmetic is written in-house rather than taken from an audited library, and its hash-to-curve suite and point handling are also custom. A security review and side-channel testing are recommended before production use.
- The VOLE-PSI Ferret parameters are taken from emp-ot and have not yet been checked against its source; they must be verified before production use.

- PIR reveals to the server which buckets the queried keywords fall into; each keyword hides among roughly `bucket_size` keys.
- PIR record encryption uses a fixed IV of 0: after a key is updated, a client that downloaded both the old and new versions, or anyone holding old segments or backup files, can obtain the XOR of the old and new labels. The only way to fully invalidate old data is to rebuild with a new seed.
- The PIR seed is the server's long-term secret; if it leaks, every label can be decrypted. A long-term key also means the platform must limit the number of queries (`max_keywords`).

For the full security analysis, see [psi.md, "安全性" (Security)](docs/algorithm/psi.md#安全性) and [pir.md, "安全性"](docs/algorithm/pir.md#安全性).

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this project by you shall be dual licensed as above, without any additional terms or conditions.
