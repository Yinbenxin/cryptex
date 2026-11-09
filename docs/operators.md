# Cryptex 算子一览

本文是简介：列出已完成的算子、核心依据和代表性的性能数字。原理、参数、完整数据和测试方法以 [algorithm/](algorithm/README.md) 下各篇为准，本文只摘录。

所有协议都是**半诚实**安全，核心为纯 Rust，通过 C ABI 提供给其他语言，目前维护 Python 绑定，支持 x86_64 和 aarch64。

## 对外算法

| 算法 | 用途 | 构造 | 曲线 / 密码套件 | 国密 | 详细文档 |
| --- | --- | --- | --- | --- | --- |
| ECDH-PSI | 隐私求交，双方规模相近 | 双方各盲化一次，比对截断哈希 | Ristretto255、P-256、SM2、FourQ | 支持（SM2 + SM3） | [psi.md](algorithm/psi.md) |
| VOLE-PSI | 隐私求交，大规模；非平衡场景同样适用 | Ferret 静默 OT → GF(2^128) VOLE → RB-OKVS 构造 OPRF | AES-128、SHA-256 | 不支持 | [psi.md](algorithm/psi.md) |
| OPRF-PSI | 隐私求交，非平衡（小集合对大集合） | 2HashDH OPRF，发送方发排好序的截断标签 | Ristretto255、P-256、SM2、FourQ | 支持（SM2 + SM3） | [psi-oprf.md](algorithm/psi-oprf.md) |
| 关键词 PIR | 匿踪查询：按关键词查“键 → 标签”库，服务端不知道查了什么 | 2HashDH OPRF 派生记录 id 和密钥，CTR 加密标签，按桶下发 | Ristretto255、P-256、FourQ 配 SHA-256 + AES-128；SM2 配 SM3 + SM4 | 支持（SM2 + SM3 + SM4） | [pir.md](algorithm/pir.md) |

共同能力：

- **并发**：每个会话可以使用独立线程池。
- **分桶**：流式落盘，内存只和单个桶的大小有关。
- **结果共享**：ECDH-PSI、VOLE-PSI 可选让发送方也得到交集。
- **通信可替换**：通信由调用方接入，`TcpChannel` 只是参考实现。
- **PIR 数据库**：支持追加、更新、删除和合并。

尚未实现：加密工具（哈希、AEAD、签名），规划中。

## 底层算子

| 类别 | 算子 | 实现 | 依据 | 验证 |
| --- | --- | --- | --- | --- |
| 椭圆曲线 | Ristretto255 | curve25519-dalek | RFC 9496 | crate 自带测试 |
| | P-256 | RustCrypto `p256` | FIPS 186-5、SEC 1 | crate 自带测试 |
| | SM2 | RustCrypto `sm2` | GB/T 32918-2016 | crate 自带测试 |
| | FourQ | **自写** | Costello、Longa（ASIACRYPT 2015），常数取自 FourQlib | 独立 Python 实现的向量 |
| hash-to-curve | P-256 `P256_XMD:SHA-256_SSWU_RO_` | RustCrypto `hash2curve` | RFC 9380 | RFC 9380 附录 J 向量 |
| | Ristretto255 | expand_message_xmd + one-way map | RFC 9380、RFC 9496 | 确定性、域分离测试 |
| | SM2 `SM2_XMD:SM3_SSWU_RO_` | **自定义套件**，Simplified SWU | 方法按 RFC 9380 | 独立 Python 实现的向量 |
| | FourQ `FourQ_XMD:SHA-256_ELL2_RO_` | **自定义套件**，Elligator 2 | 方法按 RFC 9380 | 独立 Python 实现的向量 |
| OPRF | 2HashDH | 盲化、求值、去盲，整批共用一个 blind | Jarecki、Kiayias、Krawczyk（ASIACRYPT 2014）；RFC 9497 | RFC 9497 附录 A 向量（Ristretto255、P-256） |
| 哈希 | SHA-256、SHA-512 | RustCrypto `sha2` | FIPS 180-4 | 标准向量 |
| | SM3 | RustCrypto `sm3` | GB/T 32905-2016 | 标准向量 |
| 分组密码 | AES-128 / AES-128-CTR | RustCrypto `aes`、`ctr` | FIPS 197、NIST SP 800-38A | 标准向量 |
| | SM4 / SM4-CTR | RustCrypto `sm4` | GB/T 32907-2016 | 标准向量 |
| 有限域 | GF(2^128) 乘法 | RustCrypto `polyval` | RFC 8452 | 与朴素实现对比 |
| OT | 基础 OT | Chou–Orlandi，Ristretto255 | Chou、Orlandi（Latincrypt 2015） | 单元测试 |
| | OT 扩展 | IKNP，宽度 128 | Ishai 等（Crypto 2003） | COT 关系测试 |
| | 静默 OT | Ferret：GGM 树 + 正则噪声 LPN + 自举，分块生成 | Yang 等（ACM CCS 2020） | COT 关系、固定种子已知答案测试 |
| VOLE | COT → GF(2^128) VOLE | 每 128 个 COT 合成一个元素 | 双线性推导 | 恒等式测试 |
| OKVS | 二进制随机带状 OKVS | 带宽 128，ε = 0.1 | Bienstock 等（USENIX Security 2023） | 编解码测试；20,550 次编码实测无失败 |
| 标量求逆 | 常量时间求逆 | 各曲线 crate；FourQ 用 `crypto-bigint` safegcd | Bernstein、Yang（TCHES 2019） | $k \cdot k^{-1} \equiv 1$ 测试 |
| 随机数 | CSPRNG | ChaCha20，由操作系统播种 | RFC 8439 | — |

依据中标为“自写”“自定义”的部分只能和本库互通，用于生产前建议做安全审查。VOLE-PSI 的 Ferret 参数取自 emp-ot，用于生产前需要对照源码核对。完整的依据表见 [psi.md「依据」](algorithm/psi.md#依据) 和 [pir.md「依据」](algorithm/pir.md#依据)。

## 性能

### PSI 性能

**测试条件**：Apple M5（10 核）；双方各一个进程，本机 TCP，每方 5 线程，每个方向限速 100 Mbps；数据为 11 位数字字符串。

**平衡场景（双方规模相同）**

| 规模 | 协议 | **耗时** | 通信（R→S / S→R） |
| --- | --- | --- | --- |
| 100 万 × 100 万 | VOLE-PSI | **6.4 s** | 17.5 / 17.9 MiB |
| 100 万 × 100 万 | ECDH-PSI（Ristretto255） | **26.0 s** | 30.5 / 40.1 MiB |
| 1000 万 × 1000 万（每桶 100 万） | VOLE-PSI | **44.1 s** | 169 / 181 MiB |
| 1000 万 × 1000 万 | ECDH-PSI（Ristretto255） | **280.7 s** | 305 / 410 MiB |
| 1 亿 × 1 亿（每桶 100 万，文本文件） | VOLE-PSI | **444.2 s** | 1.64 / 1.76 GiB |

**非平衡场景（1 万 × 1000 万，不分桶）**

| 协议 | **耗时** | 通信（R→S / S→R） |
| --- | --- | --- |
| VOLE-PSI | **14.2 s** | 0.9 / 96.3 MiB |
| OPRF-PSI（Ristretto255） | **83.7 s** | 0.3 / 95.7 MiB |
| ECDH-PSI（Ristretto255） | **149.3 s** | 0.3 / 305.3 MiB |

- **国密**：SM2 的标量乘约为 Ristretto255 的 4.5 倍。ECDH-PSI + SM2 在 1000 万 × 1000 万、同一进程、10 线程、不限速时耗时 **947.9 s**。
- **内存**：VOLE-PSI 1000 万规模，每桶 100 万时单方峰值 **0.56–0.74 GiB**，每桶 10 万时 **0.15–0.17 GiB**。

**ARM 云服务器（Neoverse-N1，4 核）**：aarch64 Ubuntu 20.04，每方 2 线程，双方在同一台机器上，本机 TCP，限速 100 Mbps。用于参考低配机器上的表现，尚未写入算法文档。

| 场景 | 协议 | **耗时** |
| --- | --- | --- |
| 100 万 × 100 万 | VOLE-PSI | **21.2 s** |
| 100 万 × 100 万 | ECDH-PSI（Ristretto255） | **251.5 s** |
| 非平衡 1 万 × 1000 万 | VOLE-PSI | **27.1 s** |
| 非平衡 1 万 × 1000 万 | OPRF-PSI（Ristretto255） | **869.4 s** |
| 非平衡 1 万 × 1000 万 | ECDH-PSI（Ristretto255） | **1679.4 s** |

两台机器上的通信量逐字节一致。CPU 较弱时，基于椭圆曲线的协议慢得多，VOLE-PSI 的优势更明显。

### PIR 性能

**测试条件**：Apple M5（10 核）；同一进程内收发，不含网络；标签 300 字节，`bucket_size` 1024，补齐到最长标签。“增量”指一次提交：新增 1%、更新 1%、删除 0.1%。

**数据库维护（服务端离线）**

| 曲线 | 记录数 | **首次写入** | **增量（3.1%）** | **合并** |
| --- | --- | --- | --- | --- |
| Ristretto255 | 100 万 | **4.6 s** | **0.11 s** | **0.12 s** |
| SM2 | 100 万 | **20.2 s** | **0.43 s** | **0.13 s** |
| Ristretto255 | 1000 万 | **48.2 s** | **0.99 s** | **2.6 s** |

**查询（在线）**

| 曲线 | 记录数 | 查询关键词数 | 命中桶 | **下载（S→C）** | **双方计算** |
| --- | --- | --- | --- | --- | --- |
| Ristretto255 | 100 万 | 1000 | 651 / 1024 | **198.2 MiB** | **83 ms** |
| Ristretto255 | 100 万 | 1 万 | 1024 / 1024 | **311.8 MiB** | **242 ms** |
| SM2 | 100 万 | 1000 | 631 / 1024 | **192.1 MiB** | **119 ms** |
| SM2 | 100 万 | 1 万 | 1023 / 1024 | **311.5 MiB** | **612 ms** |
| Ristretto255 | 1000 万 | 1000 | 970 / 16384 | **184.8 MiB** | **152 ms** |
| Ristretto255 | 1000 万 | 1 万 | 7470 / 16384 | **1423.4 MiB** | **1.12 s** |

- **在线耗时主要花在下载上**：百兆网下 185 MiB 约 15 s（估算，未实测网络）。
- **资源**：1000 万条时进程峰值内存 **0.70 GiB**，合并后数据库占 **3.06 GiB**。

## 选型

| 需求 | 推荐 |
| --- | --- |
| 不要求国密，规模相近或悬殊都适用 | VOLE-PSI（小集合方做接收方） |
| 要求国密，规模相近 | ECDH-PSI + SM2 |
| 要求国密，规模悬殊 | OPRF-PSI + SM2 |
| 要求 NIST 曲线 | ECDH-PSI 或 OPRF-PSI + P-256 |
| 按关键词查询，服务端不知道查了什么 | 关键词 PIR |
