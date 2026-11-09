# Cryptex

跨平台密码算法库。核心用 Rust 实现，通过 C ABI 提供给其他语言调用。目前提供隐私集合求交（PSI），维护 Python 绑定。

名字出自《达·芬奇密码》中的密码筒（cryptex）。本项目取 Crypto（密码学）+ Cortex（大脑皮层）之意，寓意密码计算的中枢：所有密码计算都在这里完成，上层服务只负责调度和接入。

## 文档导航

| 文档 | 写给谁 | 内容 |
| --- | --- | --- |
| `README.md`（本文） | 所有人 | 项目概况、支持的算法、性能摘要、快速开始、构建 |
| [docs/operators.md](docs/operators.md) | 所有人 | 一页纸的算子一览：已完成的算子、核心依据、代表性能 |
| [bindings/python/README.md](bindings/python/README.md) | Python 使用者 | 参数、数据输入、通信接入、分桶、日志、并发、底层接口 |
| [docs/algorithm/psi.md](docs/algorithm/psi.md) | 安全评审、协议实现者 | ECDH-PSI、VOLE-PSI 的原理、消息格式、参数、性能；三种 PSI 共用的会话、分桶、依据、安全性、接口 |
| [docs/algorithm/psi-oprf.md](docs/algorithm/psi-oprf.md) | 同上 | OPRF-PSI 的原理、套件、消息格式、性能（含三种协议的非平衡对比） |
| [docs/algorithm/pir.md](docs/algorithm/pir.md) | 同上 | 关键词 PIR（匿踪查询）的原理、增量存储、消息格式、性能、泄露分析 |
| [docs/algorithm/](docs/algorithm/README.md) | 同上 | 算法文档索引与写作约定 |
| [docs/optimization.md](docs/optimization.md) | 贡献者、性能调优者 | 已完成和待做的优化项（含非平衡场景） |

## 支持的算法

| 算法 | 实现 | 主要依据 | 状态 |
| --- | --- | --- | --- |
| ECDH-PSI | Ristretto255 / P-256 / SM2 / FourQ，支持并发、分桶 | Meadows（IEEE S&P 1986）；RFC 9380、RFC 9496；GB/T 32918、GB/T 32905；FourQ（ASIACRYPT 2015） | 已实现 |
| VOLE-PSI | Ferret 静默 OT + GF(2^128) VOLE + RB-OKVS，所有桶共用一次 setup、全双工流水线 | Rindal–Schoppmann（Eurocrypt 2021）、Raghuraman–Rindal（CCS 2022）；Ferret（CCS 2020）；RB-OKVS（USENIX Security 2023） | 已实现 |
| OPRF-PSI（非平衡） | 2HashDH OPRF，Ristretto255 / P-256 / SM2 / FourQ；发送方只发排好序的截断值，接收方的群运算只和自己的集合大小有关；不缓存，每次会话换新密钥 | Jarecki–Kiayias–Krawczyk（ASIACRYPT 2014）；RFC 9497（Ristretto255、P-256 通过 RFC 测试向量） | 已实现；离线缓存规划中 |
| 关键词 PIR（匿踪查询） | 2HashDH OPRF 加密“键 → 标签”库（长期密钥），支持追加、更新、删除，标签长度任意；客户端按桶下载密文、只能解密自己查的关键词；Ristretto255 / P-256 / SM2（配 SM3、SM4）/ FourQ；泄露所查的桶，更新泄露新旧标签的异或 | Jarecki–Kiayias–Krawczyk（ASIACRYPT 2014）；RFC 9497；NIST SP 800-38A；GB/T 32907 | 已实现 |
| 加密工具 | 哈希、AEAD、签名 | FIPS 180-4、FIPS 197、FIPS 186-5；GB/T 32905、GB/T 32907、GB/T 32918 | 规划中 |

三种 PSI 都是半诚实安全。默认只有接收方得到交集；ECDH-PSI 和 VOLE-PSI 可以选择让发送方也得到（[结果共享](docs/algorithm/psi.md#结果共享)），OPRF-PSI 不支持。每个组件依据的是标准、论文还是本库自定义，以及各自怎么验证，见 [psi.md「依据」](docs/algorithm/psi.md#依据)。

选型建议：

- 不要求国密时用 **VOLE-PSI**，平衡和非平衡场景都是：计算快一个数量级以上，平衡时通信量约为 ECDH-PSI 的一半；1 万对 1000 万时也比 OPRF-PSI 快约 6 倍。
- 要求国密、双方集合大小相近时用 **ECDH-PSI + SM2**。
- 要求国密、双方集合大小悬殊（例如 1 万对 1000 万）时用 **OPRF-PSI + SM2**，小集合方做接收方。同条件下比 ECDH-PSI 快约 1.8 倍，发送方的通信约为 ECDH 的 1/3。
- 要求使用 NIST 曲线时用 ECDH-PSI 或 OPRF-PSI + P-256。

## 性能摘要

Apple M5（10 核），双方各一个进程，每方 5 线程。数据为 11 位数字字符串，交集占一半。

| 场景 | 耗时 |
| --- | --- |
| VOLE-PSI，100 万 × 100 万，百兆网 | 6.4 s |
| VOLE-PSI，1000 万 × 1000 万，百兆网，每桶 100 万 | 44.1 s |
| VOLE-PSI，1 亿 × 1 亿，百兆网，每桶 100 万，文本文件输入 | 444.2 s |
| ECDH-PSI（Ristretto255），100 万 × 100 万，百兆网 | 26.0 s |
| ECDH-PSI（Ristretto255），1000 万 × 1000 万，百兆网 | 280.7 s |
| ECDH-PSI（SM2），1000 万 × 1000 万，不限速、同一进程、10 线程 | 947.9 s |
| PIR（Ristretto255），1000 万条、标签 300 字节：首次写入 / 一次增量（3.1%）/ 查 1000 个关键词（计算，不含网络；下载 185 MiB） | 48.2 s / 0.99 s / 0.15 s |
| 非平衡 1 万 × 1000 万，百兆网，不分桶：VOLE-PSI / OPRF-PSI（Ristretto255）/ ECDH-PSI（Ristretto255） | 14.2 s / 83.7 s / 149.3 s |

内存（VOLE-PSI，文本文件输入）：1000 万规模、默认每桶 100 万时，单方峰值约 0.6–0.7 GiB；每桶 10 万时约 0.15–0.17 GiB。非平衡场景的内存见 psi-oprf.md。

测试方法、通信量、内存和更多规模的数据见 [psi.md](docs/algorithm/psi.md) 的「性能」「内存」小节和 [psi-oprf.md](docs/algorithm/psi-oprf.md) 的「性能」小节。本表只是摘录，数字以这两篇为准。

## 快速开始（Python）

```bash
cd core && cargo build --release
cd ../bindings/python && pip install -e .
```

```python
from cryptex import Protocol, Psi, Role, TcpChannel

# 接收方：监听端口，得到交集
with TcpChannel.listen("0.0.0.0", 9000) as ch:
    with Psi(Protocol.VOLE, Role.RECEIVER, ch) as psi:          # 默认分桶，每桶 100 万
        count = psi.run("ids.csv", column="phone", output="result.txt")

# 发送方：连接对端，默认什么也得不到
with TcpChannel.connect("receiver-host", 9000, timeout=60) as ch:
    with Psi(Protocol.VOLE, Role.SENDER, ch) as psi:
        psi.run("ids.txt")
```

默认只有接收方得到交集。需要发送方也得到时，双方都传 `share_result=True`，发送方的 `run` 也会返回交集（同样支持 `output`）；只有一方开启会在握手时报错。

非平衡场景（小集合对大集合）同样用 `Protocol.VOLE`，小集合方做接收方；要求国密时换成 `Protocol.OPRF` 并传 `curve=Curve.SM2`。

匿踪查询（PIR）：服务端维护一个可增删改的“键 → 标签”库，客户端按关键词批量查询：

```python
from cryptex import PirClient, PirDatabase, PirServer
from cryptex.pir import generate_seed

seed = generate_seed()                                   # 服务端长期秘密，自行保管
with PirDatabase.create("users.pir", seed) as db:        # 离线写入，之后可 upsert / delete / commit
    db.load("users.csv", key_column="phone")

with PirServer("users.pir", seed) as server:             # 服务端：每个连接一次
    server.serve(channel)

labels = PirClient(channel).query(["13800000001"])       # 客户端：[b"..."] 或 [None]
```

`TcpChannel` 只是参考实现。接入平台自己的通信方式，以及全部参数说明，见 [Python 绑定文档](bindings/python/README.md)。

## 构建

环境要求：Rust（最新稳定版）、Python 3.8+。Go、Java 绑定暂未维护。

```bash
cd core
cargo build --release
```

产物位于 `core/target/release/`：

| 平台    | 动态库               | 静态库            |
| ------- | -------------------- | ----------------- |
| Linux   | `libcryptex.so`      | `libcryptex.a`    |
| macOS   | `libcryptex.dylib`   | `libcryptex.a`    |
| Windows | `cryptex.dll`        | `cryptex.lib`     |

交叉编译（ARM64 / AMD64）：

```bash
rustup target add aarch64-unknown-linux-gnu x86_64-unknown-linux-gnu
cargo build --release --target aarch64-unknown-linux-gnu
cargo build --release --target x86_64-unknown-linux-gnu
```

产物位于 `core/target/<target>/release/`。依赖都是纯 Rust，不需要 C 库。链接 Linux 目标时要有对应平台的链接器。

Python wheel（自动打包当前平台的核心库；`CRYPTEX_LIB` 指定已构建好的库，`--plat-name` 指定平台标签）：

```bash
cd bindings/python && python -m build --wheel
```

测试：

```bash
cd core && cargo test
cd bindings/python && python3 -m unittest discover -s tests -v
```

## 安全提示

- 三种 PSI 协议和 PIR 都是**半诚实**安全，不防对方主动作恶。
- 协议消息本身不加密、不认证，需要 TLS 等传输层保护。
- PSI 无法阻止接收方枚举取值空间很小的数据（比如手机号），需要在业务层面约束。
- 开启 `share_result` 时（ECDH-PSI、VOLE-PSI），发送方得到的结果由接收方报告，发送方无法验证（半诚实假设）。
- 分桶时临时目录里是输入数据的明文副本。
- SM2 的 hash-to-curve 是本库自定义的套件，只能和本库互通。
- FourQ 的曲线运算是本库自写的，没有使用经过审计的库，hash-to-curve 套件和对端点的处理方式也是自定义的。用于生产前建议做安全审查和侧信道测试。
- VOLE-PSI 的 Ferret 参数取自 emp-ot，尚未对照源码核对，用于生产前必须核对。

- PIR 会让服务端知道查询的关键词落在哪些桶，每个关键词藏在约 `bucket_size` 个键中间。
- PIR 记录加密的 IV 固定为 0：更新一个键之后，下载过新旧两版的客户端，或者拿到旧段、备份文件的人，都能得到新旧标签的异或。要彻底失效旧数据，只能换种子重建。
- PIR 的种子是服务端的长期秘密，泄露后所有标签都能被解密；长期密钥也意味着查询次数要由平台限制（`max_keywords`）。

完整的安全分析见 [psi.md「安全性」](docs/algorithm/psi.md#安全性) 和 [pir.md「安全性」](docs/algorithm/pir.md#安全性)。

## 许可证

可任选以下任一许可证使用：

- Apache License 2.0（[LICENSE-APACHE](LICENSE-APACHE)）
- MIT License（[LICENSE-MIT](LICENSE-MIT)）

除非另有明确声明，你有意提交给本项目的任何贡献，均按上述双许可证授权，不附加其他条款。
