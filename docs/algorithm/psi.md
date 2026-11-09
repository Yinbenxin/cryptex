# PSI：隐私集合求交

> 状态：**ECDH-PSI、VOLE-PSI、OPRF-PSI 均已实现**，都支持并发和分桶。ECDH-PSI 和 OPRF-PSI 支持 Ristretto255、P-256、SM2、FourQ 四条曲线；VOLE-PSI 基于静默 OT（Ferret），所有桶共用一次 setup 并流水线执行，不支持国密。ECDH-PSI 和 VOLE-PSI 可以选择让发送方也得到结果，OPRF-PSI 不支持。
>
> 本文写 ECDH-PSI、VOLE-PSI 的协议细节，以及三种协议共用的部分（会话、输入处理、并发与分桶、依据、安全性、接口）。OPRF-PSI 的协议细节和性能见 [psi-oprf.md](psi-oprf.md)。

## 概述

两方各持有一个集合，接收方持有 $X$，发送方持有 $Y$。协议结束后：

- **接收方**得到 $X \cap Y$，以自己数据中的元素表示。
- **发送方**默认什么也得不到。ECDH-PSI、VOLE-PSI 开启**结果共享**（`share_result`）时，接收方在最后把匹配位置发给发送方，发送方也得到 $X \cap Y$，以自己数据中的元素表示（见下文「结果共享」）。

双方都会知道对方集合的**大小**。

典型场景：两家机构对齐共同用户、黑名单匹配、广告转化归因。

本库提供三种协议，都在**半诚实**模型下安全。$n$ 为接收方集合大小，$m$ 为发送方集合大小：

| | ECDH-PSI | VOLE-PSI | OPRF-PSI |
| --- | --- | --- | --- |
| 状态 | 已实现 | 已实现 | 已实现（不缓存） |
| 计算 | 双方各约 $n + m$ 次标量乘，较慢 | 以 AES 和哈希为主，比 ECDH 快一个数量级以上 | 接收方 $2n$ 次、发送方 $n + m$ 次标量乘 |
| 通信（$n = m$） | 每个元素约 74 字节 | 每个元素约 37 字节（两个方向大致各一半），另有约 1 MB 固定开销 | 每个元素约两个点加 $t$ 字节 |
| 发送方每个元素的通信 | 一个点（32/33 字节）加 $t$ 字节 | $t$ 字节 | $t$ 字节 |
| 消息 | 2 条，严格交替（结果共享时 3 条） | 一个任务覆盖所有桶，全双工流水线 | 2 条，严格交替 |
| 国密 | 支持（SM2 + SM3） | 不支持，见下文 | 支持（SM2 + SM3） |
| 结果共享 | 支持 | 支持 | 不支持 |
| 适用 | 要求国密，或要求使用 NIST 曲线 | 不要求国密时的默认选择，平衡和非平衡场景都适用 | 要求国密且双方集合大小悬殊；也是将来离线缓存模式的基础（规划中） |

非平衡场景（1 万 × 1000 万，百兆网）的实测对比：VOLE 14.2 s，OPRF 83.7 s，ECDH 149.3 s。条件和通信量、内存见 [psi-oprf.md「性能」](psi-oprf.md#性能)。

三种协议的消息格式都是本库自定义的，不能和其他 PSI 实现直接互通。OPRF-PSI 里的 OPRF 计算与 RFC 9497 一致，但外层消息仍是自定义的。

## 角色与会话

- 接收方是**发起方**：第一步不需要输入消息。
- 发送方从接收方的第一条消息开始。
- 库内不做网络 IO。消息由调用方通过自定义通道传递，见 [`bindings/python/README.md`](../../bindings/python/README.md)。

协议消息开始之前，Python 绑定的 `Psi` 默认会先交换一个会话头（`handshake=True`），整数均为大端，格式如下：

| 字段 | 长度 | 说明 |
| --- | --- | --- |
| magic | 4 | `CPSI` |
| version | 1 | 会话头版本，当前为 4 |
| protocol | 1 | 0 = ECDH，1 = VOLE，2 = OPRF |
| role | 1 | 0 = 发送方，1 = 接收方 |
| curve | 1 | 0 = Ristretto255，1 = P-256，2 = SM2，3 = FourQ |
| bucket_hash | 1 | 0 = SHA-256，1 = SM3 |
| share | 1 | 1 = 接收方把结果共享给发送方 |
| bucket_size | 4 | 每桶目标元素数；0 = 不分桶 |
| n | 8 | 本方元素个数（读文件时为估计值） |

以下情况会在进入密码学流程之前报错：双方角色相同、协议不一致、曲线不一致（ECDH、OPRF 检查，VOLE 不用曲线）、结果共享设置不一致、只有一方开启分桶、分桶时哈希不一致、版本不同。

### 结果共享

ECDH-PSI 和 VOLE-PSI 都可以选择让发送方也得到结果，双方必须设置一致。做法相同：

1. 发送方打乱自己的输出时记下置换 $\pi$（第 $k$ 个输出来自第 $\pi(k)$ 个元素）。
2. 接收方求交时，同时记下每个匹配在发送方输出中的位置 $k$，排好序后发给发送方。
3. 发送方用 $\pi$ 把位置映射回自己的元素下标。

位置按升序发送，不暴露接收方元素的顺序。共享设置也写进了协议的第一条消息，发送方发现与自己的设置不一致时直接报错，不依赖会话头。

OPRF-PSI 不支持结果共享：在 Python 里创建 `Psi` 时就会拒绝 `share_result=True`，C ABI 的 `cryptex_psi_new` 也会拒绝 `share = 1`。

这一步是**半诚实**的：发送方相信接收方如实报告。恶意的接收方可以少报或多报（多报的位置只能落在发送方自己的元素上）。需要防止这一点时，应由业务层校验，或使用对称的协议（目前不在规划内）。

代价很小：多一条消息，每个交集元素 4 字节（发送方元素数 ≥ $2^{32}$ 时为 8 字节）。100 万 × 100 万、交集 50 万时多约 1.9 MiB，耗时基本不变（见下文性能小节）。

## 输入处理

以下处理在 Python 绑定的 `Psi.run` 里完成，核心库收到的是处理好的字节串列表：

- 每个元素按 UTF-8 编码成字节串，按字节比较。大小写、全角半角不会自动统一，双方需要用同样的规则清洗数据。
- 文件输入会去掉首尾空白，跳过空值。
- 去重，保留第一次出现的元素。

去重是必须的：VOLE-PSI 中的 OKVS 不允许键重复。ECDH-PSI 和 OPRF-PSI 中，接收方的一批元素用同一个标量盲化，重复元素会让发送方看到相同的点，从而泄露“接收方有重复元素”这一信息。分桶时，去重在每个桶内进行；同一个元素一定落在同一个桶，所以效果和整体去重相同。

## 并发与分桶

三种协议通用。

### 并发

- 每个会话在一个线程池上计算：可以用共享的全局线程池（每个 CPU 一个线程），也可以用独立的 $n$ 线程池（`core/src/exec.rs`）。批量的哈希、标量乘、OT 扩展、OKVS 解码都会并行处理。
- 多个会话可以在不同线程里同时运行。同一个会话不能被多个线程同时调用。
- 协议代码只在调用方的线程上阻塞等待，不会在线程池的工作线程里等待，所以 `threads=1` 时也不会死锁。
- VOLE-PSI 的 Python 驱动另外用一个后台线程接收消息，主线程负责计算和发送，所以通道必须允许 `send` 和 `recv` 同时进行。

### 分桶

Python 绑定默认分桶，每桶约 100 万个元素（`bucket_size=1_000_000`）。双方按同一个公开规则把集合分成 $B$ 个桶，同号的桶之间做 PSI：

$$
\mathrm{bucket}(x) = \mathrm{u64}_{\mathrm{be}}\big(\mathrm{Hash}(\texttt{"CRYPTEX-PSI-BUCKET-V1"} \,\|\, x)[0..8]\big) \bmod B
$$

- Hash 为 SHA-256 或 SM3（`BucketHash`），双方必须一致。
- $B = \lceil \max(n, m) / \min(s_R, s_S) \rceil$，其中 $s_R, s_S$ 是双方各自的 `bucket_size`。$B$ 由双方根据握手交换的信息各自算出，结果相同，所以分桶必须开启握手。
- 同一个元素在双方一定落在同一个桶，所以分桶不会漏掉交集。
- $B = 1$ 时直接在内存里处理，不写临时文件。
- $B > 1$ 时，核心库（`algorithms/psi/store.rs`）边读输入边把元素写进 `work_dir` 下各桶的临时文件，每次只把一个桶读进内存，处理完立即删除该桶的文件。桶内去重也在这里完成。接收方用每个元素 1 bit 的位图记录哪些元素命中，最后重新读一遍输入，按原顺序流式写出交集。UTF-8 文本文件由核心库直接读取；其他输入由 Python 绑定逐条读出、成批交给核心库。
- 桶文件的记录格式为“输入位置（u64 小端）‖ 长度（u32 小端）‖ 元素”，每条额外 12 字节。
- ECDH-PSI 和 OPRF-PSI 按桶号依次运行独立的会话，每个桶换新密钥。VOLE-PSI 把所有桶放进一个任务，只做一次 setup，各桶流水线执行（见下文）。
- 规则实现在 `algorithms/psi/bucket.rs`，有固定值测试，并用独立的 Python 实现交叉验证过。

分桶的额外泄露见下文“安全性”。

---

## ECDH-PSI

### 原理

基于判定性 Diffie-Hellman（DDH）假设。设 $G$ 为素数阶群，$H: \{0,1\}^* \to G$ 为哈希到群的函数。因为标量乘满足交换律：

$$
(H(x)^a)^b = (H(x)^b)^a = H(x)^{ab}
$$

双方各自用私钥做一次“盲化”，交换后再做一次，两边就得到同一个值。对方的私钥未知，所以单次盲化后的点不泄露原始元素。

### 流程

接收方持有 $X = \{x_1, \dots, x_n\}$，私钥 $a$；发送方持有 $Y = \{y_1, \dots, y_m\}$，私钥 $b$。$a, b$ 每次会话随机生成，是非零的均匀随机标量，用完清零。

```
接收方 R                                         发送方 S
───────────────────────────────────────────────────────────────────
a ← 随机标量                                       b ← 随机标量
u_i = H(x_i)^a                                     w_j = H(y_j)^b（打乱顺序，创建时即开始计算）
                    ── 消息 1：[u_1, …, u_n] ──▶
                                                   v_i = u_i^b            （保持顺序）
                    ◀── 消息 2：[T(v_i)], [w_j] ──
t_j = T(w_j^a)
x_i ∈ 交集  ⟺  T(v_i) ∈ {t_j}
                    ── 消息 3：匹配的 j（升序） ──▶     （仅结果共享时）
                                                   用打乱时的置换映射回自己的下标
```

- **$v_i$ 保持顺序**：接收方据此把匹配结果对应回自己的第 $i$ 个元素。
- **$w_j$ 必须打乱**：否则接收方能知道交集元素在发送方集合中的位置。
- **$T$ 是截断哈希**：$v_i$ 不需要再参与群运算，所以只发它的哈希前缀，可以节省通信；$w_j$ 还要被接收方乘以 $a$，必须发完整的点。
- **发送方预计算**：$w_j$ 不依赖消息 1，所以发送方一创建就在后台开始计算，和接收方的第一步、消息 1 的传输同时进行。实测（双方各一个进程、每方 5 线程、百兆网、Ristretto255）：100 万 × 100 万从约 30.3 s 降到 26.3 s（另一次测量为 26.0 s，见下文 VOLE-PSI 的性能表），1000 万 × 1000 万从 314.6 s 降到 280.7 s，约省 11–13%。对照组是“收到消息 1 后才开始计算 $w_j$”。

$T(p) = \mathrm{Hash}(\texttt{"CRYPTEX-ECDH-PSI-V1-T"} \,\|\, \mathrm{enc}(p))$ 的前 $t$ 字节，Hash 为套件对应的哈希（Ristretto255、P-256、FourQ 用 SHA-256，SM2 用 SM3）。

截断长度 $t$ 取 $\lambda + \log_2 n + \log_2 m + \log_2 B$ 位，向上取整到字节，最多 32 字节。$B$ 是分桶数（不分桶时为 1）。这样整个任务中误判（不在交集的元素被判为在交集）的概率不超过 $2^{-\lambda}$。统计安全参数 $\lambda = 40$。接收方会校验 $t$ 是否和自己算出的一致，不一致时直接报错。双方桶数不一致通常会导致 $t$ 不同，但最可靠的检查是握手，分桶时必须开启握手。

### 消息格式

整数均为 u64 大端，点用各曲线的压缩编码：

| 消息 | 格式 |
| --- | --- |
| 消息 1 | `0x01 ‖ share (u8) ‖ n ‖ u_1 … u_n` |
| 消息 2 | `0x02 ‖ t (u8) ‖ n ‖ T(v_1) … T(v_n) ‖ m ‖ w_1 … w_m` |
| 消息 3（仅结果共享） | `0x03 ‖ k ‖ p_1 … p_k`：$w$ 中匹配的位置，严格升序，每个 u32（$m \ge 2^{32}$ 时为 u64） |

收到的消息会严格校验：标签、长度、数量溢出、末尾多余字节、点是否在曲线上、点是否为单位元、共享标志是否与本方一致、位置是否越界或不升序。任何一项不通过都返回 `ERR_INVALID_INPUT`，会话随即不可再用。

### Hash-to-curve

$H$ 必须是真正的哈希到群，**不能**用 $H(x) = h(x) \cdot G$（$G$ 是生成元）：那样所有点和 $G$ 的离散对数都是已知的 $h(x)$，对方可以直接剥掉盲化，协议就不安全了。

| 曲线 | 套件 ID | 方法 | 点长度 |
| --- | --- | --- | --- |
| Ristretto255 | `ristretto255_XMD:SHA-512_R255MAP_RO_` | `expand_message_xmd`（SHA-512）生成 64 字节，再用 RFC 9496 的 one-way map | 32 |
| P-256 | `P256_XMD:SHA-256_SSWU_RO_` | RFC 9380 标准套件 | 33 |
| SM2 | `SM2_XMD:SM3_SSWU_RO_` | 本库自定义，见下文 | 33 |
| FourQ | `FourQ_XMD:SHA-256_ELL2_RO_` | 本库自定义，见下文 | 32 |

DST 为 `"CRYPTEX-ECDH-PSI-V1-" ‖ 套件 ID`。

#### SM2 自定义套件

SM2 没有标准化的 hash-to-curve 套件。本库按 RFC 9380 的方法构造了 `SM2_XMD:SM3_SSWU_RO_`，结构和 `P256_XMD:SHA-256_SSWU_RO_` 完全相同：

| 参数 | 取值 |
| --- | --- |
| `expand_message` | `expand_message_xmd`，哈希为 SM3 |
| 安全级别 $k$ | 128 |
| $L$ | 48 |
| 映射 | Simplified SWU，直接作用于 SM2 曲线（$A = -3$，$B \ne 0$，不需要同源） |
| $Z$ | $-9$，按 RFC 9380 附录 H.2 的规则选出 |
| 余因子 $h$ | 1，不需要清除余因子 |

验证方式：

- SSWU 是通用实现，先用 RFC 9380 附录 J.1.1 的 P-256 测试向量验证，逐项（$u_0, u_1, Q_0, Q_1$）一致。
- 用一个独立的纯 Python 实现（`core/tests/vectors/sm2_hash_to_curve.py`，包含自写的 SM3）生成 SM2 测试向量。这个实现本身也先用 P-256 向量验证过。Rust 实现的输出与它一致。

这个套件只能和使用同一套件的实现互通，也就是本库自身。如果以后出现 SM2 的标准套件，切换时需要升级会话头版本。

#### FourQ

FourQ（Costello、Longa，ASIACRYPT 2015）是 $\mathrm{GF}(p^2)$（$p = 2^{127} - 1$）上的扭曲 Edwards 曲线 $-x^2 + y^2 = 1 + d x^2 y^2$，$\#E = 392 \cdot N$，$N$ 为 246 位素数。本库只使用 $N$ 阶子群。实现是纯 Rust，没有用 FourQlib 的 C 代码：

| 部分 | 实现 |
| --- | --- |
| 域运算 | $\mathrm{GF}(p)$、$\mathrm{GF}(p^2)$，常数时间；平方根用 Adj、Rodríguez-Henríquez 的算法 9 |
| 点运算 | 扩展坐标 $(X, Y, Z, T_a, T_b)$ 的完备加法与倍点，公式取自 FourQlib |
| 标量乘 | 自同态 $\varphi$、$\psi$ 加四维分解（4 个 64 位子标量），GLV-SAC 重编码，64 次倍点加 65 次常数时间查表（8 项表，每次扫描全表）。按 FourQlib 的 `ecc_mul` 移植，常数用脚本从 FourQlib 源码中提取 |
| 点编码 | 32 字节：$y_0 \| y_1$（小端），最后一字节最高位为 $\mathrm{sgn0}(x)$ |

**hash-to-curve 套件 `FourQ_XMD:SHA-256_ELL2_RO_`**（本库自定义，FourQ 没有标准套件）：

| 参数 | 取值 |
| --- | --- |
| `expand_message` | `expand_message_xmd`，SHA-256 |
| 安全级别 $k$ | 128 |
| $L$ | 32 字节 / $\mathrm{GF}(p)$ 系数，每个 $\mathrm{GF}(p^2)$ 元素两个系数 |
| 映射 | Elligator 2 作用于双有理等价的 Montgomery 曲线 $K t^2 = s^3 + J s^2 + s$，$J = 2(1-d)/(1+d)$，$K = -4/(1+d)$（RFC 9380 §6.7.1），再用附录 D.1 的有理映射到 Edwards 曲线 |
| $Z$ | $2 + i$，按 RFC 9380 附录 H.3 的规则选出 |
| 余因子 | $Q_0 + Q_1$ 之后乘 392 |

**对端点的处理（`Group::decode_mul`）**：

- 解码时检查编码规范、点在曲线上，但不做完整的 $N \cdot P$ 子群检查，因为它的代价和一次标量乘相当。
- 解码后先乘余因子 392，把任意曲线点投影到 $N$ 阶子群，再乘私钥。小阶分量在私钥作用之前就被去掉；小阶点变成单位元，直接拒绝。
- 双方的每个比较值都恰好经过一次 `decode_mul`，所以两边多乘的是同一个 392，交集结果不变。
- 这一论证是本库自己的，没有经过外部审查。其他曲线的余因子为 1（或由 Ristretto 编码消除），`decode_mul` 就是“解码后再乘私钥”。

**验证**：

- 独立的 Python 实现 `core/tests/vectors/fourq_reference.py` 先检查常数：$p$、$N$ 为素数，$d$ 非平方，$\#E = 392N$，$Z = 2 + i$。然后生成 hash-to-curve 和标量乘的测试向量，Rust 实现与之逐字节一致（含 $(N-1) \cdot P = -P$）。
- 四维分解的标量乘与朴素倍点加法结果一致；$N \cdot G$ 为单位元。
- $\varphi$、$\psi$ 的输出在曲线上，并满足同态性质。
- 余因子清除等于 392 次加法；解码拒绝非规范编码、单位元、子群外的点（`decode`），以及小阶点（`decode_mul`）。

常数时间只从实现方式上保证（没有依赖私钥的分支，查表扫描全部表项），没有做过时序测量。

### 曲线选择

- **Ristretto255**：默认。最快，群阶是素数，没有余因子带来的问题。
- **P-256**：要求使用 NIST 曲线时选用。它的 hash-to-curve 是 RFC 9380 标准套件，但消息格式仍是本库自定义的，不能和其他 PSI 实现直接互通。
- **SM2**：要求国密合规时选用。
- **FourQ**：和 Ristretto255 速度相近（见下表），hash-to-curve 与对端点处理都是本库自定义的。没有特别理由时建议用 Ristretto255。

### 性能

测试环境：Apple M5（10 核），16 GB 内存，release 构建，默认线程数，不分桶。数据为 11 位数字字符串，交集占一半。下表的耗时不含网络传输。

| 曲线 | 规模（接收方 × 发送方） | 总耗时 | 通信量 |
| --- | --- | --- | --- |
| Ristretto255 | 10 万 × 10 万 | 1.7 s | 7.1 MiB |
| P-256 | 10 万 × 10 万 | 8.0 s | 7.2 MiB |
| SM2 | 10 万 × 10 万 | 7.6 s | 7.2 MiB |
| Ristretto255 | 100 万 × 100 万 | 18.3 s | 70.6 MiB |
| SM2 | 100 万 × 100 万 | 84.1 s | 72.5 MiB |
| Ristretto255 | 1000 万 × 1000 万 | 199.1 s | 715 MiB |
| SM2 | 1000 万 × 1000 万 | 947.9 s | 734 MiB |

- 以上为双方在同一进程内的测试，两方争用同一组 CPU，发送方预计算的收益体现不出来（分进程的实测见上文“流程”）。
- 计算量和通信量都随数据规模线性增长。SM2、P-256 比 Ristretto255 慢约 4.5 倍，差距来自曲线运算本身。
- 线程数的影响（SM2，5 万 × 5 万）：1 线程 21.8 s，2 线程 11.2 s，4 线程 5.9 s，10 线程 3.8 s，基本线性加速。

FourQ 与 Ristretto255（同一环境，同一进程，不分桶；和上表不是同一次测量，所以 Ristretto255 100 万的数字略有出入）：

| 规模 | 线程 | Ristretto255 | FourQ |
| --- | --- | --- | --- |
| 10 万 × 10 万 | 10 | 2.15 s | 1.71 s |
| 100 万 × 100 万 | 10 | 18.89 s | 17.91 s |
| 5 万 × 5 万 | 1 | 3.34 s | 3.36 s |

单次操作（单线程）：

| 操作 | Ristretto255 | FourQ | P-256 | SM2 |
| --- | --- | --- | --- | --- |
| hash-to-group | 4.7 µs | 10.6 µs | 17.2 µs | 33.1 µs |
| 标量乘 | 16.0 µs | 14.8 µs | 71.7 µs | 74.1 µs |
| 编码 | 2.2 µs | 0.6 µs | 3.2 µs | 7.1 µs |

FourQlib 用汇编和 AVX2 实现模乘，可以比 Curve25519 快 2 倍以上；这里是纯 Rust，$\mathrm{GF}(p)$ 乘法约 6 ns，标量乘只略快于 Ristretto255。hash-to-group 慢一倍多，主要来自一次 $\mathrm{GF}(p^2)$ 开方（约 2.9 µs）和余因子清除。测试方法：`cargo test --release group_timing -- --ignored --nocapture`。

内存（Ristretto255，1000 万 × 1000 万，双方各一个进程，通过 TCP 通信，从文件读数据）：

| 方式 | 接收方 | 发送方 |
| --- | --- | --- |
| 不分桶 | 201.3 s，峰值 1.82 GiB | 150.9 s，峰值 1.93 GiB |
| `bucket_size=100_000`（101 个桶） | 216.8 s，峰值 0.18 GiB | 216.0 s，峰值 0.16 GiB |

分桶后内存大约只和单个桶的大小有关，总耗时略有增加（每个桶是一次独立会话）。代价是需要和输入大小相当的临时磁盘空间。分桶一行为分桶落盘移到核心库之后的测量；之前为 195.2 s / 0.20 GiB，差异在测量波动范围内。

### 底层算子

| 算子 | 模块 |
| --- | --- |
| 曲线运算 | `primitives/ec/{curve25519, p256, sm2}.rs`（curve25519-dalek、RustCrypto `p256` / `sm2`）；`primitives/ec/fourq/`、`fourq_group.rs`（自写） |
| 哈希到群 | `primitives/ec/hash_to_curve.rs`（`hash2curve` 的 `expand_message`，自写的通用 SSWU） |
| SHA-256 / SHA-512 / SM3 | `primitives/hash/` |
| 随机标量、打乱 | `primitives/rand.rs`（ChaCha20，由操作系统随机源播种） |
| 消息编解码、截断、求交 | `algorithms/psi/common.rs` |
| 协议 | `algorithms/psi/ecdh/protocol.rs` |
| 分桶 | `algorithms/psi/bucket.rs`（桶号规则）、`algorithms/psi/store.rs`（落盘、去重、结果位图） |
| 线程池 | `exec.rs` |

依赖都是纯 Rust，不需要 C 工具链，已在 `x86_64-apple-darwin`、`aarch64-unknown-linux-gnu` 上通过 `cargo check`；`x86_64-unknown-linux-gnu` 未验证。

---

## VOLE-PSI

### 原理

VOLE-PSI 由三部分组成：

1. **静默 OT（Ferret）** 以很少的通信生成大量相关 OT（COT）。
2. 每 128 个 COT 合成一个 $\mathbb{F} = \mathrm{GF}(2^{128})$ 上的 **VOLE**。
3. 用 VOLE 和二进制 OKVS 构造**不经意伪随机函数（OPRF）**，思路和 VOLE-PSI（Rindal、Schoppmann，Eurocrypt 2021）、RR22 一致。

发送方持有 OPRF 密钥 $(\Delta, K)$，可以对任意元素求值；接收方只能对自己编码进 OKVS 的元素求值。

**VOLE 相关性**：长度为 $M$ 的 VOLE 中，接收方持有 $a, c \in \mathbb{F}^M$，发送方持有 $\Delta \in \mathbb{F}$ 和 $b \in \mathbb{F}^M$，满足 $b = c \oplus a \otimes \Delta$。

**COT → VOLE**：COT 中接收方有选择位 $x$ 和块 $t$，发送方有 $q = t \oplus x \cdot \Delta$。取 128 个 COT，令

$$
a = \textstyle\sum_k x_k e_k,\quad c = \sum_k e_k \otimes t_k,\quad b = \sum_k e_k \otimes q_k
$$

其中 $e_k$ 是只有第 $k$ 位为 1 的元素。由于 $\otimes$ 是双线性的，$b = c \oplus a \otimes \Delta$。实现上这只需要一次 Montgomery 约简（`primitives/field.rs` 的 `combine`）。

### 一个任务（job）的流程

一次 `run` 的所有桶共用一个任务：只做一次 setup，之后每个桶只需要一个请求和一个回复。

```
接收方 R                                              发送方 S
────────────────────────────────────────────────────────────────────────
           ── J1：seed_R, 各桶大小 n_b, A ──▶          Δ ← GF(2^128)
                                                      128 次基础 OT，选择位为 Δ
           ◀── J2：seed_S, 各桶大小 m_b, B_1..B_128 ──
IKNP 扩展出 Ferret 的初始储备
           ── J3：U ──▶
           ◀── Ferret 迭代 0, 1, 2, …（单向流） ──     发送方连续产生
每 128 个 COT → 一个 VOLE (a, c)                       每 128 个 COT → 一个 b

对每个桶 b（流水线，最多 2 个桶在途）：
P = Encode({x → h(x)})
           ── 请求 b：OKVS seed, a' = a ⊕ P ──▶
                                                      K = b ⊕ a' ⊗ Δ = c ⊕ P ⊗ Δ
           ◀── 回复 b：打乱后的 F(y) ──
F(x) ∈ {F(y)} ⟺ x ∈ 交集
```

对元素 $x$，记 $d = H(\texttt{"…-ITEM"} \| x)$，$h(x) = H(\texttt{"…-CODE"} \| d)$ 的前 16 字节，$H$ 为 SHA-256，DST 前缀为 `CRYPTEX-VOLE-PSI-V2-`。记桶号为 $\beta$（u32 小端编码）。

- 发送方：$F(y) = H(\texttt{"…-OUT"} \| \beta \| d \| \mathrm{Decode}(K, y) \oplus h(y) \otimes \Delta)$ 的前 $t$ 字节
- 接收方：$F(x) = H(\texttt{"…-OUT"} \| \beta \| d \| \mathrm{Decode}(c, x))$ 的前 $t$ 字节

**正确性**：$\mathrm{Decode}$ 是线性的，$\mathrm{Decode}(K, x) = \mathrm{Decode}(c, x) \oplus \mathrm{Decode}(P, x) \otimes \Delta$。对编码过的 $x$，$\mathrm{Decode}(P, x) = h(x)$，两边一致。

**安全性要点**：对接收方没有编码的 $y$，$\mathrm{Decode}(P, y) \oplus h(y)$ 不为零（除非概率为 $2^{-128}$ 的碰撞），所以 $F(y)$ 依赖接收方不知道的 $\Delta$，接收方无法预测。$a$ 是伪随机的，$a' = a \oplus P$ 不泄露 $P$。

截断长度 $t$ 与 ECDH-PSI 相同：$\lambda + \log_2 n_b + \log_2 m_b + \log_2 B$ 位。

**流水线**：Ferret 迭代、桶请求、桶回复在两个方向上同时流动。

- 发送方生成的 VOLE 只覆盖尚未回复的桶中的前 3 个，够用后就暂停生成 Ferret 迭代。
- 接收方在途（已发请求、未收到回复）的桶最多 2 个。
- 双方各自最多提前读入 3 个桶的元素。

所以内存只和几个桶的大小有关。任何一方为空的桶，双方都会跳过，不消耗 VOLE。

### 消息格式

整数均为大端：

| 标签 | 方向 | 内容 |
| --- | --- | --- |
| `0x21` | R → S | seed_R（16）、share（u8）、桶数 B（u32）、$n_0 … n_{B-1}$（u64）、A（32） |
| `0x22` | S → R | seed_S、B、$m_0 … m_{B-1}$、$B_1 … B_{128}$（各 32） |
| `0x23` | R → S | IKNP 行 U（各 16 字节，共约 47,744 行，约 764 KB） |
| `0x24` | S → R | 迭代序号（u64）、Ferret 消息（主迭代 559,440 字节） |
| `0x25` | R → S | 桶号（u32）、OKVS seed（16）、M（u64）、$a'$（各 16 字节） |
| `0x26` | S → R | 桶号、t（u8）、m（u64）、输出（各 $t$ 字节） |
| `0x27` | R → S | 仅结果共享：桶号、k（u64）、该桶回复中匹配的位置（严格升序，各 u32；$m_b \ge 2^{32}$ 时为 u64） |

收到的消息会严格校验：类型、所处阶段、桶号和迭代序号的顺序、长度、点的合法性，以及 $M$ 是否和桶大小相符。任何错误都会让任务失效。

### 静默 OT（Ferret）

按 Ferret（Yang、Weng、Lan、Zhang、Wang，CCS 2020）在 emp-ot 中的实现方式：

- **SPCOT**：每个块由发送方展开一棵 GGM 树，PRG 为固定密钥 AES：$G(s) = (\mathrm{AES}_{k_0}(s) \oplus s, \mathrm{AES}_{k_1}(s) \oplus s)$。接收方的穿孔位置 $\alpha$ 由储备 COT 的选择位决定（每层取反），所以迭代过程中**接收方不需要发消息**。发送方每层发送左、右子节点的异或和，用该层 COT 的 $H(q)$、$H(q \oplus \Delta)$ 掩码，$H$ 为带索引的 SHA-256。另外发送 $\Delta \oplus \bigoplus_l v_l$。
- **LPN**：正则噪声的原始 LPN，局部线性码每列 10 个 1，矩阵由双方公开种子经 AES-CTR 生成。
- **自举**：每次迭代保留一部分输出，作为下一次迭代的储备。

| 参数 | 初始迭代 | 主迭代 |
| --- | --- | --- |
| 输出 $n$ | 649,728 | 10,608,640 |
| LPN 秘密长度 $k$ | 36,288 | 588,160 |
| 噪声重量 $t$（树的个数） | 1,269 | 1,295 |
| 树深 $h$（块长 $2^h$） | 9（512） | 13（8192） |
| 每次迭代可用的 VOLE | 349 | 78,153 |
| 发送方每次迭代发送 | 385,776 B（约 386 KB） | 559,440 B（约 559 KB） |

每次迭代保留 $k + t \cdot h$ 个输出作为下一次的储备（主迭代为 604,995 个），其余的按 128 个一组转成 VOLE，不足 128 的余数丢弃。

各处哈希与种子（均为 SHA-256，带域分离标签）：

| 用途 | 输入 |
| --- | --- |
| GGM 的两个固定 AES 密钥 | `"CRYPTEX-FERRET-GGM-V1"`，结果的前、后 16 字节 |
| COT 去随机化的相关稳健哈希 | `"CRYPTEX-FERRET-CRH-V1"` ‖ 全局 COT 序号（u64 小端）‖ 块，取前 16 字节 |
| LPN 矩阵的 AES-CTR 密钥 | `"CRYPTEX-FERRET-LPN-V1"` ‖ 会话种子 ‖ 迭代序号（u64 小端），取前 16 字节 |
| 会话种子 | `"CRYPTEX-VOLE-PSI-V2-SESSION"` ‖ seed_R ‖ seed_S |

LPN 矩阵每列的 10 个下标，取自 AES-CTR 密钥流中每个输出对应的 48 字节（用前 40 字节，每 4 字节一个 u32），对 $k$ 取模。取模带来的偏差不超过 $k / 2^{32}$。

参数取自 emp-ot 的 `ferret_cot`（`N_REG`、`K_REG`、`T_REG`、`BIN_SZ_REG` 及对应的 `_PRE_` 常量）。它们是针对 GF(2) 上的 LPN 分析的，这里也只在 GF(2) 上使用：COT 的选择位是二进制 LPN 的输出，转换成 GF(2^128) 上的 VOLE 是在 LPN 之后进行的线性组合，不改变底层 LPN 实例。

**这些常量是按 emp-ot 源码的记忆写入的，尚未对照源码核对，用于生产前必须逐一核对。** 实现的正确性（COT 关系、自举、与 IKNP 的衔接）有单元测试覆盖，但测试无法验证参数的安全强度。

### OT 扩展与基础 OT

- **基础 OT**：Chou–Orlandi simplest OT，Ristretto255，128 次。发送方是基础 OT 的接收方，选择位为 $\Delta$。密钥为 SHA-256(`"CRYPTEX-BASE-OT-V1"` ‖ 序号（u64 大端）‖ A ‖ B_i ‖ 共享点) 的前 16 字节。在随机预言机模型和 CDH 假设下半诚实安全。
- **IKNP**：宽度 128，PRG 为 AES-128-CTR。接收方的选择位随机生成，只用来产生 Ferret 初始迭代所需的 47,709 个 COT（向上取整到 47,744）。角色和基础 OT 相反：发送方（持有 $\Delta$）是扩展的发送方。

### OKVS

二进制随机带状 OKVS（RB-OKVS，Bienstock、Patel、Seo、Yeo，USENIX Security 2023）。矩阵是二进制的，表项为 16 字节（GF(2^128) 元素），编码和解码都只做异或，所以 $\mathrm{Decode}$ 对表是线性的。

| 参数 | 取值 |
| --- | --- |
| 带宽 | 128 位，第 0 位固定为 1 |
| 表大小 $M$ | $n + \lceil n/10 \rceil + 128$，向上取整到 128 的倍数（$\varepsilon = 0.1$） |
| 行哈希 | SHA-256(`"CRYPTEX-RB-OKVS-V1"` ‖ seed ‖ d)：前 8 字节（u64 小端）对 $M - 127$ 取模得到起始列，接下来 16 字节（u128 小端）作为带 |
| 编码 | 按起始列排序，做只在带内进行的高斯消元，再回代；没有约束的表项取随机值 |
| 失败处理 | 行线性相关时编码失败，接收方换一个随机 seed 重试，最多 8 次；seed 随桶请求发送 |

在 $\varepsilon = 0.1$、带宽 128 下，实测 20,000 次 $n = 1000$、500 次 $n = 10^5$、50 次 $n = 10^6$，均未出现失败（`cargo test --release okvs_failure_rate -- --ignored`）。这是**实测结果，不是理论界**。重试会向发送方暴露“接收方的集合在之前的 seed 下编码失败过”这一事件。按实测失败率，这个泄露可以忽略，但它不在本库给出的 $2^{-40}$ 界之内。

### 国密支持

**VOLE-PSI 不提供国密版本，固定使用 AES-128 和 SHA-256。** 需要国密合规时，请使用 ECDH-PSI + SM2。

### 性能

两个进程分别扮演接收方和发送方，通过本机 TCP 通信，每方 5 个线程，每个方向限速 100 Mbps，模拟两台 5 核机器之间的百兆全双工链路。数据为 11 位数字字符串，交集占一半。除标明“文件”的行外，输入是 Python 列表。

| 协议 | 规模（接收方 × 发送方） | 分桶 | 耗时 | R→S | S→R |
| --- | --- | --- | --- | --- | --- |
| VOLE | 100 万 × 100 万 | 否 | 6.4 s | 17.5 MiB | 17.9 MiB |
| VOLE | 100 万 × 100 万 | 每桶 20 万 | 4.7 s | 17.5 MiB | 17.9 MiB |
| ECDH（Ristretto255） | 100 万 × 100 万 | 否 | 26.0 s | 30.5 MiB | 40.1 MiB |
| VOLE | 1000 万 × 1000 万 | 否 | 65.3 s | 169 MiB | 181 MiB |
| VOLE | 1000 万 × 1000 万 | 每桶 100 万 | 44.1 s | 169 MiB | 181 MiB |
| ECDH（Ristretto255） | 1000 万 × 1000 万 | 否 | 280.7 s | 305 MiB | 410 MiB |
| VOLE，文件 | 1 亿 × 1 亿 | 每桶 100 万 | 444.2 s | 1.64 GiB | 1.76 GiB |

不限速时，100 万 × 100 万 VOLE-PSI 为 3.4 s，1000 万（每桶 100 万）为 32.5 s（列表输入）或 30.3 s（文本文件输入）。

1000 万、每桶 100 万、文本文件输入时耗时的构成（不限速）：核心库读文件并分桶落盘 0.6 s，桶内去重也在核心库里，耗时可以忽略；其余约 30 s 是 11 个桶的 PSI。上一版分桶和去重在 Python 层完成，这两步约 10 s（双方在不同进程时）到 19 s（同一进程）。单个 100 万的桶在 Rust 里的耗时为：Ferret 16 次迭代 3.2 s（双方合计）、接收方 OKVS 编码与请求 0.23 s、发送方回复 0.14 s、接收方求交 0.06 s。所以**瓶颈是 Ferret 的计算**。百兆网下 1000 万规模每个方向约 180 MiB，传输约 15 s，可以和计算重叠。

- 每个元素的通信量约为 R→S 18 字节、S→R 19 字节。上一版（IKNP，宽 512）R→S 约 70 字节。
- 两个方向的数据量接近，全双工链路两边都能用满。
- Ferret 生成速度：5 线程每方约 9000–9900 万 COT/s（含合成 VOLE），约合 74 万 VOLE/s。
- 1 亿规模（实测 444 s，约 7.4 分钟）：每个方向约 1.7 GiB，按 100 Mbps 传输约 150 s；其余主要是 Ferret 计算。上一版（IKNP，宽 512）同样条件下估计约 16 分钟（未实测）。
- 列表输入比文本文件慢一些，因为每个元素要先在 Python 里编码，再成批交给核心库。

结果共享的开销（不限速、列表输入、不分桶，100 万 × 100 万，交集 50 万，其他条件同上）：

| 协议 | 不共享 | 共享 | R→S 增加 |
| --- | --- | --- | --- |
| VOLE | 4.7 s | 4.7 s | 17.5 → 19.4 MiB |
| ECDH（Ristretto255） | 24.0 s | 24.6 s | 30.5 → 32.4 MiB |

后续的提速方向见 [optimization.md](../optimization.md)。

### 内存

双方各一个进程，通过 TCP 通信，每方 5 线程，不限速，从文件读数据，接收方把交集流式写入文件。数值为进程峰值常驻内存（`ru_maxrss`）。

| 规模 | 分桶 | 接收方峰值 | 发送方峰值 |
| --- | --- | --- | --- |
| 100 万 × 100 万 | 否 | 0.51 GiB | 0.37 GiB |
| 100 万 × 100 万 | 每桶 10 万 | 0.12 GiB | 0.11 GiB |
| 1000 万 × 1000 万 | 否 | 2.34 GiB | 2.09 GiB |
| 1000 万 × 1000 万 | 每桶 100 万 | 0.74 GiB | 0.56 GiB |
| 1000 万 × 1000 万 | 每桶 10 万 | 0.17 GiB | 0.15 GiB |
| 1 亿 × 1 亿（百兆网） | 每桶 100 万 | 1.51 GiB | 1.22 GiB |

内存由三部分组成：

- **和桶大小有关的部分**：一个桶的元素、OKVS 表、VOLE 元素，以及接收方在途的最多 2 个桶的输出和位置表。分桶后桶由核心库读入并直接交给协议，不会在 Python 里再复制一份。
- **固定部分**：Ferret 按块生成，每块的输出当场合成 VOLE，一次迭代的原始 COT（主迭代约 1000 万个，约 170 MB）不会同时放在内存里，只保留下一次迭代的储备（约 60 万个，约 10 MB）。所以 `bucket_size` 设到 10 万时，单方峰值约 0.15 GiB。
- **和总数据量有关的部分**：接收方的结果位图，每个元素 1 bit，1 亿条约 12 MB。1 亿规模（百兆网）实测峰值比 1000 万高约 0.7 GiB，位图解释不了这个差值，原因尚未查明。

不分桶时整个集合在内存里，而且列表输入时 Python 和核心库各持有一份，内存随规模增长。

Python 绑定默认 `bucket_size=1_000_000`。内存紧张时设为 10 万左右。

上一版（Python 层分桶，Ferret 整体生成）的对应数值：1000 万、每桶 100 万为 1.26 / 1.13 GiB，每桶 10 万为 0.39 / 0.34 GiB。

### 底层算子

| 算子 | 模块 |
| --- | --- |
| 基础 OT | `primitives/ot/base.rs`（Ristretto255） |
| IKNP | `primitives/ot/extension.rs`（宽度为泛型参数，这里用 128） |
| 静默 OT | `primitives/ot/ferret.rs`（按块生成，每块的输出当场合成 VOLE） |
| GF(2^128) 运算、COT → VOLE | `primitives/field.rs`（`polyval` crate 的 POLYVAL 乘法） |
| PRG | `primitives/prg.rs`（AES-128-CTR） |
| OKVS | `primitives/okvs/band.rs` |
| 任务协议 | `algorithms/psi/vole/job.rs` |
| C 接口 | `ffi/vole.rs` |

---

## 依据

“依据”一列说明每个组件来自哪里，“类型”一列表示它属于哪一类：

- **标准**：按标准实现，并用标准里的测试向量验证。
- **论文**：按公开论文的构造实现，没有官方测试向量，用单元测试验证正确性。
- **自定义**：本库自己确定的参数或格式，只能和本库互通。

### ECDH-PSI 的组件

| 组件 | 实现 | 依据 | 类型 | 验证 |
| --- | --- | --- | --- | --- |
| 协议 | 双方各盲化一次，交换后比对截断哈希 | Meadows（IEEE S&P 1986）；Huberman、Franklin、Hogg（ACM EC 1999） | 论文 | 端到端测试 |
| Ristretto255 群 | curve25519-dalek | RFC 9496 | 标准 | 由 crate 自带测试覆盖 |
| Ristretto255 hash-to-group | `expand_message_xmd`（SHA-512）+ RFC 9496 one-way map，套件 `ristretto255_XMD:SHA-512_R255MAP_RO_` | RFC 9380、RFC 9496；构造方式与 RFC 9497 相同 | 标准 | 确定性、域分离测试 |
| P-256 曲线 | RustCrypto `p256` | FIPS 186-5、SEC 1 | 标准 | 由 crate 自带测试覆盖 |
| P-256 hash-to-curve | 套件 `P256_XMD:SHA-256_SSWU_RO_` | RFC 9380 | 标准 | RFC 9380 附录 J.1.1 测试向量 |
| SM2 曲线 | RustCrypto `sm2` | GB/T 32918-2016 | 标准 | 由 crate 自带测试覆盖 |
| SM2 hash-to-curve | 套件 `SM2_XMD:SM3_SSWU_RO_`，Simplified SWU，Z = −9 | 方法按 RFC 9380；Z 按 RFC 9380 附录 H.2 选出 | **自定义** | 通用 SSWU 先用 P-256 标准向量验证；SM2 向量由独立 Python 实现生成并比对 |
| FourQ 曲线与标量乘 | 自写：GF(p^2)、完备加法、自同态与四维分解 | Costello、Longa（ASIACRYPT 2015）；公式与常数取自 FourQlib | 论文 | 独立 Python 实现的测试向量；与朴素倍点加法对比 |
| FourQ hash-to-curve | 套件 `FourQ_XMD:SHA-256_ELL2_RO_`，Elligator 2，Z = 2 + i，乘余因子 392 | 方法按 RFC 9380（§6.7.1、附录 D.1、H.3） | **自定义** | 独立 Python 实现生成的向量逐字节比对 |
| FourQ 对端点处理 | 解码后乘余因子 392 再乘私钥（`decode_mul`），代替完整子群检查 | 本库自己的论证 | **自定义** | 小阶点拒绝、带挠分量的点投影测试 |
| SHA-256 | RustCrypto `sha2` | FIPS 180-4 | 标准 | FIPS 180-4 测试向量 |
| SM3 | RustCrypto `sm3` | GB/T 32905-2016 | 标准 | GB/T 32905 附录 A 测试向量 |
| 截断长度 | $\lambda + \log_2 n + \log_2 m + \log_2 B$ 位，$\lambda = 40$ | 误判概率的联合界 | 自定义参数 | 单元测试 |
| 会话头、消息格式 | 见上文 | — | **自定义** | 畸形消息测试 |

### OPRF-PSI 的组件

群、hash-to-curve、SHA-256、SM3 与 ECDH-PSI 共用，见上表。只列 OPRF-PSI 特有的部分：

| 组件 | 实现 | 依据 | 类型 | 验证 |
| --- | --- | --- | --- | --- |
| OPRF | 2HashDH：$F_k(x) = \mathrm{Hash}(x, H(x)^k)$，盲化、求值、去盲 | Jarecki、Kiayias、Krawczyk（ASIACRYPT 2014）；RFC 9497 OPRF 模式 | 标准 | RFC 9497 附录 A.1.1（ristretto255-SHA512）、A.3.1（P256-SHA256）测试向量 |
| SM2、FourQ 的 OPRF 套件 | `SM2-SM3`、`FourQ-SHA256`，结构同 RFC 9497 | 方法按 RFC 9497 | **自定义** | 端到端测试；输出与 blind 无关的测试 |
| 整批共用一个 blind | 接收方一次会话只用一个 $r$，只求一次逆 | 与 ECDH-PSI 消息 1 相同的 DDH 论证 | 自定义用法 | 输出与 blind 无关的测试 |
| SHA-512 | RustCrypto `sha2` | FIPS 180-4 | 标准 | FIPS 180-4 测试向量 |
| 标量求逆 | 各 crate 的常量时间求逆；FourQ 用 `crypto-bigint` 的 safegcd | Bernstein、Yang（TCHES 2019） | 标准算法 | $k \cdot k^{-1} \equiv 1$ 测试，含边界值 |
| 消息格式 | 见 [psi-oprf.md](psi-oprf.md) | — | **自定义** | 畸形消息、乱序调用测试 |

### VOLE-PSI 的组件

| 组件 | 实现 | 依据 | 类型 | 验证 |
| --- | --- | --- | --- | --- |
| OPRF 与 PSI 协议 | VOLE + OKVS 构造 OPRF | Rindal、Schoppmann（Eurocrypt 2021）；Raghuraman、Rindal（RR22，ACM CCS 2022） | 论文 | 端到端测试、随机消息交错测试 |
| 基础 OT | Chou–Orlandi simplest OT，Ristretto255，128 次 | Chou、Orlandi（Latincrypt 2015） | 论文 | 选择密钥正确、另一密钥不同 |
| OT 扩展 | IKNP，宽度 128 | Ishai、Kilian、Nissim、Petrank（Crypto 2003） | 论文 | COT 关系测试 |
| 静默 OT | Ferret：GGM 树 SPCOT + 正则噪声原始 LPN + 自举 | Yang、Weng、Lan、Zhang、Wang（ACM CCS 2020）；Boyle 等（Crypto 2019） | 论文 | COT 关系、多轮自举测试 |
| Ferret 参数 | n = 10,608,640，k = 588,160，t = 1,295，块长 8192；初始轮另有一组 | emp-ot 的 `ferret_cot` 常量 | **需核对** | 按 emp-ot 源码记忆写入，生产前应对照源码核对 |
| GF(2^128) 乘法 | POLYVAL，RustCrypto `polyval` | RFC 8452 | 标准 | 与朴素实现对比、域公理测试 |
| COT → VOLE | 128 个 COT 线性组合为一个 VOLE | 双线性推导（见上文「原理」） | 自定义推导 | 恒等式测试 |
| OKVS | 二进制随机带状 OKVS，带宽 128，ε = 0.1 | Bienstock、Patel、Seo、Yeo（USENIX Security 2023） | 论文 + 自选参数 | 编解码与线性测试；20,570 次编码实测无失败（实测结果，不是理论界） |
| AES-128 | RustCrypto `aes` | FIPS 197 | 标准 | FIPS 197 附录 C.1 测试向量 |
| PRG | AES-128-CTR | NIST SP 800-38A（CTR 模式） | 标准 | 计数器偏移一致性测试 |
| GGM PRG | 固定密钥 AES：$\mathrm{AES}_k(s) \oplus s$ | emp-ot / libOTe 的常用做法 | 论文惯例 | 由 Ferret 测试覆盖 |
| 随机预言机、相关稳健哈希 | 带域分离标签的 SHA-256 | FIPS 180-4 | 标准哈希 + 自定义用法 | 由协议测试覆盖 |
| 消息格式 | 见上文 | — | **自定义** | 畸形消息测试 |

### 通用组件

| 组件 | 实现 | 依据 | 类型 |
| --- | --- | --- | --- |
| 随机数 | ChaCha20，由操作系统随机源播种（`rand`、`getrandom`） | RFC 8439（ChaCha20） | 标准 |
| 分桶规则 | SHA-256 或 SM3（`"CRYPTEX-PSI-BUCKET-V1"` ‖ 元素）前 8 字节，对桶数取模 | — | **自定义**，固定值测试并用独立 Python 实现交叉验证 |
| 密钥清零 | `zeroize` | — | — |

### 需要特别注意的几项

- **FourQ 是自写实现**：曲线运算没有使用经过审计的库，hash-to-curve 套件和对端点处理（`decode_mul`）也是本库自定义的；常数时间只从实现方式上保证。用于生产前建议做安全审查和侧信道测试。
- **SM2 的 hash-to-curve 是自定义套件**：SM2 没有标准化的 hash-to-curve 套件，本库按 RFC 9380 的方法构造了一个，只能和本库互通。如果以后出现标准套件，切换时需要升级会话头版本。
- **Ferret 参数需要核对**：参数取自 emp-ot，但这些常量是按源码记忆写入的。单元测试只能验证实现正确，不能验证参数的安全强度，用于生产前应对照 emp-ot 源码逐一核对。
- **OKVS 编码失败率是实测值**：ε = 0.1、带宽 128 位下，20,570 次实测无失败，但这不是理论上的 $2^{-40}$ 界。编码失败时会换 seed 重试，重试本身会向对方暴露一次“编码失败过”。

完整列表见下文「参考文献」。

## 安全性

### 安全模型

三种协议都是**半诚实**安全：假设双方会按协议执行，只是会试图从收到的消息里推断额外信息。

VOLE-PSI 依赖的假设：Ristretto255 上的 CDH（基础 OT）、GF(2) 上正则噪声的原始 LPN（Ferret，参数见上文）、固定密钥 AES 作为 GGM 的 PRG、AES-CTR 作为 PRG、SHA-256 作为随机预言机 / 相关稳健哈希。ECDH-PSI 依赖所选群上的 DDH，以及哈希到群函数被视为随机预言机。OPRF-PSI 的假设与 ECDH-PSI 相同（2HashDH 在随机预言机模型下基于 One-More-Gap-DH 假设），另外把 `Finalize` 的哈希视为随机预言机。

半诚实安全**不防**以下行为：

- 一方构造畸形消息，诱导对方泄露更多信息；
- 发送方故意输出错误结果；
- 一方使用与声称不符的输入。注意，即使在恶意安全模型下也无法阻止这一点，这是 PSI 本身的限制。

如果对方可能主动作恶，需要恶意安全版本，目前不在规划内。

### 泄露的信息

| 信息 | 接收方 | 发送方 |
| --- | --- | --- |
| 对方集合大小 | 知道 | 知道 |
| 交集内容 | 知道 | 不知道；结果共享时知道（OPRF-PSI 不支持共享） |
| 交集大小 | 知道 | 不知道；结果共享时知道（OPRF-PSI 不支持共享） |
| 交集元素在对方集合中的位置 | 不知道（ECDH、VOLE 的发送方会打乱；OPRF 的发送方按伪随机值排序，顺序与输入无关） | 不知道（位置按升序发送） |
| 对方每个桶的元素个数（仅分桶时） | 知道 | 知道 |
| 对方每个桶的交集大小（仅分桶时） | 知道 | 不知道；结果共享时知道 |

分桶规则是公开的，各桶的元素个数相当于对方数据哈希值的粗略直方图。它不暴露具体元素，但桶越多、越细，信息越多。`bucket_size` 不宜设得太小。

分桶时，接收方还能知道交集落在了哪些桶里。规则公开，接收方可以对自己的候选值算桶号，所以这和接收方本来就能知道的交集内容相比，没有多泄露什么。

### 使用注意

- **重复执行会泄露更多**：接收方用不同集合和同一个发送方多次执行，可以拼凑出发送方集合的更多信息。在业务层面要限制执行次数和输入规模。
- **小值域可被枚举**：如果元素的取值空间很小（比如手机号只有约 $10^{10}$ 种），接收方可以把整个空间作为输入，从而得到发送方的完整集合。PSI 无法阻止这种行为，需要业务层面约束接收方的输入。
- **传输层安全**：协议消息本身不加密、不认证，需要依靠 TLS 等传输层手段防止中间人。
- **临时文件**：分桶时，`work_dir` 下的桶文件是输入数据的明文副本。要放在可信的磁盘上。任务结束或出错时会自动删除，但进程被强制终止（`kill -9`、断电）时不会删除。

## 接口

Python 的用法、参数和示例只在 [`bindings/python/README.md`](../../bindings/python/README.md) 里维护，这里只列出各层的入口。

| 层 | ECDH-PSI | OPRF-PSI | VOLE-PSI |
| --- | --- | --- | --- |
| Python 高层 | `Psi(Protocol.ECDH, …).run(...)` | `Psi(Protocol.OPRF, …).run(...)` | `Psi(Protocol.VOLE, …).run(...)` |
| Python 低层 | `PsiParty`（一来一回） | `PsiParty`（一来一回） | `VoleJob`（全双工、事件驱动） |
| C ABI | `cryptex_psi_new(CRYPTEX_PSI_ECDH, …)` / `step` / `result` / `free`（`ffi/psi.rs`） | `cryptex_psi_new(CRYPTEX_PSI_OPRF, …)`，其余同 ECDH；`share` 必须为 0 | `cryptex_vole_job_*`（`ffi/vole.rs`） |
| 共用 C ABI | `cryptex_pool_new` / `free`（线程池）、`cryptex_psi_bucket`（桶号）、`cryptex_store_*`（分桶落盘、去重、结果位图，`ffi/store.rs`） | 同左 | 同左 |
| Rust | `algorithms::psi::ecdh::{Sender, Receiver}`，实现 `protocol::Party` | `algorithms::psi::oprf::{Sender, Receiver}`，实现 `protocol::Party` | `algorithms::psi::vole::job`（`receive` / `next_send`） |

C 函数的参数、内存所有权和调用顺序，以源码中的文档注释为准。

## 参考文献

- C. Meadows. *A More Efficient Cryptographic Matchmaking Protocol for Use in the Absence of a Continuously Available Third Party*. IEEE S&P 1986.
- B. Huberman, M. Franklin, T. Hogg. *Enhancing Privacy and Trust in Electronic Communities*. ACM EC 1999.
- A. Faz-Hernandez et al. *Hashing to Elliptic Curves*. RFC 9380, 2023.
- H. de Valence et al. *The ristretto255 and decaf448 Groups*. RFC 9496, 2023.
- C. Costello, P. Longa. *FourQ: Four-Dimensional Decompositions on a Q-curve over the Mersenne Prime*. ASIACRYPT 2015.
- Microsoft Research. *FourQlib*（公式、常数与标量乘算法的来源）。
- G. Adj, F. Rodríguez-Henríquez. *Square Root Computation over Even Extension Fields*. IEEE Transactions on Computers, 2014.
- P. Rindal, P. Schoppmann. *VOLE-PSI: Fast OPRF and Circuit-PSI from Vector-OLE*. Eurocrypt 2021.
- S. Raghuraman, P. Rindal. *Blazing Fast PSI from Improved OKVS and Subfield VOLE*. ACM CCS 2022.
- B. Pinkas, M. Rosulek, N. Trieu, A. Yanai. *PSI from PaXoS: Fast, Malicious Private Set Intersection*. Eurocrypt 2020.
- Y. Ishai, J. Kilian, K. Nissim, E. Petrank. *Extending Oblivious Transfers Efficiently*. Crypto 2003.
- T. Chou, C. Orlandi. *The Simplest Protocol for Oblivious Transfer*. Latincrypt 2015.
- K. Yang, C. Weng, X. Lan, J. Zhang, X. Wang. *Ferret: Fast Extension for coRRElated oT with Small Communication*. ACM CCS 2020.
- E. Boyle, G. Couteau, N. Gilboa, Y. Ishai, L. Kohl, P. Scholl. *Efficient Pseudorandom Correlation Generators: Silent OT Extension and More*. Crypto 2019.
- L. Roy. *SoftSpokenOT: Quieter OT Extension from Small-Field Silent VOLE in the Minicrypt Model*. Crypto 2022.
- E. Boyle et al. *Correlated Pseudorandomness from Expand-Accumulate Codes*. Crypto 2022.
- A. Bienstock, S. Patel, J. Y. Seo, K. Yeo. *Near-Optimal Oblivious Key-Value Stores for Efficient PSI, PSU and Volume-Hiding Multi-Maps*. USENIX Security 2023.
- GB/T 32918-2016《信息安全技术 SM2 椭圆曲线公钥密码算法》
- GB/T 32905-2016《信息安全技术 SM3 密码杂凑算法》
- H. Davidson et al. *Oblivious Pseudorandom Functions (OPRFs) Using Prime-Order Groups*. RFC 9497, 2023.
- S. Jarecki, A. Kiayias, H. Krawczyk. *Round-Optimal Password-Protected Secret Sharing and T-PAKE in the Password-Only Model*. ASIACRYPT 2014.（2HashDH OPRF）
- D. J. Bernstein, B.-Y. Yang. *Fast constant-time gcd computation and modular inversion*. TCHES 2019.
- S. Gueron, A. Langley, Y. Lindell. *AES-GCM-SIV: Nonce Misuse-Resistant Authenticated Encryption*. RFC 8452, 2019.（POLYVAL 的定义）
- Y. Nir, A. Langley. *ChaCha20 and Poly1305 for IETF Protocols*. RFC 8439, 2018.
- NIST. *Secure Hash Standard (SHS)*. FIPS 180-4, 2015.
- NIST. *Digital Signature Standard (DSS)*. FIPS 186-5, 2023.（P-256 曲线参数）
- NIST. *Advanced Encryption Standard (AES)*. FIPS 197, 2001（2023 年更新）.
- M. Dworkin. *Recommendation for Block Cipher Modes of Operation*. NIST SP 800-38A, 2001.（CTR 模式）
- SECG. *SEC 1: Elliptic Curve Cryptography*, Version 2.0, 2009.（点编码）
- emp-toolkit. *emp-ot*（Ferret 参数来源）：https://github.com/emp-toolkit/emp-ot
