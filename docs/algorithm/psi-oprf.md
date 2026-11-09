# OPRF-PSI：非平衡场景（不缓存）

> 状态：**已实现**（核心库、C ABI、Python）。支持 Ristretto255、P-256、SM2、FourQ，支持分桶。半诚实安全，不支持结果共享。离线缓存模式（长期密钥、客户端缓存发送方标签）规划中。
>
> 本文只写 OPRF-PSI 特有的部分。会话头、输入处理、并发与分桶、依据、安全模型和接口与另外两种协议一起写在 [psi.md](psi.md)。

## 概述

接收方集合小（$n$），发送方集合大（$m \gg n$）。ECDH-PSI 在这种情况下：

- 接收方要对发送方的 $m$ 个点各做一次标量乘；
- 发送方要发 $m$ 个完整的点（32/33 字节）。

OPRF-PSI 去掉了这两部分：接收方只做 $2n$ 次标量乘，发送方每个元素只发 $t$ 字节的截断值。接收方的**群运算**与 $m$ 无关，但它仍要接收 $m \cdot t$ 字节，并把 $m$ 个标签扫描一遍。发送方的计算仍与 $m$ 成正比。

**和 VOLE-PSI 比**：VOLE-PSI 的发送方每个元素也只发 $t$ 字节，而且计算以 AES 和哈希为主，在同样的非平衡场景下比 OPRF-PSI 快约 6 倍（见下文「性能」）。所以：

- 不要求国密时，非平衡场景也用 **VOLE-PSI**。
- 要求国密（SM2 + SM3）且集合大小悬殊时，用 **OPRF-PSI**。它比 ECDH-PSI 快约 1.8 倍，S→R 通信约为 ECDH 的 1/3。
- OPRF-PSI 的另一个用途，是作为离线缓存模式的基础：密钥长期保存后，发送方的标签可以预先下发，在线阶段只和 $n$ 有关（规划中）。VOLE 的 OPRF 密钥和一次 setup 绑定，做不到这一点。

不缓存：每次会话（每个桶）发送方都用新密钥，重新计算并发送全部 $m$ 个值。

## 协议

基于 2HashDH OPRF（Jarecki、Kiayias、Krawczyk，ASIACRYPT 2014），形状与 RFC 9497 的 OPRF 模式一致：

$$
F_k(x) = \mathrm{Hash}\big(\mathrm{I2OSP}(|x|, 2) \,\|\, x \,\|\, \mathrm{I2OSP}(N_e, 2) \,\|\, \mathrm{enc}(H(x)^k) \,\|\, \texttt{"Finalize"}\big)
$$

接收方用一个随机标量 $r$ 盲化，发送方用密钥 $k$ 求值，接收方乘 $r^{-1}$ 去盲：

```
接收方 R（X，小）                                 发送方 S（Y，大；密钥 k）
r ← 随机标量                                      k ← 随机标量（每次会话新生成）
q_i = H(x_i)^r                                    f_j = T(F_k(y_j))，排序（创建时即开始计算）
                  ── 消息 1：[q_1, …, q_n] ──▶
                                                  e_i = q_i^k（保持顺序）
                  ◀── 消息 2：[e_i]，[f_j] ──
F_k(x_i) = Finalize(x_i, e_i^(1/r))
x_i ∈ 交集  ⟺  T(F_k(x_i)) ∈ {f_j}
```

- **$f_j$ 排序而不是打乱**：$F_k$ 的输出是伪随机的，排序后的顺序与 $Y$ 无关。接收方把自己的 $n$ 个值排序后与 $\{f_j\}$ 做一次归并，额外内存只有 $O(n)$。
- **一个 $r$ 盲化整批**：RFC 9497 对每个输入用独立的 blind；这里整批共用一个，接收方只需求一次逆。$F_k$ 的输出与 $r$ 无关（有测试），发送方看到的 $\{H(x_i)^r\}$ 在 DDH 假设下与随机点不可区分，和 ECDH-PSI 消息 1 的论证相同。
- **发送方预计算**：$f_j$ 不依赖消息 1，发送方一创建就在后台计算。
- **截断长度** $t$ 与 ECDH-PSI 相同：$\lambda + \log_2 n + \log_2 m + \log_2 B$ 位，$\lambda = 40$，$B$ 为桶数。密钥每次会话新生成，所以只需覆盖本次任务的比较次数。单次会话要求 $t \le 16$ 字节（约 $n \cdot m \cdot B < 2^{88}$），超过时发送方报错，提示分桶。

### 消息格式

整数为 u64 大端，点用各曲线的压缩编码：

| 消息 | 格式 |
| --- | --- |
| 消息 1 | `0x11 ‖ n ‖ q_1 … q_n` |
| 消息 2 | `0x12 ‖ t (u8) ‖ n ‖ e_1 … e_n ‖ m ‖ f_1 … f_m`，$f_j$ 按字节序升序 |

标签与 ECDH-PSI（`0x01`、`0x02`）不同，两种协议的消息不会被误收。双方都完整校验收到的点：在曲线上、在素数阶子群内、不是单位元。接收方还检查 $t$ 是否与自己算出的一致，以及 $f_j$ 是否有序。

## 参数

| 曲线 | 套件 ID | HashToGroup | Finalize 哈希 | 点长度 |
| --- | --- | --- | --- | --- |
| Ristretto255 | `ristretto255-SHA512` | RFC 9380 / RFC 9496，`expand_message_xmd`（SHA-512） | SHA-512 | 32 |
| P-256 | `P256-SHA256` | RFC 9380 `P256_XMD:SHA-256_SSWU_RO_` | SHA-256 | 33 |
| SM2 | `SM2-SM3`（自定义） | 本库 `SM2_XMD:SM3_SSWU_RO_` | SM3 | 33 |
| FourQ | `FourQ-SHA256`（自定义） | 本库 `FourQ_XMD:SHA-256_ELL2_RO_` | SHA-256 | 32 |

- 上下文串 `contextString = "OPRFV1-" ‖ 0x00 ‖ "-" ‖ 套件 ID`，HashToGroup 的 DST 为 `"HashToGroup-" ‖ contextString`，与 RFC 9497 一致。
- 元素长度上限 65535 字节（Finalize 用 2 字节长度前缀），超过时创建会话就报错。
- 标量求逆：Ristretto255、P-256、SM2 用各自 crate 的常量时间实现；FourQ 用 `crypto-bigint` 的常量时间 safegcd（Bernstein–Yang）。
- 曲线选择与 ECDH-PSI 相同，见 [psi.md「曲线选择」](psi.md#曲线选择)。

## 性能

**理论开销**（与 ECDH-PSI 对比）：

| | ECDH-PSI | OPRF-PSI |
| --- | --- | --- |
| 接收方计算 | $n$ 次 hash + $n + m$ 次标量乘 | $n$ 次 hash + $2n$ 次标量乘 + 1 次求逆 |
| 发送方计算 | $m$ 次 hash + $n + m$ 次标量乘 | $m$ 次 hash + $n + m$ 次标量乘 |
| R → S | $n$ 个点 | $n$ 个点 |
| S → R | $n \cdot t$ 字节 + $m$ 个点 | $n$ 个点 + $m \cdot t$ 字节 |

**实测**：Apple M5（10 核），双方各一个进程，通过本机 TCP 通信，每方 5 线程，每个方向限速 100 Mbps，Ristretto255（VOLE 不用曲线），数据为 11 位数字字符串，不分桶，接收方的元素全部在交集中。

| 协议 | 规模（接收方 × 发送方） | 耗时（接收方） | R → S | S → R | 峰值内存（R / S） |
| --- | --- | --- | --- | --- | --- |
| VOLE-PSI | 1 万 × 1000 万 | 14.2 s | 0.9 MiB | 96.3 MiB | 0.52 / 2.37 GiB |
| OPRF-PSI | 1 万 × 1000 万 | 83.7 s | 0.3 MiB | 95.7 MiB | 0.20 / 1.69 GiB |
| ECDH-PSI | 1 万 × 1000 万 | 149.3 s | 0.3 MiB | 305.3 MiB | 0.97 / 2.85 GiB |

- OPRF-PSI 一行通过 C ABI 直接驱动，另外两行通过 Python `Psi` 驱动（`bucket_size=None`）。Python 层的列表输入会多占一份内存，所以内存一列不完全可比。
- OPRF-PSI 的耗时主要是发送方的 $m$ 次 hash-to-group 和标量乘；VOLE-PSI 的发送方每个元素只做哈希和 OKVS 解码。
- 用 `Psi` 默认分桶（每桶 100 万）时，发送方内存应接近单桶的规模（未实测）。

## 依据

各组件的依据、类型和验证方式见 [psi.md「OPRF-PSI 的组件」](psi.md#oprf-psi-的组件)。要点：Ristretto255、P-256 两个套件用 RFC 9497 附录 A.1.1、A.3.1 的测试向量逐项验证了 Blind、BlindEvaluate 和 Finalize（`primitives/oprf.rs` 的 `rfc9497_*` 测试）；SM2、FourQ 套件是本库自定义的。

## 安全性

安全模型、泄露的信息和使用注意见 [psi.md「安全性」](psi.md#安全性)，以下只写 OPRF-PSI 特有的部分：

- 发送方的 $f_j$ 在接收方没有 $k$ 时与随机值不可区分；接收方只能通过发送方求值，得到自己 $n$ 个元素的 $F_k$。
- 发送方从消息 1 只得到 $n$ 个被同一个随机标量盲化的点，不知道接收方的元素。
- 每次会话（每个桶）都用新密钥，不同会话的标签互相无关。将来的离线缓存模式会用长期密钥，那时需要额外限制查询次数，并定期轮换密钥（规划中，见 [optimization.md](../optimization.md)）。
- 与另外两种协议相同，半诚实模型下不防止接收方在消息 1 里放入任意元素；需要限制查询的元素时，应由平台控制接收方的输入。

## 接口

入口与 ECDH-PSI 相同，只是协议参数不同，见 [psi.md「接口」](psi.md#接口)：Rust `algorithms::psi::oprf::{Sender, Receiver}`，C ABI `cryptex_psi_new(CRYPTEX_PSI_OPRF = 2, …)`（`share` 必须为 0），Python `Psi(Protocol.OPRF, …)`、`PsiParty(Protocol.OPRF, …)`。

## 参考文献

- S. Jarecki, A. Kiayias, H. Krawczyk. *Round-Optimal Password-Protected Secret Sharing and T-PAKE in the Password-Only Model*. ASIACRYPT 2014.（2HashDH）
- RFC 9497. *Oblivious Pseudorandom Functions (OPRFs) Using Prime-Order Groups*. 2023.
- D. J. Bernstein, B.-Y. Yang. *Fast constant-time gcd computation and modular inversion*. TCHES 2019.
