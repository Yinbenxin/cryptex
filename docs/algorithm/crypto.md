# 加密工具

> 状态：**规划中**。`core/src/algorithms/crypto/` 只有空模块，尚无 FFI 和 Python 接口。

## 概述

提供不容易用错的常用密码学接口。原始的分组运算、ECB 这类危险用法只留在 `primitives` 内部，不对外暴露。

| 类别 | 算法 | 模块 |
| --- | --- | --- |
| 哈希 | SHA-256、SM3 | `algorithms/crypto/hash.rs` |
| 对称加密（AEAD） | AES-GCM、SM4-GCM | `algorithms/crypto/symmetric.rs` |
| 数字签名 | ECDSA P-256、SM2 | `algorithms/crypto/signature.rs` |

## 设计原则

- **只提供认证加密**：对称加密只提供 AEAD，不提供 CBC、CTR 等没有完整性保护的模式。
- **nonce 由库生成**：加密时库内随机生成 nonce，并放在密文开头，调用方不需要管理。GCM 的 nonce 一旦重复，就会同时破坏机密性和完整性。
- **常量时间比较**：标签和签名的校验使用常量时间比较。
- **密钥清零**：密钥对象释放时清零内存。

## 哈希

| 算法 | 输出长度 | 标准 |
| --- | --- | --- |
| SHA-256 | 32 字节 | FIPS 180-4 |
| SM3 | 32 字节 | GB/T 32905-2016 |

## 对称加密

| 算法 | 密钥 | nonce | 标签 | 标准 |
| --- | --- | --- | --- | --- |
| AES-128-GCM / AES-256-GCM | 16 / 32 字节 | 12 字节 | 16 字节 | NIST SP 800-38D |
| SM4-GCM | 16 字节 | 12 字节 | 16 字节 | GB/T 32907-2016、RFC 8998 |

密文格式（待定）：`nonce ‖ ciphertext ‖ tag`。

随机 nonce 只有 96 位，同一个密钥加密的消息数应控制在 $2^{32}$ 条以内。

## 数字签名

| 算法 | 哈希 | 标准 |
| --- | --- | --- |
| ECDSA P-256 | SHA-256 | FIPS 186-5 |
| SM2 签名 | SM3 | GB/T 32918.2-2016 |

SM2 签名会对用户标识 ID 求杂凑值 $Z_A$。没有特别约定时，ID 取默认值 `1234567812345678`（GB/T 35276-2017）。签名方和验签方必须使用同一个 ID。

签名编码格式（DER 或 `r ‖ s` 定长）待定。

## 底层算子

| 算子 | 模块 |
| --- | --- |
| SHA-256、SM3 | `primitives/hash/` |
| AES、SM4 | `primitives/cipher/` |
| P-256、SM2 曲线 | `primitives/ec/` |
| 随机数 | `primitives/rand.rs` |

## 参考文献

- FIPS 180-4 *Secure Hash Standard*
- FIPS 186-5 *Digital Signature Standard*
- NIST SP 800-38D *Galois/Counter Mode (GCM) and GMAC*
- RFC 8998 *ShangMi (SM) Cipher Suites for TLS 1.3*
- GB/T 32905-2016《SM3 密码杂凑算法》
- GB/T 32907-2016《SM4 分组密码算法》
- GB/T 32918-2016《SM2 椭圆曲线公钥密码算法》
- GB/T 35276-2017《SM2 密码算法使用规范》
