# Cryptex Python 绑定

基于 ctypes 封装 cryptex 核心库。本文只讲 **Python 怎么用**：参数、数据输入、通信接入、分桶、日志、并发和底层接口。

- 协议原理、消息格式、安全性、完整性能数据：见 [`docs/algorithm/psi.md`](../../docs/algorithm/psi.md)；OPRF-PSI 见 [`docs/algorithm/psi-oprf.md`](../../docs/algorithm/psi-oprf.md)；匿踪查询见 [`docs/algorithm/pir.md`](../../docs/algorithm/pir.md)
- 项目概况和构建：见[根目录 README](../../README.md)

## 安装

```bash
# 先构建 Rust 核心库
cd ../../core
cargo build --release

# 再安装 Python 包
cd ../bindings/python
pip install -e .
```

## PSI（隐私集合求交）

目前只支持半诚实模型。参与方分两种角色：

- 接收方（`Role.RECEIVER`）：得到交集，是协议的发起方。
- 发送方（`Role.SENDER`）：默认什么也得不到；双方都设置 `share_result=True` 时也得到交集。

选哪种协议见[根目录 README 的选型建议](../../README.md#支持的算法)。

### 基本用法

创建 `Psi` 时传入协议参数和通道，调用 `run` 时传入数据或数据文件：

```python
from cryptex import Curve, Protocol, Psi, Role

psi = Psi(Protocol.ECDH, Role.RECEIVER, channel, curve=Curve.SM2)

common = psi.run(["alice", "bob", "carol"])           # 列表
common = psi.run("ids.txt")                           # 文本文件，每行一个
common = psi.run("users.csv", column="phone")         # CSV，按列名取
common = psi.run("users.csv", column=0)               # CSV，按列序号取（从 0 开始）
count = psi.run("ids.txt", output="result.txt")       # 交集写入文件，返回条数
```

**`Psi(...)` 的参数**

| 参数 | 说明 |
| --- | --- |
| `protocol` | `Protocol.ECDH`、`Protocol.VOLE` 或 `Protocol.OPRF`（非平衡场景、要求国密时用，小集合方做接收方） |
| `role` | `Role.RECEIVER` 或 `Role.SENDER`，双方必须不同 |
| `channel` | 到对端的通道，见下文“通信方式” |
| `curve` | ECDH、OPRF 使用的曲线：`RISTRETTO255`（默认）、`P256`、`SM2`、`FOURQ`，双方必须一致。VOLE 忽略此参数 |
| `share_result` | 是否让发送方也得到交集，默认 `False`（只有接收方得到）。双方必须一致，握手时检查。OPRF 不支持 |
| `handshake` | 是否先交换会话头校验配置，默认 `True`，双方设置必须一致 |
| `threads` | 计算用的并发线程数。默认 `0`：所有实例共用一个线程池，线程数等于 CPU 核数。设为 `n`：该实例使用独立的 `n` 线程池，上限 1024。双方可以设置不同的值 |
| `bucket_size` | 每个桶大约放多少个元素，默认 `1_000_000`（`DEFAULT_BUCKET_SIZE`）。双方数据都不超过这个数时只有一个桶，直接在内存里处理，不写临时文件。传 `None` 关闭分桶，整个集合在内存里处理。双方要么都分桶，要么都不分桶。`handshake=False` 时默认值自动变为 `None` |
| `bucket_hash` | 分桶用的哈希：`BucketHash.SHA256`（默认）或 `BucketHash.SM3`。双方必须一致 |
| `work_dir` | 存放临时桶文件的目录，默认是系统临时目录 |
| `on_bucket` | 可选回调 `on_bucket(桶号, 桶总数, 本桶元素数)`，每个桶算完后调用一次，可用于显示进度 |
| `log_file` | 日志文件路径，追加写入，UTF-8。不传时日志交给标准 `logging`，记录器名为 `cryptex.psi` |
| `log_level` | 日志级别，如 `logging.DEBUG` 或 `"INFO"`。指定了 `log_file` 时默认 `INFO` |

参数在创建时就会校验，非法值直接抛出异常。

**非平衡场景（OPRF-PSI）**

双方集合大小悬殊时，让小集合方做接收方。不要求国密时直接用 `Protocol.VOLE`，它在非平衡场景下也最快；要求国密时用 `Protocol.OPRF` 加 `curve=Curve.SM2`：

```python
# 接收方：1 万条
common = Psi(Protocol.OPRF, Role.RECEIVER, channel, curve=Curve.SM2).run("small.txt")
# 发送方：1000 万条
Psi(Protocol.OPRF, Role.SENDER, channel, curve=Curve.SM2).run("large.txt")
```

用法和 ECDH 完全相同（分桶、文件输入、`output` 都支持），底层也可以用 `PsiParty(Protocol.OPRF, ...)` 逐步驱动。不支持 `share_result`。元素长度不能超过 65535 字节。

**并发**

```python
psi = Psi(Protocol.ECDH, Role.RECEIVER, channel, threads=8)
```

- 需要限制 CPU 占用时（比如和其他服务部署在同一台机器上），设置 `threads`。
- 多个 `Psi` 实例可以在不同线程里同时运行，比如同时和多个对端求交。这时建议给每个实例设一个较小的 `threads`，避免争抢 CPU。
- 同一个实例不要在多个线程里同时调用 `run`。
- 计算结果和线程数无关。

**分桶（默认开启，每桶 100 万）**

```python
psi = Psi(Protocol.ECDH, Role.RECEIVER, channel, curve=Curve.SM2,
          bucket_size=100_000, bucket_hash=BucketHash.SM3, work_dir="/data/psi-tmp",
          on_bucket=lambda i, n, size: print(f"{i + 1}/{n}"))
count = psi.run("ids.csv", column="phone", output="result.txt")
```

默认就是分桶模式，每桶约 100 万个元素。内存紧张时调小 `bucket_size`，比如 `100_000`。双方数据都不超过 `bucket_size` 时只有一个桶，这时直接在内存里处理，不写临时文件。各档位的实测内存见 [psi.md「内存」](../../docs/algorithm/psi.md#内存)。

使用上要注意：

- 结果和不分桶时完全一样，顺序也是接收方的输入顺序。
- 输入文件是流式读取的。接收方的输入文件会读两遍，这期间文件不能被修改；如果变了会报错，不会输出错误的结果。
- 分桶、去重和结果回写都在核心库里完成。输入是 UTF-8 文本文件（`encoding` 为默认的 `utf-8-sig` 或 `utf-8`，不指定 `column`）时最快：文件由核心库直接读取，数据不经过 Python。CSV 列、其他编码和列表输入会先在 Python 里逐条读出，再成批交给核心库。
- 磁盘占用大约等于输入数据的大小，再加每条 12 字节。临时文件里是**明文数据**，`work_dir` 要放在可信的磁盘上。任务结束或出错时会自动删除。
- 数据量是根据文件开头 4 MiB 估算的，所以桶的实际大小会在 `bucket_size` 上下浮动。
- 双方的 `bucket_hash` 必须一致；只有一方分桶会直接报错；分桶要求开启握手。
- `bucket_size` 不要设得太小：对方会知道你每个桶的元素个数，桶越多暴露的分布越细。
- 需要自己计算桶号时用 `bucket_of(items, buckets, hash)`。

桶数怎么算、桶号规则、误判率怎么保持、额外泄露了什么，见 [psi.md「分桶」](../../docs/algorithm/psi.md#分桶)。

**日志**

```python
psi = Psi(Protocol.ECDH, Role.RECEIVER, channel,
          log_file="/var/log/psi/receiver.log", log_level="DEBUG")
...
psi.close()          # 或者用 with Psi(...) as psi:，关闭日志文件
```

- `INFO` 级别记录：
  - **输入和输出**：参与计算的文件名、ID 列（CSV 的列名或序号、表头、分隔符、编码），或“内存列表”；结果写到哪个文件。
  - **进行到哪一步**：`step 2/4: partition input into 3 buckets under …`。步骤依次是读入或握手、分桶落盘、PSI、写结果，按实际配置编号。
  - **PSI 进度**：分桶时每完成一个桶记一条 `PSI bucket 3/10 done (30%)`，最多约 100 条。
  - 协议、角色、曲线、是否结果共享、线程数、`bucket_size`、元素个数、桶数、耗时、交集大小。
  - 出错时记录 `ERROR`：在哪一步失败（`failed in step 'handshake'`），带完整调用栈。
- `DEBUG` 级别额外记录**每条收发的消息是什么**：消息类型和方向、各部分的条数和每条字节数，以及前 2 条值的前 8 字节示例，例如：

  ```
  sent 31978 bytes: ECDH msg1 R→S [receiver's items, blinded H(x)^a]: 999 points × 32 B, share_result=False (e.g. #0 aa926b2edba5e477…; #1 f20c316e8f609357…, … 997 more)
  received 55818 bytes: ECDH msg2 S→R [receiver's items re-blinded, tags T(H(x)^ab)]: 999 tags × 8 B (e.g. …); [sender's items, blinded H(y)^b, shuffled]: 1494 points × 32 B (e.g. …)
  received 385785 bytes: VOLE Ferret iteration 1 S→R [silent OT]: 385776 B
  sent 22 bytes: session header [v4 protocol=0 role=1 curve=0 bucket_hash=0 share_result=False bucket_size=2000 items=3000]
  ```

  示例值是盲化后的点、截断的伪随机标签或 OT/VOLE 数据，没有对应的密钥就无法还原元素，密钥从不写入日志。此外还记录每一步的计算耗时、每个桶的元素数和命中数。
- 每个实例的日志相互独立。指定了 `log_file` 后，记录只写入这个文件，不会再传给应用的根记录器。
- 日志中**不会出现**任何元素或交集的内容，但会有元素个数、交集大小、每桶命中数（`DEBUG`）、文件路径，出错时还可能有 CSV 列名。日志文件会流转给第三方时，用 `INFO` 级别并限制访问权限。
- 不传 `log_file` 时，用法和普通 Python 库一样，由应用自己配置，例如 `logging.basicConfig(level=logging.INFO)`。

**`run(...)` 的参数**

| 参数 | 说明 |
| --- | --- |
| `data` | `str`/`bytes` 组成的列表或可迭代对象，或者文件路径（`str`、`Path`） |
| `column` | 不传时按文本文件读，每行一个元素；传入时按 CSV 读，取这一列。可以是列名，也可以是从 0 开始的序号 |
| `has_header` | CSV 是否有表头，默认 `True`。按列名取值时必须有表头 |
| `delimiter` | CSV 分隔符，默认 `,`，TSV 文件传 `"\t"` |
| `encoding` | 文件编码，默认 UTF-8（会自动去掉 BOM）。GBK 文件传 `"gbk"` |
| `output` | 把交集流式写入这个文件，每行一个，UTF-8 编码。传了之后 `run` 返回交集条数。接收方可用；发送方只在 `share_result=True` 时可用 |

**返回值**：接收方返回自己数据中属于交集的元素，顺序与输入一致；传了 `output` 时返回交集条数。发送方返回 `None`；`share_result=True` 时和接收方一样，返回自己数据中属于交集的元素。

**数据预处理**

- 文件中每个值会去掉首尾空白，空行和空单元格会被跳过。
- 重复元素会被去掉，只保留第一次出现的。`"a"` 和 `b"a"` 编码后相同，视为重复。
- 元素按字节比较，大小写、全角半角都不会自动统一。双方需要按同样的规则清洗数据，比如手机号统一去掉 `+86`。

一个 `Psi` 实例可以多次调用 `run`，每次是一轮独立的 PSI。对端也要调用同样的次数，顺序一一对应。

**让发送方也得到结果**

双方都传 `share_result=True`，发送方的 `run` 也会返回交集（以发送方自己的数据表示，顺序与它的输入一致），同样可以用 `output` 写文件：

```python
# 接收方
common = Psi(Protocol.VOLE, Role.RECEIVER, channel, share_result=True).run("a.txt")

# 发送方
count = Psi(Protocol.VOLE, Role.SENDER, channel, share_result=True).run(
    "b.txt", output="result.txt")
```

只有一方开启时，握手阶段双方都会报 `share_result mismatch`。发送方相信接收方如实报告结果（半诚实）。原理和开销见 [psi.md「结果共享」](../../docs/algorithm/psi.md#结果共享)。

### 通信方式：由调用方决定

库本身不做网络 IO，也不绑定任何传输协议。PSI 消息就是一段段字节，怎么送到对端由调用方决定，可以用平台自己的 HTTP、gRPC、消息队列、RPC 框架等。

有三种接入方式。

**方式一：`CallbackChannel`，直接传入平台的收发函数**

```python
from cryptex import CallbackChannel, Curve, Protocol, Psi, Role

ch = CallbackChannel(send=platform.send_bytes, recv=platform.recv_bytes)
psi = Psi(Protocol.ECDH, Role.RECEIVER, ch, curve=Curve.SM2)
common = psi.run("ids.txt")
```

**方式二：自己实现通道类**

只要对象有 `send(bytes)` 和 `recv() -> bytes` 两个方法，就可以作为 `Psi` 的 `channel`，不需要继承任何基类。`cryptex.Channel` 是对应的 `typing.Protocol`，可以拿来做类型检查。

**方式三：事件驱动（不阻塞）**

`Psi.run` 会阻塞，直到协议结束。如果平台是回调式、不能阻塞等待（比如 HTTP 回调、异步框架），就直接驱动底层对象。这种用法下，读文件、去重、分桶都要自己做；分桶可以用 `bucket_of`。

- **ECDH-PSI、OPRF-PSI**：用 `PsiParty`，消息严格一来一回。

  ```python
  from cryptex import Protocol, PsiParty, Role

  with PsiParty(Protocol.ECDH, Role.RECEIVER, items) as party:
      msg, done = party.step(None)      # 发起方第一步不传消息
      while True:
          if not done or msg:
              send_to_peer(msg)         # 协议中途的空消息也要发出去
          if done:
              break
          msg, done = party.step(recv_from_peer())
      common = party.result()
  ```

  发送方不是发起方，它的第一步要传入对端发来的第一条消息。调用顺序不对会抛出 `ERR_INVALID_STATE`。任何一步出错之后，会话都不能再用。

  双方都传 `share=True` 时，接收方的最后一步会返回一条发给发送方的消息；发送方处理它之后 `done` 为真，可以调用 `result()`。

- **VOLE-PSI**：用 `VoleJob`。一个任务覆盖所有桶，消息是**全双工**的，双方随时都可能发送，没有固定的先后顺序。`VoleJob` 的方法都不会阻塞：

  ```python
  from cryptex import JobRole, VoleJob

  job = VoleJob(JobRole.RECEIVER, sizes)     # sizes[b]：第 b 个桶的元素个数（已去重）

  def pump():                                # 每次有进展后调用
      while (b := job.need()) is not None:
          job.provide(b, buckets[b])         # 按桶号顺序提供
      while (msg := job.next_send()) is not None:
          send_to_peer(msg)
      while (r := job.take_result()) is not None:
          bucket, indices = r                # 下标指向该桶提供的元素

  def on_message(msg):                       # 平台收到对端消息时回调
      job.receive(msg)
      pump()

  pump()
  # job.done 为 True 时结束
  ```

  同一个 `VoleJob` 的方法不能被多个线程同时调用，需要加锁。双方都传 `share=True` 时，发送方也能用 `take_result()` 拿到每个桶的结果。

可运行的示例见 [`examples/queue_transport.py`](examples/queue_transport.py)。

### 通道必须满足的要求

- **保持消息边界**：一次 `send` 对应对端一次 `recv`，拿到完整的同一段字节。基于流的传输（TCP、管道）需要自己加长度前缀。
- **保持顺序**：消息按发送顺序到达。
- **空消息也要传**：协议中途可能产生 `b""`，必须当作一条真实消息送达。
- **全双工（VOLE-PSI）**：`Psi` 运行 VOLE-PSI 时，会用一个后台线程调用 `recv`，同时在主线程调用 `send`。通道必须允许这两个调用同时进行。`TcpChannel`、`MemoryChannel` 都满足；只能“一问一答”的平台通道，请用方式三的 `VoleJob`。
- **`recv` 阻塞**：收到消息才返回，超时或断开时抛异常，不要返回 `None`。
- **安全**：消息本身不加密、不认证。链路的认证与加密（TLS、mTLS、平台签名）由传输层负责。

### 会话握手

`Psi` 默认在协议开始前先交换一个会话头，双方配置不一致（角色相同、协议或曲线不同、`share_result` 不同、只有一方分桶、分桶哈希不同、版本不兼容）时会直接报错，不会进入密码学流程。会话头的字段见 [psi.md「角色与会话」](../../docs/algorithm/psi.md#角色与会话)。

双方的 `handshake` 设置必须一致。如果平台已经在别处协商好了这些参数，可以双方都传 `handshake=False` 跳过，但这样就不能分桶。方式三不做握手。

### 参考实现：TcpChannel

如果没有现成的通信方式，可以用内置的 `TcpChannel`。谁监听端口、谁去连接，和 PSI 角色无关。

```python
from cryptex import Curve, Protocol, Psi, Role, TcpChannel

# 机器 A：接收方，监听 9000 端口
with TcpChannel.listen("0.0.0.0", 9000, timeout=60) as ch:
    common = Psi(Protocol.ECDH, Role.RECEIVER, ch, curve=Curve.SM2).run("ids.txt")

# 机器 B：发送方，连接 A
with TcpChannel.connect("host-a", 9000, timeout=60) as ch:
    Psi(Protocol.ECDH, Role.SENDER, ch, curve=Curve.SM2).run("ids.txt")
```

- `listen` 只接受一个对端连接。`port=0` 表示自动选一个空闲端口，选中的端口号通过 `on_listening` 回调拿到。
- `connect` 在超时之前会一直重试，所以双方不用关心谁先启动。
- `timeout` 既是建立连接的超时，也是之后每次收发的超时。
- 每条消息前面带 8 字节大端长度，单条消息上限默认 1 GiB（`max_message_size`），防止对端发来畸形长度把内存耗尽。
- `TcpChannel` 是明文 TCP，不做身份认证。在不可信网络上应放在 TLS 或 VPN 之后，只监听内网地址，不要直接把端口暴露到公网。

## 匿踪查询（PIR）

客户端用一批关键词查询服务端的“键 → 标签”库，得到命中关键词的标签；服务端只知道关键词落在哪些桶。原理、泄露分析（包括更新带来的泄露）见 [`docs/algorithm/pir.md`](../../docs/algorithm/pir.md)。

### 写入数据库（服务端，离线，可增量）

数据库是一个目录。首次写入和之后的增删改用同一套接口：

```python
from cryptex import Curve, PirDatabase
from cryptex.pir import csv_metadata, generate_seed

seed = generate_seed()   # 32 字节长期秘密，自行保管（如 KMS），写入和服务都要用

# 新建
with PirDatabase.create("users.pir", seed, curve=Curve.SM2,
                        metadata=csv_metadata("users.csv", key_column="phone")) as db:
    db.load("users.csv", key_column="phone")          # 其余列作为标签，自动提交

# 之后增量修改
with PirDatabase("users.pir", seed) as db:
    db.upsert({"13800000003": "王五,深圳"})             # 新增或覆盖
    db.delete(["13800000001"])
    db.commit()                                        # 一起生效
    db.compact()                                       # 可选：合并段，清掉已删除和被覆盖的记录
```

| 方法 | 说明 |
| --- | --- |
| `PirDatabase.create(dir, seed, curve=, metadata=)` | 新建数据库。目录不存在时会创建；已存在时必须为空。`metadata` 会原样交给客户端 |
| `PirDatabase(dir, seed)` | 打开已有数据库写入。同一目录同时只能有一个写入方 |
| `upsert(data)` | 新增或覆盖记录。`data` 为 dict 或 `(键, 标签)` 序列，str 或 bytes 均可；标签长度任意。标签很大时注意 `padding`，见下文 |
| `delete(keys)` | 按键删除，不存在的键忽略 |
| `load(csv, key_column=, label_columns=, ...)` | 读 CSV 并写入：标签列（默认为键列以外的所有列）按 CSV 的一行编码。默认写完即提交 |
| `commit()` / `rollback()` | 提交 / 丢弃上次提交之后的操作。同一批里，对同一个键的最后一次操作生效 |
| `compact()` | 合并所有段，丢掉已删除和被覆盖的记录，修正记录数和最长标签 |
| `info` / `pending` | 已提交的状态（`DbInfo`）/ 未提交的操作数 |

批次很大时，操作会落到数据库目录下的临时文件里，不会一直占内存。

### 服务与查询

```python
from cryptex import Padding, PirClient, PirServer

# 服务端：打开一次，每个连接调用一次 serve（可以多线程同时调用）
server = PirServer("users.pir", seed, bucket_size=1024, padding=Padding.MAX,
                   max_keywords=100_000)
server.serve(channel)
server.reload()            # 写入方提交后，切换到新数据；正在进行的查询不受影响

# 客户端
client = PirClient(channel, curve=Curve.SM2)            # curve 可选，用来拒绝曲线不符的服务端
labels = client.query(["13800000001", "13900000000"])   # [b"...", None]，与输入一一对应
hits = client.query_file("phones.txt", "result.csv")    # 命中的写成 CSV：键 + 标签列
```

| `PirServer` 参数 | 说明 |
| --- | --- |
| `bucket_size` | 每桶大约多少条，默认 1024。桶数取 2 的幂，每个关键词的匿名集约为一个桶的大小，客户端也按桶下载 |
| `padding` | `Padding.MAX`（默认）：标签补到最长标签的长度，客户端看不到标签长度。库里有一条很大的标签时，所有记录都会补到这么大，下载量随之放大。`Padding.NONE`：按真实长度下发，省流量，但客户端能看到所下载记录的标签长度 |
| `max_keywords` | 一次查询最多多少个不同关键词，超过时在计算前拒绝，客户端收到 `ConnectionError` |
| `threads` / `pool` | 并发线程，同 `Psi` |

- 一次 `serve` / `query` 是一次查询，两来两回，最后若干条消息下发记录，单条约 4 MiB。
- 通道要求与 PSI 相同，见上文“通信方式”。
- 日志记录器为 `cryptex.pir`，只记录数量和耗时，不记录关键词和标签。

可运行的示例见 [`examples/pir_tcp.py`](examples/pir_tcp.py)：从 CSV 建库，做一次增量修改，再通过 TCP 查询。

## 动态库查找顺序

1. `Cryptex(lib_path=...)` 传入的路径
2. 环境变量 `CRYPTEX_LIB`
3. 包内 `cryptex/lib/` 目录
4. `core/target/release/` 目录

## 测试

```bash
python3 -m unittest discover -s tests -v
```

## 环境要求

- Python 3.8+
- cryptex 核心库
