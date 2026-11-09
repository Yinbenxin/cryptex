# 示例

| 文件 | 内容 |
| --- | --- |
| [queue_transport.py](queue_transport.py) | 用消息队列模拟平台自己的通信方式，演示两种接入写法：`CallbackChannel` 传入收发函数、自己实现通道类 |
| [pir_tcp.py](pir_tcp.py) | 匿踪查询（PIR）：从 CSV 建库，做一次增量修改（更新、新增、删除各一条），再通过 `TcpChannel` 查询一批手机号，命中结果写成 CSV |

## 运行

```bash
cd ../../../core && cargo build --release && cd -
PYTHONPATH=.. python3 queue_transport.py
PYTHONPATH=.. python3 pir_tcp.py
```

`queue_transport.py` 的预期输出：

```
intersection seen by the receiver: ['bob', 'carol']
```

`pir_tcp.py` 的预期输出（13800000002 已更新，13800000003 已删除，13800000004 是新增的）：

```
database: ~4 records in 2 segments
3 of 5 keywords found:
key,name,city
13800000001,张三,北京
13800000002,李四,深圳
13800000004,赵六,杭州
```

`~4` 是合并前的估算值：更新的记录在两个段里各算一次，删除记一次减法，`compact()` 之后才是准确数。

接入方式、通道必须满足的要求、握手的规则，见 [Python 绑定文档的「通信方式」](../README.md#通信方式由调用方决定)；PIR 的参数见 [「匿踪查询（PIR）」](../README.md#匿踪查询pir)。
