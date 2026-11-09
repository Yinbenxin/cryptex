# Cryptex Go 绑定（暂缓）

目前只封装了 `cryptex_version`，没有 PSI 接口，暂不维护。需要使用 PSI 请用 [Python 绑定](../python/README.md)。

构建方法：

```bash
cd ../../core && cargo build --release
cd ../bindings/go && go build
```

运行前需要能找到动态库，比如在 Linux 上设置 `LD_LIBRARY_PATH`，在 macOS 上设置 `DYLD_LIBRARY_PATH`，指向 `core/target/release`。
