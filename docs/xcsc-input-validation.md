# xcsc 输入校验

xssc 作为客户端工具只消费一个 `xcsc` Cargo 包，启用 `offline-maintenance` 特性，固定官方 URL `https://github.com/isarmg/xcsc`、精确版本 `=1.0.3` 和完整提交修订 `5641a33e991209eecdbbc91cffaa3be545875757`。`xcsc::contracts`、`xcsc::state_file`、`xcsc::fs_safety`、`xcsc::log` 和 `xcsc::sqlite` 是包内模块。Cargo 正常、build、dev 与锁文件输入对应同一个正式客户端公共包。

`xcsc-client.toml`、`Cargo.toml` 与根 `Cargo.lock` 必须表达同一来源和客户端角色。`offline-maintenance` 仅为 Linux 离线管理提供状态锁、文件安全、日志和有界 SQLite 支持；工具拥有升级编排、签名策略、快照和恢复状态机。离线维护遵循被维护产品给出的真实持久状态合同。

CI 和发行版本的客户端来源任务检出完整提交修订的官方 xcsc，运行其 `scripts/check-xcsc.py`。检查既验证客户端产品 ID，也验证实际锁图，不接受本地路径替代正式来源。

取得上述完整提交修订的官方 xcsc 源码后，本地复核命令：

```sh
cargo metadata --locked --format-version 1
python3 /absolute/path/to/xcsc/scripts/check-xcsc.py --product-root /absolute/path/to/xssc
```

第一条命令读取真实 Cargo.lock 依赖图，不更新锁文件；第二条运行与 CI 相同的官方客户端角色和来源校验，确认产品描述、版本、提交修订和实际依赖图一致。历史原始输入记录另存工作区审计备份，不作为当前 xcsc 或产品签名资产的验收证据。当前产品按最终源码独立通过原生测试、签名发行和解包验证。
