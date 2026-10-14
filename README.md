# xssc

XSSC 是六个 server 的升级与恢复核心，升级脚本由独立的 XSSI 仓库提供。它没有常驻服务，也不被 server 运行时调用。

用户运行已安装 ROOT 中的 `upgrade.sh --root /absolute/ROOT --version N.N.N`。脚本先下载并验证新版本，然后自动停止全部写入服务；XSSC 在独占维护下检查数据、备份、调用独立辅助程序只读检查源与目标当前结构、替换程序并启动服务，最后核验实际运行文件摘要和 `/readyz`。

仅支持 Linux x86_64 GNU 和 systemd。发行校验使用 SHA256 清单及逐文件摘要；业务所需的 TLS 与密码保护由对应服务和辅助程序处理。六个产品使用唯一的固定 ROOT 包合同；不接受旧布局、旧升级清单、旧 CLI 或旧数据格式。安装与离线管理见独立的 [XSSI 仓库](https://github.com/isarmg/xssi)，卸载由用户处理。

```sh
cargo build --locked --release
./target/release/xssc support --json
./target/release/xssc apply-upgrade --help
```

核心仍提供 `apply-upgrade --plan PATH`、`inspect-upgrade --work-directory PATH` 和 `recover-upgrade --work-directory PATH`。日常升级由 XSSI 脚本生成计划，无需手工重复配置路径。恢复默认保护服务可能启动后产生的新增写入；`--allow-data-loss` 只用于用户明确授权的数据恢复。

[操作文档](docs/README.md)
