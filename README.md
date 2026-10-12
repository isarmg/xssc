# xssc

xssc 是服务端离线升级命令行工具，用于验证受签名发行物、执行当前合同下的软件切换，并在失败时按持久记录恢复。

## 项目功能

- 校验独立信任锚、签名、源码身份和完整发行目录。
- 在停服和独占维护条件下保护配置、数据库与媒体等持久资源。
- 记录升级阶段，检查事务状态，执行受控恢复与业务就绪验收。

## 适用平台

仅支持 Linux x86_64 GNU（glibc）；需要本机 systemd、支持 Ed25519 的 `/usr/bin/openssl`、Zstandard 和校验工具。无需配对，没有常驻服务。

## 快速部署

下载 [v1.0.3 发行包及校验文件](https://github.com/isarmg/xssc/releases/tag/v1.0.3)，在独立空目录中执行：

```sh
set -eu
sha256sum --check xssc-1.0.3-linux-x86_64.tar.zst.sha256
mkdir xssc-1.0.3
tar --zstd -xf xssc-1.0.3-linux-x86_64.tar.zst --no-same-owner -C xssc-1.0.3
cd xssc-1.0.3
# 必须从独立可信渠道取得指纹，不使用包内自报值。
EXPECTED_KEY_SHA256='替换为可信发行公钥的64位小写DER-SHA256指纹'
ACTUAL_KEY_SHA256=$(/usr/bin/openssl pkey -pubin -in RELEASE-SIGNING-PUBLIC.pem -outform DER | sha256sum | cut -d ' ' -f 1)
test "$ACTUAL_KEY_SHA256" = "$EXPECTED_KEY_SHA256"
/usr/bin/openssl pkeyutl -verify -rawin -pubin -inkey RELEASE-SIGNING-PUBLIC.pem -in SHA256SUMS -sigfile SHA256SUMS.sig
sha256sum --check SHA256SUMS
sudo install -o root -g root -m 0755 bin/xssc /usr/local/bin/xssc
/usr/local/bin/xssc support --json
/usr/local/bin/xssc apply-upgrade --help
```

保留完整包中的文档与发行身份。实际升级前按详细文档准备私有计划、产品签名信任锚并停止全部相关写入进程，再运行 `xssc apply-upgrade --plan /absolute/private/plan.json`。恢复默认保护交接运行权后的新增写入；不要把 `--allow-data-loss` 用作常规重试。

## 编译部署

准备 Rust `1.99.0`、C 编译工具链及上述运行依赖，在仓库根目录执行：

```sh
cargo build --release --locked
./target/release/xssc support --json
./target/release/xssc apply-upgrade --help
```

这是未绑定正式发行源码身份的开发构建，用于开发验证。生产部署使用完成签名和验收的发行包；自行制作正式包须按文档执行源码身份绑定、完整包构建与签名流程。

[详细文档](docs/README.md)
