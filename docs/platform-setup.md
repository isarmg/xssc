# xssc 安装、检查与卸载

适用于 `xssc 1.0.3`。当前只发布 **Linux x86_64 GNU** 命令行工具，用于本机 systemd 管理的服务端离线升级；没有 Windows、macOS、Android 或 iOS 执行包。需要 Linux x86_64 主机、GNU 用户空间、systemd，以及支持 Ed25519 的 `/usr/bin/openssl`。六个服务端的升级条件和完整恢复合同见[离线升级与恢复](offline-upgrades.md)。

xssc 不连接客户端账户，**无需配对或重新配对**；产品签名公钥、独立可信指纹和私有升级计划决定授权范围。公钥轮换应由发布者提供新的可信发行与信任说明，不用客户端实例授权码替代。xssc 也**没有常驻服务、开机启动项或 `service start/stop` 命令**。下文区分工具进程与被维护的服务端服务。

## 1. 检查平台并安装依赖

先在服务端所在主机执行只读检查：

~~~sh
# 核对操作系统和架构：必须是 Linux / x86_64。
uname -s
uname -m
# 查看 GNU C 库版本；当前发布目标是 GNU，不是 musl。
getconf GNU_LIBC_VERSION
# 核对 systemd 管理本机；容器只有 systemctl 程序不等于存在可用的系统管理器。
systemctl --version
systemctl is-system-running
# 核对 OpenSSL 程序及算法；必须能列出 ED25519。
/usr/bin/openssl version
/usr/bin/openssl list -public-key-algorithms
~~~

`is-system-running` 返回 `degraded` 时，先检查相关产品 unit 的实际状态；不能只凭此汇总状态判断目标服务已经停止。缺少 GNU 环境、systemd 管理器或 Ed25519 时先处理环境，不能换成其他平台二进制。

Debian/Ubuntu 使用以下命令安装下载、解压和签名验证工具：

~~~sh
# 刷新 APT 软件包索引。
sudo apt-get update
# 安装 HTTPS 下载、可信 CA、OpenSSL、Zstandard、tar 和校验工具。
sudo apt-get install --yes ca-certificates curl openssl zstd tar coreutils procps
~~~

使用 DNF 的 RPM 发行版执行：

~~~sh
# 从本机已配置软件源安装相同工具；不改变 Server 服务配置。
sudo dnf install --assumeyes ca-certificates curl openssl zstd tar coreutils procps-ng
~~~

`procps` / `procps-ng` 提供后文只读进程检查使用的 `pgrep`。依赖来自操作系统软件源，不需要为使用正式二进制安装 Rust。源码开发构建见[开发规范](development-contract.md)，未绑定正式源码身份的开发程序不能用于生产升级。

## 2. 下载、校验与验签

从 [xssc 发布页](https://github.com/isarmg/xssc/releases) 选择 `v1.0.3`，下载实际资产 `xssc-1.0.3-linux-x86_64.tar.zst` 及 `xssc-1.0.3-linux-x86_64.tar.zst.sha256`。当前不单独发布外置 `SHA256SUMS.sig`：**签名、内部文件清单和公钥都在压缩包内**。准备独立可信渠道确认的 xssc 发行公钥 DER SHA-256 指纹，不能把包内 `release.json` 中的指纹当作独立信任来源。

以下命令在普通用户的独立下载目录执行。先解压和验签，全部通过后才运行包中的程序：

~~~sh
# 下载固定版本压缩包；-f 对 HTTP 错误返回失败，-L 跟随 GitHub 资产重定向。
curl -fL --output xssc-1.0.3-linux-x86_64.tar.zst \
  https://github.com/isarmg/xssc/releases/download/v1.0.3/xssc-1.0.3-linux-x86_64.tar.zst
# 下载同版归档校验文件。
curl -fL --output xssc-1.0.3-linux-x86_64.tar.zst.sha256 \
  https://github.com/isarmg/xssc/releases/download/v1.0.3/xssc-1.0.3-linux-x86_64.tar.zst.sha256
# 校验整个压缩包字节；看到对应文件 OK 后继续。
sha256sum --check xssc-1.0.3-linux-x86_64.tar.zst.sha256
# 新建空目录并解压，不接管归档记录的属主，不执行其中程序。
mkdir xssc-1.0.3
tar --zstd --extract --file xssc-1.0.3-linux-x86_64.tar.zst \
  --no-same-owner --directory xssc-1.0.3
# 进入包根；bin/、docs/、SHA256SUMS 和 SHA256SUMS.sig 均在此目录内。
cd xssc-1.0.3
# 替换为独立可信渠道确认的 64 位小写十六进制指纹，不能照抄包内元数据。
XSSC_EXPECTED_KEY_SHA256='替换为独立确认的发行公钥DER指纹'
# 计算包内公钥的 DER SHA-256；此值只用于与独立指纹比较。
XSSC_ACTUAL_KEY_SHA256=$(/usr/bin/openssl pkey -pubin \
  -in RELEASE-SIGNING-PUBLIC.pem -outform DER | sha256sum | cut -d ' ' -f 1)
# 只有完全一致才继续；失败时停止安装并核对下载来源和信任锚。
test "$XSSC_ACTUAL_KEY_SHA256" = "$XSSC_EXPECTED_KEY_SHA256"
# 用已核对身份的 Ed25519 公钥验证内部校验清单的签名。
/usr/bin/openssl pkeyutl -verify -rawin -pubin -inkey RELEASE-SIGNING-PUBLIC.pem \
  -in SHA256SUMS -sigfile SHA256SUMS.sig
# 签名成功后核对清单中每个程序、说明和元数据文件，必须全部 OK。
sha256sum --check SHA256SUMS
~~~

每条命令成功后再执行下一条；单独粘贴多条命令不会自动在中途失败时停止。外置归档哈希用于检查下载完整性，独立公钥身份与内部签名用于确认发行来源。升级**产品**制品使用产品自己的签名公钥，与这里安装 xssc 工具的发行公钥分别核验。

## 3. 安装并确认命令能力

本节从已经完成验签的包根执行。首次安装采用明确的版本目录保存离线文档和元数据，再把程序安装到固定命令路径。已有此版本目录时先核对当前安装，不要直接覆盖。

~~~sh
# 确认版本目录尚不存在，防止把不同输入混入旧安装。
test ! -e /opt/sarmg/xssc/1.0.3
# 创建 root 拥有、普通用户不可写的程序版本目录。
sudo install -d -o root -g root -m 0755 /opt/sarmg/xssc/1.0.3
# 复制已验证的完整包：保留文档、签名、清单和发行身份，目标由 root 创建。
sudo cp -R . /opt/sarmg/xssc/1.0.3/
# 将已验证二进制安装到 PATH 的常见目录，固定 root 所有及 0755 模式。
sudo install -o root -g root -m 0755 bin/xssc /usr/local/bin/xssc
# 先使用绝对路径确认实际安装版本。
/usr/local/bin/xssc --version
# 查看编译目标、正式源码身份和支持的升级/恢复能力；本命令不改产品状态。
/usr/local/bin/xssc support --json
# 查看当前真实子命令与参数；不启动升级。
/usr/local/bin/xssc --help
/usr/local/bin/xssc apply-upgrade --help
/usr/local/bin/xssc recover-upgrade --help
# 核对当前终端实际解析到哪个 xssc，避免 PATH 中另一份旧程序优先。
command -v xssc
~~~

版本必须为 `xssc 1.0.3`，`support --json` 的 `compiled_target` 和 `formal_release_target` 应为 `x86_64-unknown-linux-gnu`，`source_revision` 应与此发行版本的正式源码提交一致。核对包内 `release.json` 和 `adapter-catalog.json`，保留完整安装包作为验收依据。若 `command -v` 未指向 `/usr/local/bin/xssc`，后续使用绝对路径；sudo 的 PATH 也可能与当前终端不同。

## 4. 配置与执行升级

xssc 没有全局账户配置或配对数据库；每次事务使用独立的私有 JSON 计划，写入真实 unit、配置、数据范围、可信产品公钥以及全新 `work_directory`。计划字段和权限要求按[完整操作合同](offline-upgrades.md#执行升级)填写，不能直接使用文档中的示例路径或身份。root 管理系统级部署，产品配置及私有数据仍由实际服务 UID/GID 持有。

以下示例的 `xocs.service` 必须换成本机目标主服务单元；有 MediaMTX 等额外写入进程时，全部停止并核验，不能只停主服务：

~~~sh
# 设定已经确认的实际目标 unit 名，供后续只读诊断和停服使用。
XSSC_UNIT='xocs.service'
# 查看 unit 的服务账户、执行路径、启动方式及当前状态。
systemctl cat "$XSSC_UNIT"
systemctl show "$XSSC_UNIT" -p LoadState -p ActiveState -p MainPID -p User -p Group -p ExecStart
# 在完整升级计划就绪、其他管理器自动重启已关闭后，停止目标 writer。
sudo systemctl stop "$XSSC_UNIT"
# 确认 LoadState=loaded、MainPID=0，ActiveState=inactive 或 failed；其他状态不可当作停服。
systemctl show "$XSSC_UNIT" -p LoadState -p ActiveState -p MainPID
# 按私有计划进行验签、备份、切换及成功后的运行权交接；命令可能修改被维护产品。
sudo /usr/local/bin/xssc apply-upgrade --plan /absolute/private/upgrade-plan.json
# 用本次计划中实际的恢复目录查看阶段，并核验已完成备份及维护门状态。
sudo /usr/local/bin/xssc inspect-upgrade --work-directory /absolute/private/recovery
~~~

工具不会下载或主动停止服务端，也不修改 unit；成功切换后会按计划启动并验证产品真实业务就绪。事务中不要人工替换二进制、启动服务端或打开另一套升级器。不存在无损暂停子命令；关闭终端或终止进程可能中断事务，重新操作前必须检查持久记录。

## 5. 查看、诊断与恢复

查看 xssc 使用命令输出、退出码和本次恢复目录的事务日志；它没有自己的 systemd 日志服务。以下服务端状态与日志命令只读：

~~~sh
# 显示本机是否仍有 xssc 进程及其参数；无输出通常表示当前没有进程。
pgrep -a -x xssc
# 查看目标 Server 当前状态，--no-pager 将输出留在终端。
systemctl status "$XSSC_UNIT" --no-pager
# 查看目标 Server 最近 100 条日志；日志可能含私有路径，分享前脱敏。
journalctl -u "$XSSC_UNIT" -n 100 --no-pager
# 按恢复目录重新核验事务；检查不等于执行恢复。
sudo /usr/local/bin/xssc inspect-upgrade --work-directory /absolute/private/recovery
# 仅在需要恢复且满足停服、权限与备份条件时，恢复原程序、配置和数据并验收原服务。
sudo /usr/local/bin/xssc recover-upgrade --work-directory /absolute/private/recovery
~~~

`pgrep` 查看的是工具进程，不能代替事务状态或服务端业务验收。`inspect-upgrade` 的错误也不能当作没有发生修改。空间不足、权限、身份、签名或备份损坏时，保存原输出和恢复目录，按[失败恢复](offline-upgrades.md#失败恢复与数据损失授权)处理；不要手改事务日志、删维护门或自行启动服务。

恢复默认保护运行权交接后的业务写入；返回 `RECOVERY_AUTHORIZATION_REQUIRED` 时保留现状。只有明确接受丢弃备份后的写入，才按完整合同使用 `--allow-data-loss`，不要把该选项作为常规重试。工具没有普通“重新配对”来修复签名或状态错误。

日常服务端的启停仍按对应产品部署文档使用 `systemctl start/stop/restart`；这些命令改变服务端运行状态。已有未结束的升级/恢复事务时先完成恢复流程，不能通过直接启动或重启绕过维护门。成功事务已由工具启动服务，不需要再手工启动一次。

## 6. 更新或卸载工具

更新 xssc 自身时先确保没有运行中的工具进程或未结束的升级事务。按目标发行版本重新下载、核对独立信任身份和验签，保存到新的版本目录后安装新二进制，再检查 `--version`、`support --json` 和实际命令路径；不改现有计划、恢复目录或服务端数据。不用删除工具来修复进行中的事务。

卸载适用于已完成事务并确实不再需要此工具的主机。先确认当前 PATH 和进程，以下删除范围仅是本指南创建的安装：

~~~sh
# 确认命令路径；若实际来自其他安装目录，先按那次部署方式处理。
command -v xssc
# 查看是否还有进程；有输出时先核对事务，不继续删除。
pgrep -a -x xssc
# 删除本指南安装的固定程序，不操作任何 Server unit。
sudo rm -- /usr/local/bin/xssc
# 删除本指南保存的这个版本完整包；不会删除 /opt/sarmg 下其他产品或版本。
sudo rm -r -- /opt/sarmg/xssc/1.0.3
# 验收固定程序已不存在，再检查 PATH 是否还有其他 xssc 安装。
test ! -e /usr/local/bin/xssc
command -v xssc
~~~

xssc 不安装系统账户或服务，无需 `systemctl disable`、`daemon-reload` 或账户删除。上述卸载保留私有计划、签名信任锚、事务备份和服务端配置/数据；这些内容按实际保留需求单独管理。完成记录可用于审计，未结束事务的证据与恢复目录必须保留。

