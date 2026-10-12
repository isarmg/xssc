# 离线升级与恢复

本页面向维护 xsos、xszs、xscs、xcos、xczs 或 xocs 的操作者。xssc 将停服检查、签名验证、完整快照、软件切换和业务就绪组织为一次有持久记录的事务。

升级事件和状态的日历时间统一为 UTC / Unix epoch，等待、超时与事务执行预算使用单调计时。恢复比较同一时间点或持久操作身份，不按操作者所在地日期重新解释时间。

先按[安装指南](platform-setup.md)安装并验证工具，再准备发行方提供的目标制品和本机计划。当前支持源与目标 `SchemaIdentity` 完全相同的程序更新；软件版本与数据格式身份分别核验。

## 运行条件

- Linux AMD64、systemd 和支持 Ed25519 的 `/usr/bin/openssl`。操作者先停止主服务及所有相关持久数据写入进程，并关闭其他管理器自动重启。工具不下载、不停服，也不修改 unit。未确认已停返回 `SERVER_MUST_BE_STOPPED`。
- 六个服务端的当前程序与未来目标均提供标准 `config validate --config PATH --data-dir PATH --json`、`release-identity --json` 和普通 `state-contract --json`。配置校验必须只读、校验真实结构和业务约束，输出 `schema_identity` 与全部 `state_paths`。
- `state_paths` 包含所有不可重建的持久输入。SQLite 报告数据库父目录以保护 WAL/SHM；外部媒体、密钥或其他数据目录必须落在计划资源内。工具在校验前后对整组内容及属主进行核对，拒绝意外写入。
- 当前和目标运行时使用中立状态锁 `.state-maintenance.lock`、`.state-instance.lock`，遇任何 `.state-maintenance-pending.json` 对象均拒绝启动。工具确认已停、设置中性维护门并取得排他维护锁；配置校验不申请写入权。
- 服务的 `/readyz` 返回 HTTP 200、JSON `{"ready":true}`，带与产品身份一致的 `x-service`。关键业务依赖不可用时不得就绪。
- root 可管理独立服务 UID 的物理 0700 状态目录，普通运行者仍必须是目录实际属主。工具验证 systemd 固定 User/Group 与数据 UID/GID 一致，清辅助组后降权执行产品校验。配置父目录必须由该服务用户持有且可访问，JSON 文件为私有 0600。DynamicUser 暂不支持。
- 全部输入使用绝对规范路径。除下文唯一受控 `current` 入口外，链接、特殊文件、多链接文件、组或其他用户可写对象、重叠保护根均拒绝。恢复保留实际 UID/GID、权限和内容；xattr/ACL、稀疏布局和硬链接关系不在支持合同内。

## 执行升级

创建私有计划文件，填写已经确认的 unit、配置、状态范围、信任锚与全新恢复目录。以下路径是部署示例，必须替换为本实例实际路径；文件已存在、权限已满足、签名已由正式发布者制作才可执行：

```json
{
  "plan_version": 1,
  "service": "xocs.service",
  "installed_binary": "/opt/sarmg/bin/xocs",
  "target_binary": "/srv/xocs-release/xocs",
  "release_manifest": "/srv/xocs-release/upgrade-release.json",
  "release_signature": "/srv/xocs-release/upgrade-release.sig",
  "trusted_public_key": "/etc/sarmg/trust/xocs-release.pem",
  "trusted_public_key_sha256": "独立信任渠道确认的64位小写DER摘要",
  "config": "/etc/sarmg/xocs.json",
  "data_dir": "/var/lib/sarmg/xocs",
  "resources": [
    {"name": "config", "kind": "file", "path": "/etc/sarmg/xocs.json"},
    {"name": "data", "kind": "directory", "path": "/var/lib/sarmg/xocs"}
  ],
  "work_directory": "/srv/backups/xocs-upgrade-unique-id",
  "readiness_address": "127.0.0.1:8080",
  "timeout_seconds": 60,
  "max_backup_bytes": 1099511627776
}
```

额外写入进程使用本工具签名 `additional_service_roles`，按相同顺序映射计划 `additional_services`，例如：

```json
"additional_service_roles": ["mediamtx"]
```

```json
"additional_services": [{"role":"mediamtx","service":"xcos-mediamtx.service"}]
```

主服务单元使用计划 `service`。同名角色/服务单元、缺失或多余映射、超过 16 个辅助写入进程均拒绝。工具逐个只读确认 `LoadState=loaded`、`MainPID=0` 且 `ActiveState=inactive` 或 `failed`；not-found/error/未知/启动中/停止中不能当作停止。设置门、取得锁、快照完成及校验结束时复查全部服务单元。xcos 的 MediaMTX 是独立录像写入进程，不能只停主服务。systemd 以外的写入进程不在当前自动核验范围，须先停止并保全其输入；工具不运行任意 shell 检查。

资源顺序、名称和类型与签名定义完全一致。外部数据库、媒体或密钥要求对应产品发布定义列出另外的保护根，并在计划中明确映射实际路径；缺失会拒绝升级。`max_backup_bytes` 限制整组旧程序与状态备份，默认 1 TiB；目录深度上限 128、每资源最多 2,000,000 项。交接可能写入标记持久后，工具先启动额外写入进程、再启动主服务单元并检查真实业务就绪。单个命令等待 1–600 秒，stdout/stderr 各限制 1 MiB。

```sh
xssc apply-upgrade --plan /absolute/private/upgrade-plan.json
xssc inspect-upgrade --work-directory /srv/backups/xocs-upgrade-unique-id
```

工具不自行下载程序；所取得的离线目标先验证签名、信任锚、发行身份、目标平台、ELF 架构和完整性，封存到受控执行目录后才调用目标校验器。单程序在已安装程序同一目录暂存并原子替换；完整发行根目录使用下述完整目录协议。当前状态采用停服、独占锁下的完整原始快照，主库与 sidecar 同组保存，前后清单与 SHA-256 一致后才标记可恢复。

就绪必须同时证明 unit 活跃、实际 MainPID 运行指定路径及目标 SHA-256、正确产品的 `/readyz` 业务检查通过。进程存在、端口可连或一条退出成功的启动命令都不足以完成升级。

成功结果为 `ready`，表示实际目标进程与业务就绪均已通过。保存本次输出、计划和恢复目录，便于之后检查。

## 阶段与中断

使用 `inspect-upgrade` 查看阶段、已验证快照、实际程序身份和维护门状态。完整字段含义见[事务阶段参考](reference/transaction-stages.md)。

## 失败恢复与数据损失授权

出现失败先保留输出和恢复目录。不要手工删除维护门、修改事务日志、换回旧二进制或重跑同一升级计划。

```sh
xssc inspect-upgrade --work-directory /absolute/recovery-directory
xssc recover-upgrade --work-directory /absolute/recovery-directory
```

尚未交接运行权时，先要求所有写入进程已由操作者停止，再在独占维护下验证备份并恢复原程序、配置和数据，恢复后用原程序普通只读校验核对结构/范围/无写入，再交接、启动并检查原程序业务就绪。部分备份不会被当作已完成快照使用。未知的现行程序、损坏备份或错误记录均停止恢复，不覆盖现状。

进入 `start-intent` 后，即使启动失败或观察超时，也不能证明目标没有写入。默认恢复返回 `RECOVERY_AUTHORIZATION_REQUIRED`，保留新增数据。仅在操作方明确接受**丢弃备份时刻之后的业务写入**后执行：

```sh
xssc recover-upgrade \
  --work-directory /absolute/recovery-directory \
  --allow-data-loss
```

恢复自己的启动也采用同样规则：若 `recovery-start-intent` 中断，下一次重新恢复不能默认丢弃原程序随后产生的写入。完成的恢复再次执行只报告既有结果，不重复恢复。

## 制作受信任升级制品

发行维护者按[制品制作参考](reference/release-artifacts.md#制作受信任升级制品)准备源身份、目标文件和签名定义。产品签名公钥指纹通过独立可信渠道交付给操作者。

## 完整发行目录与权限分工

使用 `current` 选择完整发行目录的产品，在计划中填写 `native_release`。字段、树摘要和权限分工见[完整发行目录参考](reference/release-artifacts.md#完整发行目录与权限分工)。

## 验证边界

开发构建、机制测试和真实产品演练见[构建与测试](development.md)。历史执行记录见[验证台账](validation.md)，其中每份结果只适用于记录的源码和环境。
