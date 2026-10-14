# 升级计划

计划由 XSSI 在当前SHA256包、纯配置报告和用户选定目标版本之间生成。`plan_version=1`；所有路径使用物理、规范、绝对路径。权限和内容仍由 XSSC 重验，脚本结果不是信任捷径。

关键字段：`service`、`additional_services`、`installed_binary`、`target_binary`、`release_manifest`、`release_checksum`、`config`、`data_dir`、`resources`、`work_directory`、`readiness_address`、`timeout_seconds`、`max_backup_bytes`。

`native_release` 必须是 `{root, source_manifest}`。ROOT 是唯一安装目录；源清单固定为 ROOT/share/package.json，摘要固定为相邻 package.sha256（64位小写SHA256和换行）；配置固定为 ROOT/config/config.json。目标清单在下载包内。不存在选择器、旧版本目录或自动猜测。

资源由已校验源辅助程序的 `state_paths` 规范化成最小保护根，名称只用于事务记账。文件/目录类型必须匹配；外置数据库、密钥、录像、共享目录等需要完整保护，不能漏报或扩大范围。源与目标的保护声明都要与计划一致。

脚本和核心使用 ROOT/maintenance/tool.lock 共享同一 flock 协调描述符，不能通过新建锁文件替代旧 inode。全部声明的运行锁保持同一实际 inode 和 flock，文件锁及共享目录锁分别验证，不删除锁制造成功。[完整合同](offline-upgrades.md)

`readiness_address` 必须使用非零端口和本机地址，支持回环地址、已配置在本机接口上的 IPv4 与 IPv6。XSSI 将 `0.0.0.0`、`::` 通配监听转换为对应回环探测地址；明确的内网地址保持原值。XSSC 不向任意远端或多播地址执行就绪探测，进程身份与程序摘要校验仍然执行。
