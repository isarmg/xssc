# 操作与恢复

日常操作：`sudo ROOT/upgrade.sh --root ROOT --version N.N.N`。XSSI 持有 ROOT 工具锁，在停服之前下载、核验SHA256并核对完整目标包、服务账号和实际加载的 systemd 单元。XSSC 先封存校验目标，持久记录工作目录、writer 原状态及本操作启动条件的 inode，验证系统管理器已加载限制后停止全部 writer；XCOS 包含 MediaMTX。

停止证明完成后，源辅助程序报告精确保护范围，XSSC 备份完整程序及状态组。源和目标独立辅助程序只读检查各自发行绑定的当前结构，校验器修改文件、ACL、权限或修改时间都会拒绝。只有当前结构一致时才切换清单载荷，持久保存可能出现新写入的 intent，移除自身启动限制，启动依赖与主服务，验收实际 ELF 摘要、服务身份和业务就绪。

```sh
sudo xssc --json inspect-upgrade --work-directory /absolute/ROOT/maintenance/upgrades/UUID
sudo xssc --json recover-upgrade --work-directory /absolute/ROOT/maintenance/upgrades/UUID
```

恢复首先核对原事务的目录与载荷 inode、备份和实际程序，重新建立本操作启动限制后停止 writer。只有明确愿意丢弃备份之后的业务写入，才增加 `--allow-data-loss`；未知程序、损坏备份、结构不符或未知 writer 不会被强制覆盖。失败保留启动控制与完整恢复材料；纯预检没有服务副作用的记录可清理已授权暂存并关闭。

```sh
sudo xssc --json collect-upgrades --root /absolute/ROOT --minimum-age-seconds 2592000 --keep-completed 2
sudo xssc --json collect-upgrades --root /absolute/ROOT --minimum-age-seconds 2592000 --keep-completed 2 --execute
```

保留策略必须显式提供，默认输出具体回收计划。只有已完成、过期、超过保留数量、没有其他记录引用并且启动控制已释放的事务才可回收。执行前持久保存对象 inode 与属性清单；被替换、未知、仍承担恢复义务的资源保留。回收中断后给同一策略和 `--execute --resume-collection UUID`，只继续原记录授权的剩余对象。

[合同](offline-upgrades.md) · [部署](platform-setup.md)
