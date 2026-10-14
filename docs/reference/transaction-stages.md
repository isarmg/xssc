# 持久事务阶段

正常流程：prechecked → maintenance-intent → maintenance-acquired → backup-started → backup-complete → validated → switch-intent → switched → start-intent → ready。

恢复流程：recovery-maintenance-intent → recovery-restoring → recovery-start-intent → rolled-back。

可能发生写入的标志在移除本操作系统管理器启动条件和启动服务之前持久化。部分备份不能当作完整快照使用。启动控制和程序切换的 intent 必须在副作用前落盘；未完成阶段不被猜测为成功。检查命令只读输出事务、当前程序身份、启动控制与备份验证结果。[恢复](../operations.md)
