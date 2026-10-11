# xssc 文档

xssc 在 Linux x86_64 GNU 主机上维护已停止的 systemd 服务，将受签名程序更新、完整状态快照和失败恢复放在同一次事务中。

## 安装和操作

1. [安装并检查工具](platform-setup.md)：依赖、下载验签、安装、更新与卸载
2. [准备升级计划](configuration.md)：输入文件、字段、默认值及资源范围
3. [执行升级与恢复](offline-upgrades.md)：停服条件、应用计划、检查结果和恢复
4. [排查问题](troubleshooting.md)：按错误码、事务阶段和服务日志定位

日常维护从[操作说明](operations.md)进入。首次了解流程可读[概念导读](beginner-guide/README.md)；安装工具后的 `support --json` 和 `catalog --json` 可查看当前机制与产品目录。

## 开发和参考

- [构建与测试](development.md)
- [流程与源码导航](project-workflow.md)
- [计划、签名、阶段和审查参考](reference/README.md)
- [1.0.1 发布说明](releases/1.0.1.md)
- [1.0.0 发布说明](releases/1.0.0.md)

xssc 是按需执行的命令行工具。产品的业务结构和当前数据校验由产品本身提供，公共机制来自启用 `offline-maintenance` 的 xcsc 库。代码采用 [Apache License 2.0](../LICENSE-APACHE)。
