# 安装升级工具

正式平台是 Linux x86_64 GNU；需要 Python 3.12、Bash、systemd、XSSC 当前发行包。XSSC 工具包自身完整SHA256清单、文件摘要和源码身份必须在以 root 安装前核验。

把验证后的 `bin/xssc` 安装为 root 拥有的 `/usr/local/bin/xssc`，权限 0755，父目录不可被服务账号或其他普通用户写入。执行 `xssc --version` 和 `xssc support --json` 核对版本和六个产品。

server 首装通过 XSSI 的 `install.sh`；初始化和管理维护通过随包校验的 `libexec/setup`。日常升级通过 ROOT 中的 `upgrade.sh`，自动下载校验SHA256、停止服务、运行 XSSC、启动服务并检查真实就绪。XSSC 没有常驻服务，不需要配对。

卸载由用户自行处理。程序和工具都没有卸载命令，不隐式清理任何配置、密钥、数据库或业务文件。

[操作](operations.md) · [升级合同](offline-upgrades.md)
