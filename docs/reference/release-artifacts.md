# 唯一发行格式

XSSI 的 `scripts/package.py finalize` 为产品包生成 `share/package.json` 和 65字节 `share/package.sha256`，内容为该清单SHA256的64位小写十六进制和换行。

PackageManifest v1 精确字段为 `manifest_version`、`identity`、`schema_identity`、`server`、`setup`、`services`、`files`。未知字段拒绝。

`identity` 包含 product、version、source_revision、target、state_contract_sha256。`schema_identity` 包含 application、application_version、schema_revision、schema_sha256；application_version 是数据格式名，不是软件版本。

server 位于 bin；setup 固定为 libexec/setup。services 精确声明 server 单元及 XCOS 的 MediaMTX 单元。每个 files 项为 path、mode、size、sha256，模式只允许 0755 或 0644，目录为 0755。整个包拒绝未声明文件、重复路径、硬链接、符号链接、特殊文件和不受控写入权限。

XSSC 从独立验证的源 PackageManifest 与目标 PackageManifest 派生内部 `fixed-root-payload-v1` 事务记录。不存在单 ELF、旧升级清单或 immutable-release-root 协议回退。源元数据同样必须核对 SHA256，源完整程序清单同样核对摘要和权限。

构建服务端包使用独立 XSSI 的 scripts/build-package.sh；XSSC 不再交付另一份产品包生成器。[升级合同](../offline-upgrades.md)
