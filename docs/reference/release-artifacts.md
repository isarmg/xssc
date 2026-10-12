# 制作产品升级制品

本页供签名发行维护者使用。现场操作者从[离线升级](../offline-upgrades.md)开始。

## 制作受信任升级制品

升级发布者在本工具维护受控产品定义，并从普通产品发行诊断取得严格 `ReleaseIdentity` 及真实状态合同。产品仓库没有升级定义、专用命令或工具依赖。工具定义精确绑定当前软件的普通发行身份，并包含相同源/目标状态身份、必需资源、额外数据写入进程角色及可选完整发行目录：

```json
{
  "source_identity": {
    "product": "xocs",
    "version": "1.0.0",
    "source_revision": "由当前正式程序release-identity取得的40位小写Git提交",
    "target": "x86_64-unknown-linux-gnu",
    "state_contract_sha256": "由当前正式程序release-identity取得的64位小写SHA256"
  },
  "source_schema": {
    "application": "xocs",
    "application_version": "xocs-db-v1",
    "schema_revision": 1,
    "schema_sha256": "由产品实际结构定义取得的64位小写SHA256"
  },
  "target_schema": {
    "application": "xocs",
    "application_version": "xocs-db-v1",
    "schema_revision": 1,
    "schema_sha256": "与源结构相同的64位小写SHA256"
  },
  "resources": [
    {"name": "config", "kind": "file"},
    {"name": "data", "kind": "directory"}
  ]
}
```

定义仅接受 `source_identity`、`source_schema`、`target_schema`、`resources` 和可选 `artifact`、`additional_service_roles`。源/目标不同、额外字段、任意命令或钩子均拒绝。稳定的数据格式标签可以低于软件版本；保持标签稳定不代表程序来自旧发行。

以上是 xocs `1.0.0` 的字段模板，不能直接作为升级定义执行。`source_identity` 的完整五字段应逐字取自本实例当前正式程序的 `release-identity --json`；源码提交和状态合同摘要不可使用其他发行版本的值。当前状态身份为 `application=xocs`、`application_version=xocs-db-v1`、`schema_revision=1`，结构摘要应取自当前程序的 `config validate --json`。其他产品使用自己的真实当前身份。工具在任何协调锁、事务日志或维护门改写之前，以当前程序的 `release-identity` 逐字段核验 `source_identity`。不符返回 `CURRENT_RELEASE_INCOMPATIBLE`，不会以结构碰巧一致接纳其他软件发行。定义与发行输入已经完成校验后，发布者使用集中脚本：

```sh
python3 scripts/stage-upgrade-release.py \
  --binary /absolute/release/xocs \
  --identity /absolute/release/release-identity.json \
  --definition /absolute/xssc/definitions/xocs.json \
  --private-key /absolute/private/signing.pem \
  --trusted-public-key /absolute/product/release-signing-public.pem \
  --output /absolute/new-upgrade-package
```

脚本拒绝既有输出目录、错误平台和与源码绑定公钥不匹配的私钥，生成精确字节签名的 `upgrade-release.json` 与 `upgrade-release.sig`。私钥不进入制品。发行标识、源码修订、目标、二进制 SHA-256、源/目标结构及必需资源定义都在签名范围内。

操作方从独立可信渠道取得并固定产品公钥的 DER SHA-256。不能把下载包自带的公钥或摘要当作信任来源。计划中的公钥与指纹必须来自该预先确定的信任锚。

## 完整发行目录与权限分工

本工具的受控定义与签名清单提供部署权威。`artifact` 缺省为单 ELF；完整发行根目录使用严格 `immutable-release-root-v1` 对象，声明 `root_layout`、`entrypoint` 和树摘要。定义必须来自真实当前产品正式交付方式：包含网页资源/MediaMTX 等完整目录的产品不能用仅含二进制制品通过其普通当前状态校验。产品只提供自己的普通诊断和运行入口。额外字段和未知协议拒绝；工具不根据软件版本猜数据格式。


完整发行根目录的签名定义新增 `artifact`，由本工具受控定义声明 `protocol`、`root_layout`、`entrypoint`，打包工具使用 `--release-root` 计算并补入 `tree_sha256`。目录和文件模式逐项参与签名，允许产品原有 0755/0644 或 0555/0444 模式；必须同一可信属主，拒绝组/其他用户写入、特殊位、特殊对象、硬链接和任意符号链接。不能把产品权限模式清单改成另一组值来满足升级工具。树摘要是 `immutable-release-root-v1\n` 后接 UTF-8 紧凑 JSON：深度优先前序遍历、每目录兄弟项按文件名排序、根相对路径为空字符串，每项字段精确顺序 `path,directory,mode,bytes,sha256`。目录 bytes=0/摘要空，文件摘要是原字节 SHA256。单棵树上限 200 万项、128 层及计划 byte budget。

完整目录可选签名字段 `diagnostic_release_root_env`，例如 xcos 已有的普通 `XCOS_RELEASE_ROOT`。只接受长度不超过64的大写 `*_RELEASE_ROOT` 名称。工具清环境后，仅在 `config validate` 注入这个变量；值由已固定执行文件和签名 `entrypoint` 导出对应物理发行根目录，操作者不能另填值。没有任意环境或 shell 钩子。xsos、xszs、xscs 的普通配置校验不需要该字段。

计划新增唯一部署选择对象，示例：

```json
"native_release": {
  "current_link": "/opt/isarmg/xcos/current",
  "source_root": "/opt/isarmg/xcos/releases/当前实际版本",
  "install_root": "/opt/isarmg/xcos/releases/未来实际目标版本"
}
```

`installed_binary` 必须为 `current_link/entrypoint`，输入发行根目录与安装发行根目录都必须保留签名 `root_layout` 的物理后缀。只有名为 `current` 的受控单跳绝对符号链接可选择其同级 `releases` 中声明的两棵物理树；重复斜线、`./`、`..`、任意别名和未知对象拒绝。原服务单元在初始化部署时必须已经使用该受支持入口；工具不改 unit，不给未知旧 CLI 包装壳。封存和验证整棵目标后，工具将完整目录以 NOREPLACE 发布，然后原子替换 `current` 并同步目录。已有目标目录必须逐项一致。当前父目录身份与原发行根目录 inode 记录在事务日志中，另一数据目录也不能并行切换同一部署。

原完整发行根目录和全部持久资源属于同一个已完成备份组。恢复保留原发行根目录；若原 inode 仍在但资产损坏，先持久化修复意图，将损坏树移到 `.upgrade-displaced-original-操作ID` 留证，重建原树并切回选择链接。发生在移开原发行根目录后的中断，可凭固定原 inode/持久意图/完整备份继续；未知替换 inode、悬空 link 和损坏备份均拒绝覆盖。未完成发布的暂存树保留，不猜测删除。

对于 root 管理程序目录、独立服务 UID 持有数据的部署，工具采用 xcsc 1.0.4 的客户端离线维护与文件保护入口；被维护产品仍实施既定运行属主与权限规则。行政入口仅允许实际属主或 root，数据目录必须物理 0700，root 创建的维护锁/门继承目录实际 UID/GID 和 0600。主 systemd 固定 User/Group 必须与数据目录属主一致，DynamicUser 暂不支持。产品 config JSON 也必须供实际服务 UID 读取；工具不把管理员环境或仅 root 可读的 EnvironmentFile 内容偷偷注入验证进程。

事务日志和私密备份保持操作者 0700。为独立服务 UID 执行只读验证，公开发行闭包封存在安装父目录下 root 持有的 `.xssc-execution-操作ID`；它及祖先可遍历但不能由服务 UID、组或其他用户修改。工具先 NOFOLLOW 打开固定 ELF FD，再继承 FD4执行；清辅助组、切实际 GID/UID，并清环境。父进程保留排他维护锁，子进程只校验当前状态；没有迁移授权通道。持久资源另外记录逐项 UID/GID，恢复保留原属主、权限和内容；协议锁/门保持原 inode。辅助命令 stdout/stderr 同时非阻塞读取，各自最多 1MiB，超限/超时 kill+wait，stderr不进入普通错误说明。
