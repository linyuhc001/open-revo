# Revo Xray

> **类型**：tab 插件（WebView2 内嵌面板）+ 本地伴随服务 `xray-service.exe`
> **模块**：节点 · 订阅 · 路由 · DNS · 核心 · 设置 · 日志
> **内核**：Xray-core（XTLS/Xray-core 官方 release，按需下载）

---

## 概述

Xray-only 的轻量代理面板：vless / vmess / trojan / shadowsocks 节点与 base64 订阅导入、一键选节点、tcping 与经完整链路的真连接延迟、WinINET 系统代理开关。前端只做渲染，所有逻辑在本地伴随服务 `xray-service.exe`（默认 127.0.0.1:18957）里完成，由宿主按 manifest `service` 托管启停。

插件**不捆绑内核**：首次使用在「核心」页一键从官方 release 下载 `Xray-windows-64.zip`（约 16MB），解压到插件 `data/bin/` 目录；国内网络可填镜像前缀加速。

## 功能

| 页签 | 能力 |
| :--- | :--- |
| 节点 | 粘贴/剪贴板导入分享链接（多行）、base64 订阅内容；表格展示协议/地址/延迟；单击选中、双击选中并启动；单节点 tcping、批量 tcping、当前节点真延迟（走 socks→出口的 204 探测）；分享链接导出（复制到剪贴板） |
| 订阅 | 添加/删除订阅、手动更新；更新按「proto+地址+端口+凭据+订阅」去重刷新，不重复堆积 |
| 路由 | 域名解析策略（AsIs / IPIfNonMatch / IPOnDemand）；预定义规则集一键填入（绕过大陆 / 黑名单 / 全局代理，同 v2rayN V4 模板）；自定义规则列表（出站 代理/直连/拦截 × 域名/IP 条件，支持 geosite:/domain:/纯域名、geoip:/CIDR），增删改、上下移；空列表回落到默认 CN 直连规则集；缺 geo 文件时 geo 规则自动跳过 |
| DNS | 基础设置（同 v2rayN 基础模式）：直连 DNS / 远程 DNS / Bootstrap DNS 三个下拉+自定义（内置 v2rayN 默认选项）、启用开关、查询策略 UseIP/UseIPv4/UseIPv6。远程 DNS 查询经代理出站（`inboundTag dns-module→proxy`），直连 DNS 走直连，Bootstrap（纯 IP）负责解析 DoH 服务器域名。所有解析由 xray 核心完成，插件只生成配置 |
| 核心 | 代理总开关（一键 = 启动核心 + 接管系统代理 / 还原 + 停止）、内核与 Geo 文件下载/更新（支持镜像前缀；**优先走自身代理，失败回落直连**；文件被运行中内核占用时自动「临时停核 → 替换 → 恢复运行」，仍被锁则改名 `.old` 兜底、下次启动清理）、启动/停止/重启；本机入口显示 |
| 设置 | 入站端口自定义（1024–65535，保存前真实绑定探测 + TCP 表占用进程定位，同进程管理插件），还原默认 |
| 日志 | 服务日志（环形缓冲 + 落盘 `data/service.log`） |

## 配置生成

服务按所选节点生成 xray 客户端配置：

- 入站：socks（UDP 开启 + sniffing）与 http 两个本地入口
- 出站：所选节点 + `direct`（freedom）+ `block`（blackhole）
- 路由：默认 `geosite:private/cn`、`geoip:private/cn` → direct，其余走代理（geoip/geosite.dat 随内核 zip 提供）
- 传输层支持：tcp（含 http 伪装）、ws、grpc、h2、httpupgrade、xhttp、kcp；安全层支持 tls / reality（vless flow 透传）

不支持的协议或参数组合会在启动/导入时明确报错，而不是生成一份静默失败的配置。

## 系统代理

「系统代理」开关写 WinINET 每用户注册表（`ProxyEnable/ProxyServer/ProxyOverride`），指向本地 HTTP 入口，并通过 `InternetSetOption` 广播刷新；不写 PAC，不需要管理员权限。开启状态会在页眉实时显示。

## 内核进程托管

xray.exe 以 `CREATE_NO_WINDOW | CREATE_SUSPENDED` 拉起，挂到 `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` 的 Job Object 上后恢复运行——宿主停掉伴随服务时内核进程必然一起退出，不留孤儿进程。

## API 速览

```
GET  /api/health              {status, version, port, xray_installed, xray_version, running, selected, nodes, sysproxy}
GET  /api/nodes               {nodes[], selected}
POST /api/nodes/import        {text, sub_id?}          链接或 base64 订阅内容 → {added, total, errors[]}
POST /api/nodes/select        {id}
POST /api/nodes/delete        {id}
POST /api/nodes/clear
POST /api/nodes/share         {id}                     → {link}
POST /api/test/tcping         {id?}                    id 缺省 = 全部节点（并行）
POST /api/test/real                                    当前节点 204 探测 → {ms}
GET  /api/subs                {subs[]}
POST /api/subs/add            {url, name}
POST /api/subs/delete         {id}                     同时删除该订阅的节点
POST /api/subs/update         {id}                     → {count, errors[]}
POST /api/core/start          无参数；未选节点/未装内核时报错
POST /api/core/stop
POST /api/core/restart
POST /api/core/download       {mirror?}                镜像前缀拼在 release URL 之前；核心运行中优先走自身代理
POST /api/geo/download        {mirror?}                geoip/geosite.dat（Loyalsoldier 源，同 v2rayN）；同上优先自身代理
POST /api/proxy/toggle        {on}                     总开关：on=启核心+接管系统代理，off=还原+停核心
GET  /api/settings            {socks_port, http_port, routing[], routing_strategy, dns}
POST /api/ports/check         {socks, http}            真实绑定探测 + 占用进程定位 → {ok, ports{socks,http}}
POST /api/ports/set           {socks, http}            校验 + 冲突复检后保存；核心在运行则自动重启生效
POST /api/routing/set         {rules[{outbound, domain, ip}], strategy?}   strategy = AsIs/IPIfNonMatch/IPOnDemand；空数组 = 回到默认规则集
POST /api/dns/set             {enabled, direct_dns?, remote_dns?, bootstrap_dns?, query_strategy?}
GET  /api/log                 {log}
POST /api/sysproxy            {on}
GET  /api/sysproxy            {enabled, ours}
```

除 `/api/health`、`/api/nodes`、`/api/subs`、`/api/log`、`/api/sysproxy` 为 GET 外，其余均为 `POST` + 扁平 JSON body。错误统一返回 `{"__error": "..."}`。

## 目录结构

```text
revo-xray/
├── manifest.json          # tab 插件声明 + service 托管配置（默认端口 18957）
├── index.html             # 单文件前端（纯 HTML/CSS/JS，无构建步骤）
├── README.md
└── sidecar/               # 独立 Rust crate，不依赖 src-tauri
    ├── Cargo.toml         # serde / serde_json / ureq(rustls) / flate2 / windows-sys
    ├── src/main.rs        # HTTP 服务 + 路由 + 状态持久化
    ├── src/node.rs        # 节点模型、分享链接解析/生成（自带 base64 编解码）
    ├── src/xconf.rs       # xray 客户端配置生成
    ├── src/winapi.rs      # Job Object 进程托管、WinINET 系统代理
    ├── src/net.rs         # 内核下载、zip 解压（自研最小 reader）、延迟探测
    └── xray-service.exe   # 构建产物（CI artifact），随仓库分发
```

运行期数据在插件 `data/` 目录：`state.json`（节点/订阅/选择/端口）、`config.json`（当前生成的内核配置）、`bin/`（xray.exe + geo 文件）、`service.log`。卸载插件删目录即可全部清理，无注册表残留（系统代理开关在关闭时会复位 ProxyEnable）。

## 构建与部署

仓库内已附带 `sidecar/xray-service.exe`（CI 构建产物），把整个 `revo-xray/` 复制到 `%APPDATA%\OpenRevo\plugins\` 后重开面板即可。

```bash
cd revo-xray/sidecar
cargo build --release          # 产物：target/release/xray-service.exe
cp target/release/xray-service.exe ./xray-service.exe
```

crate 自带独立 `[workspace]`，本目录 `cargo build` 不会触碰宿主依赖。CI 见 `xray-sidecar.yml`（改动 sidecar 源码自动触发 / 手动 `workflow_dispatch`）。

## 已知边界（v0.9）

- 仅 Xray 内核：不支持 sing-box/mihomo 系协议（hy2/tuic 等）、无 TUN 模式（xray 本身不做 TUN）
- 订阅格式：base64 与明文链接列表；Clash YAML 订阅会报"解析出 0 个节点"
- ss 节点忽略 plugin 参数（obfs 系不支持）；IPv6 字面量地址未做括号归一
- 核心启动失败时以日志尾部提示，暂不做自动回滚
