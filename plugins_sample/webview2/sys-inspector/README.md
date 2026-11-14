# 系统资源检视台 (Sys Inspector)

> **类型**：tab 插件（WebView2 内嵌面板）+ 本地伴随服务 `sys-service.exe`
> **模块**：性能 · 进程 · 连接与端口 · 文件占用

---

## 概述

将 Argus 风格的系统级检视能力带进 OpenRevo：进程管理、硬件性能曲线、网络连接表、文件占用排查。
前端只做渲染，所有数据来自本地伴随服务 `sys-service.exe`（127.0.0.1:18956），
由宿主按 manifest `service` 配置托管启停（`elevated: true`，随守护进程以管理员运行）。

## 模块

| 页签 | 能力 | 数据通道 |
|---|---|---|
| 性能 | CPU 总占用 + 频率、内存/交换、磁盘分区用量、磁盘读写速率、网速实时曲线、GPU 占用（宿主遥测桥） | `GET /api/system` + `get_hardware_status` |
| 进程 | 全进程表（CPU%/内存/路径/父 PID）、搜索、点列排序、结束进程 / 结束进程树 | `GET /api/processes`、`POST /api/process/kill` |
| 连接 | TCP/UDP 全量端点表（含 PID 与进程名）、状态着色、按端口/进程搜索、TCP 强制断连（DELETE_TCB） | `GET /api/connections`、`POST /api/connections/close` |
| 文件占用 | 粘贴文件或文件夹路径，Restart Manager 列出所有占用进程，可直接结束 | `GET /api/file/occupiers` |

## 目录结构

```text
sys-inspector/
├── manifest.json            # tab 插件声明 + service 托管配置（端口 18956）
├── index.html               # 四页签前端（纯 HTML/CSS/JS，无构建步骤）
├── README.md
└── sidecar/                 # 独立 Rust crate，不依赖 src-tauri
    ├── Cargo.toml           # sysinfo + windows-sys
    ├── src/main.rs          # 手写 HTTP 服务 + Windows API 封装
    └── sys-service.exe      # CI 产物（Actions artifact 下载后放入）
```

## API 速览

```
GET  /api/health                  {status, version, elevated}
GET  /api/system                  CPU/内存/磁盘/网络计数器
GET  /api/processes               进程快照
POST /api/process/kill            {pid, tree}
POST /api/process/priority        {pid, class: idle|below|normal|above|high|realtime}
POST /api/process/eco             {pid, enable}
GET  /api/connections             {tcp[], udp[]}
POST /api/connections/close       {local_addr, local_port, remote_addr, remote_port}
GET  /api/file/occupiers?path=    Restart Manager 占用列表
```

## 构建与部署

1. GitHub Actions：`.github/workflows/sys-service.yml`（手动 `workflow_dispatch` 或改动 sidecar 源码自动触发）
2. 下载 artifact `sys-service`，将 `sys-service.exe` 放入本插件 `sidecar/` 目录
3. 将整个 `sys-inspector/` 复制到 `%APPDATA%\OpenRevo\plugins\`
4. 重启宿主面板，插件列表出现「系统资源检视台」

## 权限说明

- 服务以管理员运行（继承宿主计划任务权限）：结束任意进程树、断开任意 TCP 连接、查系统文件占用均不受 UIPI 限制
- 磁盘读写速率通过 PDH 性能计数器（`\PhysicalDisk(_Total)`）采样，sidecar 内部 1s 固定节拍刷新
- 文件占用走 Restart Manager（资源管理器「文件正在使用」同源通道），不注入、不驱动

## 许可

随 open-revo fork 仓库分发。核心依赖：sysinfo (MIT/Apache-2.0)、windows-sys (MIT/Apache-2.0)、serde (MIT/Apache-2.0)。
