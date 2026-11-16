// xray-service — OpenRevo revo-xray companion service.
//
// Headless HTTP service (127.0.0.1:18957 by default) that drives Xray-core:
// node/subscription storage, share-link parsing, client config generation,
// core process lifecycle (job-object tied), WinINET system proxy, latency
// probes and on-demand core download.
//
// Same standalone-crate pattern as process-service / pbo-service: no host
// source dependency, `cargo build` here never touches src-tauri.

mod net;
mod node;
mod winapi;
mod xconf;

use node::Node;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const VERSION: &str = "0.9.9";
const LOG_RING: usize = 400;
/// service.log rotates to service.log.old when it grows past this (1 MB).
const LOG_FILE_MAX: u64 = 1024 * 1024;
/// Loyalsoldier/v2ray-rules-dat release API — tags are timestamps like
/// "202611152204", directly comparable.
const GEO_TAG_API: &str = "https://api.github.com/repos/Loyalsoldier/v2ray-rules-dat/releases/latest";
/// Geo download sources, raced by probe_speed before downloading. jsDelivr
/// mirrors the repo's `release` branch, which ships both dat files and is
/// reachable from CN without a proxy.
const GEO_SOURCES: &[(&str, &str)] = &[
    ("GitHub", "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/{name}"),
    ("jsDelivr", "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/{name}"),
    ("fastly-jsDelivr", "https://fastly.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/{name}"),
];

// ---------- persisted state ----------

#[derive(Serialize, Deserialize, Default)]
struct Persist {
    nodes: Vec<Node>,
    subs: Vec<Sub>,
    selected: String,
    #[serde(default = "default_socks")]
    socks_port: u16,
    #[serde(default = "default_http")]
    http_port: u16,
    #[serde(default)]
    routing: Vec<xconf::Rule>,
    #[serde(default = "default_strategy")]
    routing_strategy: String,
    #[serde(default)]
    dns: xconf::DnsCfg,
    /// Set right before the port-switch handover: the replacement process
    /// auto-starts the core once it is up, so switching the service port
    /// doesn't leave the browser pointed at a dead local proxy.
    #[serde(default)]
    resume_core: bool,
    /// TUN inbound (Xray-native `tun` protocol + wintun.dll). Persisted so a
    /// core restart (settings save, node switch) keeps the TUN inbound.
    #[serde(default)]
    tun_on: bool,
    /// Tag of the geo release (Loyalsoldier/v2ray-rules-dat, e.g.
    /// "202611152204") whose geoip.dat/geosite.dat are in bin/. Empty = unknown
    /// (pre-0.9.8 files) — compared against the latest release on download.
    #[serde(default)]
    geo_tag: String,
}

fn default_socks() -> u16 { 20808 }
fn default_http() -> u16 { 20809 }
fn default_strategy() -> String { "IPIfNonMatch".into() }

#[derive(Clone, Serialize, Deserialize)]
struct Sub {
    id: String,
    name: String,
    url: String,
    #[serde(default)]
    last_update: String,
    #[serde(default)]
    count: usize,
}

// ---------- shared state ----------

struct State {
    data: Mutex<Persist>,
    core: Mutex<Option<winapi::CoreHandle>>,
    logs: Mutex<VecDeque<String>>,
    data_dir: PathBuf,
    bin_dir: PathBuf,
    /// Cached `xray.exe version` keyed by the exe's mtime — health polls must
    /// not spawn a child process on every request (and certainly not while
    /// holding the data lock).
    xray_ver: Mutex<Option<(u64, String)>>,
}

fn now_str() -> String {
    // local-time-ish stamp without pulling chrono: UTC hh:mm:ss is enough for
    // a service log.
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = t.as_secs() + 8 * 3600; // +08:00 fixed offset
    format!("{:02}:{:02}:{:02}", (secs / 3600) % 24, (secs / 60) % 60, secs % 60)
}

impl State {
    fn log(&self, msg: &str) {
        let line = format!("[{}] {}", now_str(), msg);
        {
            let mut ring = self.logs.lock().unwrap_or_else(|e| e.into_inner());
            if ring.len() >= LOG_RING {
                ring.pop_front();
            }
            ring.push_back(line.clone());
        }
        let log_path = self.data_dir.join("service.log");
        // rotate: > LOG_FILE_MAX → rename to .old (replacing any previous
        // .old), keeping the on-disk footprint capped at ~2 MB
        if let Ok(meta) = std::fs::metadata(&log_path) {
            if meta.len() > LOG_FILE_MAX {
                let old = self.data_dir.join("service.log.old");
                let _ = std::fs::remove_file(&old);
                let _ = std::fs::rename(&log_path, &old);
            }
        }
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
        {
            let _ = writeln!(f, "{line}");
        }
    }

    fn persist(&self, p: &Persist) {
        let path = self.data_dir.join("state.json");
        if let Ok(text) = serde_json::to_string_pretty(p) {
            if let Err(e) = std::fs::write(&path, text) {
                self.log(&format!("状态保存失败: {e}"));
            }
        }
    }

    fn xray_exe(&self) -> PathBuf {
        self.bin_dir.join("xray.exe")
    }

    fn xray_installed(&self) -> bool {
        self.xray_exe().is_file()
    }

    fn core_running(&self) -> bool {
        let mut guard = self.core.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(h) = guard.as_ref() {
            if winapi::is_running(h.0) {
                return true;
            }
            self.log("xray 进程已退出");
            *guard = None;
        }
        false
    }

    fn take_core(&self) -> Option<winapi::CoreHandle> {
        let mut guard = self.core.lock().unwrap_or_else(|e| e.into_inner());
        let h = guard.take();
        if let Some(h) = h {
            if winapi::is_running(h.0) {
                winapi::kill(h.0);
            }
        }
        None
    }

    /// PID of the running xray child, if any — used to whitelist "the port is
    /// held by our own core" during conflict probes.
    fn core_pid(&self) -> Option<u32> {
        let guard = self.core.lock().unwrap_or_else(|e| e.into_inner());
        guard.as_ref().and_then(|h| winapi::process_id(h.0))
    }
}

// ---------- helpers ----------

fn json_resp(stream: &mut TcpStream, code: u32, body: &Value) {
    let text = body.to_string();
    let head = format!(
        "HTTP/1.1 {code} OK\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Headers: content-type\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nConnection: close\r\n\r\n",
        text.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(text.as_bytes());
    let _ = stream.flush();
}

fn err_resp(stream: &mut TcpStream, msg: &str) {
    json_resp(stream, 200, &json!({ "__error": msg }));
}

fn read_request(stream: &mut TcpStream) -> Option<(String, String, Vec<u8>)> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    // read until \r\n\r\n
    let header_end;
    loop {
        let n = stream.read(&mut tmp).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_subsequence(&buf, b"\r\n\r\n") {
            header_end = pos;
            break;
        }
        if buf.len() > 1_048_576 {
            return None;
        }
    }
    let head = String::from_utf8_lossy(&buf[..header_end]).into_owned();
    let mut lines = head.lines();
    let request_line = lines.next()?.to_string();
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?.to_string();
    let path_full = parts.next()?.to_string();
    let path = path_full.split('?').next().unwrap_or("").to_string();

    let mut content_length = 0usize;
    for l in lines {
        let l = l.trim();
        if let Some(v) = l.to_ascii_lowercase().strip_prefix("content-length:") {
            content_length = v.trim().parse().unwrap_or(0);
        }
    }
    let mut body = buf[header_end + 4..].to_vec();
    while body.len() < content_length {
        let n = stream.read(&mut tmp).ok()?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
    }
    body.truncate(content_length);
    Some((method, path, body))
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
}

fn body_json(body: &[u8]) -> Value {
    if body.is_empty() {
        json!({})
    } else {
        serde_json::from_slice(body).unwrap_or(json!({}))
    }
}

fn jstr<'a>(v: &'a Value, k: &str) -> String {
    v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string()
}

fn stamp() -> String {
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let days = t.as_secs() / 86400;
    // days since 1970-01-01 → y-m-d (civil algorithm)
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = doe / 1461;
    let y = yoe + era * 400;
    let doy = doe - yoe * 1461;
    let mp = doy / 588;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let d = doy - (153 * mp + 2) / 5 + 1;
    let y = if m <= 2 { y + 1 } else { y };
    let secs = t.as_secs() + 8 * 3600;
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}", (secs / 3600) % 24, (secs / 60) % 60)
}

fn id_gen() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let t = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let mut x = t.as_nanos() as u64;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    format!("{:08x}", (x & 0xFFFF_FFFF) ^ (t.subsec_nanos() as u64))
}

// ---------- core lifecycle ----------

fn core_start(st: &State) -> Result<Value, String> {
    if !st.xray_installed() {
        return Err("Xray 内核未安装，请先在「核心」页下载".into());
    }
    let geoip_ok = st.bin_dir.join("geoip.dat").is_file();
    let geosite_ok = st.bin_dir.join("geosite.dat").is_file();
    if !geoip_ok || !geosite_ok {
        st.log("注意：缺少 geoip.dat / geosite.dat，已降级为不含 geo 规则的配置（点「下载 Geo 文件」可恢复 CN 直连规则）");
    }
    let p = st.data.lock().unwrap_or_else(|e| e.into_inner());
    let node = p
        .nodes
        .iter()
        .find(|n| n.id == p.selected)
        .cloned();
    let node = match node {
        Some(n) => n,
        None => return Err("尚未选择节点".into()),
    };
    let ports = xconf::Ports { socks: p.socks_port, http: p.http_port };
    let rules = p.routing.clone();
    let dns = p.dns.clone();
    let strategy = p.routing_strategy.clone();
    let tun = p.tun_on;
    let cfg = xconf::build_config(&node, &ports, geoip_ok, geosite_ok, &rules, &dns, &strategy, tun)?;
    let cfg_path = st.data_dir.join("config.json");
    std::fs::write(&cfg_path, &cfg).map_err(|e| format!("写配置失败: {e}"))?;

    // take down any previous instance first — the data lock is released
    // BEFORE killing/waiting on the old process so a slow kill can never
    // wedge every data-locking endpoint.
    let old_handle = {
        let mut guard = st.core.lock().unwrap_or_else(|e| e.into_inner());
        guard.take()
    };
    drop(p);
    if let Some(h) = old_handle {
        if winapi::is_running(h.0) {
            winapi::kill(h.0);
            std::thread::sleep(Duration::from_millis(300));
        }
    }

    st.log(&format!("启动 xray：节点「{}」({})", node.name, node.addr_port()));
    // truncate the child's log, then let the child append its stdout/stderr to
    // it — the only way to see why xray refuses to start.
    let log_path = st.data_dir.join("xray.log");
    std::fs::File::create(&log_path).map_err(|e| format!("创建 xray.log 失败: {e}"))?;
    let handle = winapi::spawn_tracked(
        st.xray_exe().to_str().ok_or("路径含非 UTF-8")?,
        &["run", "-c", cfg_path.to_str().ok_or("配置路径非 UTF-8")?],
        Some(&st.bin_dir),
        Some(&log_path),
    )?;
    *st.core.lock().unwrap_or_else(|e| e.into_inner()) = Some(winapi::CoreHandle(handle));
    std::thread::sleep(Duration::from_millis(500));
    if !winapi::is_running(handle) {
        *st.core.lock().unwrap_or_else(|e| e.into_inner()) = None;
        let tail = read_xray_log(st);
        st.log("xray 启动即退出");
        return Err(format!("xray 启动失败，请看日志。{tail}"));
    }
    st.log(&format!("xray 已启动，socks :{}，http :{}", ports.socks, ports.http));
    Ok(json!({ "ok": true, "running": true, "node": node.name }))
}

fn read_xray_log(st: &State) -> String {
    std::fs::read_to_string(st.data_dir.join("xray.log"))
        .map(|s| {
            s.lines()
                .rev()
                .take(5)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect::<Vec<_>>()
                .join(" | ")
        })
        .unwrap_or_default()
}

fn core_stop(st: &State) -> Result<Value, String> {
    st.take_core();
    st.log("xray 已停止");
    Ok(json!({ "ok": true, "running": false }))
}

/// Fetch preferring our own proxy when the core is running (GitHub is the
/// usual target and unreachable from CN networks directly), falling back to
/// direct otherwise / on failure. Logs which path was taken.
fn http_get_auto(st: &State, what: &str, url: &str, timeout_s: u64) -> Result<Vec<u8>, String> {
    if st.core_running() {
        let http = st.data.lock().unwrap_or_else(|e| e.into_inner()).http_port;
        match net::http_get_via(url, timeout_s, Some(http)) {
            Ok(b) => {
                st.log(&format!("{what}：已走自身代理下载"));
                return Ok(b);
            }
            Err(e) => st.log(&format!("{what}：自身代理下载失败（{e}），改用直连")),
        }
    }
    let b = net::http_get_via(url, timeout_s, None)?;
    st.log(&format!("{what}：已直连下载"));
    Ok(b)
}

/// Windows keeps a running exe un-deletable but renameable: park the old file
/// aside, write the new one; `.old` leftovers are cleaned up on startup.
fn replace_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    match std::fs::write(path, bytes) {
        Ok(()) => Ok(()),
        Err(_) => {
            let name = path
                .file_name()
                .ok_or("路径无效")?
                .to_string_lossy()
                .into_owned();
            let bak = path.with_file_name(format!("{name}.{}.old", id_gen()));
            std::fs::rename(path, &bak).map_err(|e| format!("目标被占用且无法改名: {e}"))?;
            std::fs::write(path, bytes).map_err(|e| format!("改名后写入仍失败: {e}"))?;
            Ok(())
        }
    }
}

/// Ensure the target is removable before an unzip overwrites it in place.
fn pre_replace_locked(path: &Path) -> Result<(), String> {
    if !path.is_file() {
        return Ok(());
    }
    if std::fs::remove_file(path).is_ok() {
        return Ok(());
    }
    let name = path
        .file_name()
        .ok_or("路径无效")?
        .to_string_lossy()
        .into_owned();
    let bak = path.with_file_name(format!("{name}.{}.old", id_gen()));
    std::fs::rename(path, &bak).map_err(|e| format!("文件被占用且无法改名: {e}"))?;
    Ok(())
}

fn cleanup_old_files(st: &State) {
    if let Ok(rd) = std::fs::read_dir(&st.bin_dir) {
        for e in rd.flatten() {
            if e.file_name().to_string_lossy().ends_with(".old") {
                let _ = std::fs::remove_file(e.path());
                st.log(&format!("清理旧文件：{}", e.file_name().to_string_lossy()));
            }
        }
    }
}

/// Run a file-replacement closure with the core temporarily stopped (xray.exe
/// cannot be overwritten while running), then restore the previous state.
fn with_core_stopped<T>(
    st: &State,
    what: &str,
    f: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    let was_running = st.core_running();
    if was_running {
        st.take_core();
        st.log(&format!("{what}：核心运行中，先临时停止"));
    }
    let r = f();
    if was_running {
        match &r {
            Ok(_) => {
                st.log(&format!("{what}：完成，恢复核心运行"));
                core_start(st)?;
            }
            Err(_) => {
                st.log(&format!("{what}：失败，核心未自动恢复，请手动启动"));
            }
        }
    }
    r
}

/// Parse "Xray 26.9.9 (...)" / "v26.9.9" → [26, 9, 9]. None if unparseable.
fn version_key(s: &str) -> Option<Vec<u32>> {
    let t = s.trim().trim_start_matches('v');
    let t = t.strip_prefix("Xray ").unwrap_or(t);
    let t = t.split([' ', '(', '-']).next().unwrap_or("");
    let mut out = Vec::new();
    for p in t.split('.') {
        out.push(p.trim().parse::<u32>().ok()?);
    }
    if out.is_empty() { None } else { Some(out) }
}

/// Segment-wise compare, padding the shorter side with zeros.
fn ver_cmp(a: &[u32], b: &[u32]) -> std::cmp::Ordering {
    for i in 0..a.len().max(b.len()) {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        if x != y {
            return x.cmp(&y);
        }
    }
    std::cmp::Ordering::Equal
}

/// Latest Xray-core tag from the GitHub releases API (proxied when the core
/// is running, direct otherwise). None = API unreachable, caller falls back
/// to the old always-download behavior.
fn latest_xray_tag(st: &State) -> Option<String> {
    let body = http_get_auto(
        st,
        "版本检查",
        "https://api.github.com/repos/XTLS/Xray-core/releases/latest",
        20,
    )
    .ok()?;
    let v: Value = serde_json::from_slice(&body).ok()?;
    v.get("tag_name")?.as_str().map(|s| s.trim().to_string())
}

fn core_download(st: &State, mirror: &str) -> Result<Value, String> {
    // Preflight: only download when the local core is OLDER than the latest
    // release, OR required files are missing (repair). Up-to-date + complete
    // → skip; anything else keeps the old always-download fallback (API
    // unreachable, unparseable versions, custom builds).
    let exe_ok = st.xray_exe().is_file();
    let wintun_ok = st.bin_dir.join("wintun.dll").is_file();
    let local_ver = xray_version_cached(st);
    if exe_ok && wintun_ok {
        if let Some(lk) = version_key(&local_ver) {
            if let Some(tag) = latest_xray_tag(st) {
                match version_key(&tag).map(|nk| ver_cmp(&nk, &lk)) {
                    Some(std::cmp::Ordering::Equal) | Some(std::cmp::Ordering::Greater) => {
                        st.log(&format!("内核已是最新（{local_ver}），跳过下载"));
                        return Ok(json!({
                            "ok": true,
                            "skipped": true,
                            "version": local_ver,
                            "message": format!("内核已是最新（{local_ver}），无需下载")
                        }));
                    }
                    Some(std::cmp::Ordering::Less) => {
                        st.log(&format!("发现新内核：本地 {local_ver} → 最新 {tag}"));
                    }
                    None => st.log(&format!("无法解析最新版本号（{tag}），继续下载")),
                }
            } else {
                st.log("无法获取最新版本号（GitHub API 不可达），继续下载");
            }
        }
    } else {
        st.log("内核文件不完整（xray.exe / wintun.dll 缺失），执行修复下载");
    }
    let url = if mirror.is_empty() {
        net::XRAY_RELEASE_URL.to_string()
    } else {
        format!("{}{}", mirror.trim_end_matches('/'), "/XTLS/Xray-core/releases/latest/download/Xray-windows-64.zip")
    };
    st.log(&format!("开始下载内核：{url}"));
    // fetch first — the core may still be running to proxy this request
    let zip_bytes = http_get_auto(st, "内核", &url, 120)?;
    st.log(&format!("内核下载完成 {} 字节，解压中", zip_bytes.len()));
    let zip_path = st.data_dir.join("xray-core.zip");
    std::fs::write(&zip_path, &zip_bytes).map_err(|e| format!("写 zip 失败: {e}"))?;
    let res = with_core_stopped(st, "内核更新", || {
        cleanup_old_files(st);
        pre_replace_locked(&st.xray_exe())?;
        std::fs::create_dir_all(&st.bin_dir).ok();
        let files = net::unzip_into(&zip_path, &st.bin_dir)?;
        let _ = std::fs::remove_file(&zip_path);
        let ver = net::xray_version(&st.xray_exe()).unwrap_or_else(|| "unknown".into());
        st.log(&format!("内核就绪：{}（{} 个文件）", ver, files.len()));
        Ok(json!({ "ok": true, "version": ver, "files": files.len() }))
    });
    // recent Xray zips no longer ship the geo dat files; grab them separately
    // (best-effort — the panel keeps working without them, just without CN rules)
    let missing = !st.bin_dir.join("geoip.dat").is_file() || !st.bin_dir.join("geosite.dat").is_file();
    if res.is_ok() && missing {
        match geo_download(st, mirror) {
            Ok(_) => {}
            Err(e) => st.log(&format!("geo 文件下载失败（可稍后点「下载 Geo 文件」重试）: {e}")),
        }
    }
    res
}

/// Latest geo release tag from the GitHub API (proxied when the core runs).
fn latest_geo_tag(st: &State) -> Option<String> {
    let body = http_get_auto(st, "geo 版本检查", GEO_TAG_API, 20).ok()?;
    let v: Value = serde_json::from_slice(&body).ok()?;
    v.get("tag_name")?.as_str().map(|s| s.trim().to_string())
}

/// True when the stored geo tag is behind `latest`. Unparseable tags compare
/// by equality only.
fn geo_outdated(stored: &str, latest: &str) -> bool {
    match (stored.parse::<u64>().ok(), latest.parse::<u64>().ok()) {
        (Some(a), Some(b)) => a < b,
        _ => stored != latest,
    }
}

fn geo_download(st: &State, mirror: &str) -> Result<Value, String> {
    // Preflight: skip only when the files are complete AND the stored release
    // tag matches (or is newer than) the latest release. Unknown stored tag
    // (pre-0.9.8 files) counts as outdated. API unreachable + complete files
    // keeps the old skip behavior so a dead API never forces a download.
    let complete = ["geoip.dat", "geosite.dat"].iter().all(|name| {
        std::fs::metadata(st.bin_dir.join(name))
            .map(|m| m.len() > 0)
            .unwrap_or(false)
    });
    let stored_tag = st.data.lock().unwrap_or_else(|e| e.into_inner()).geo_tag.clone();
    let latest = latest_geo_tag(st);
    if complete {
        let must = match &latest {
            Some(t) => geo_outdated(&stored_tag, t),
            None => false,
        };
        if !must {
            let why = match &latest {
                Some(t) => format!("geo 已是最新（release {t}），跳过下载"),
                None => "geo 文件已完整（geoip.dat + geosite.dat），跳过下载".to_string(),
            };
            st.log(&why);
            return Ok(json!({ "ok": true, "skipped": true, "message": why, "version": latest }));
        }
        st.log(&format!(
            "发现新 geo 版本：{} → {}，开始更新",
            if stored_tag.is_empty() { "(未知)".to_string() } else { stored_tag.clone() },
            latest.as_ref().unwrap()
        ));
    } else {
        st.log("geo 文件缺失，开始下载");
    }

    // Source selection: URLs come from github.com/Loyalsoldier/v2ray-rules-dat
    // (release + its jsDelivr mirrors). Race GitHub against the CDNs and pick
    // the fastest. When our own proxy is running, GitHub joins the race
    // through the tunnel; without a proxy GitHub is pointless from CN — go
    // straight to the CDNs. The user mirror, if set, is probed too.
    let proxy_on = st.core_running();
    let proxy_port = if proxy_on {
        Some(st.data.lock().unwrap_or_else(|e| e.into_inner()).http_port)
    } else {
        None
    };
    if proxy_on {
        st.log("自身代理运行中：GitHub 经代理参与测速，与 CDN 比速度");
    } else {
        st.log("无自身代理：直接走 CDN 源");
    }
    // (label, template, proxy port override)
    let mut sources: Vec<(String, String, Option<u16>)> = Vec::new();
    if !mirror.is_empty() {
        let m = mirror.trim_end_matches('/').to_string();
        sources.push((
            "镜像".to_string(),
            format!("{m}/Loyalsoldier/v2ray-rules-dat/releases/latest/download/{{name}}"),
            None,
        ));
    }
    let (gh_label, gh_tpl) = GEO_SOURCES[0];
    if let Some(p) = proxy_port {
        sources.push((format!("{gh_label}@代理"), gh_tpl.to_string(), Some(p)));
    }
    for (label, tpl) in &GEO_SOURCES[1..] {
        sources.push(((*label).to_string(), (*tpl).to_string(), None));
    }
    let handles: Vec<_> = sources
        .iter()
        .map(|(label, tpl, proxy)| {
            let url = tpl.replace("{name}", "geoip.dat");
            let label = label.clone();
            let tpl = tpl.clone();
            let proxy = *proxy;
            std::thread::spawn(move || {
                let ms = net::probe_speed(&url, 256 * 1024, 8, proxy);
                (label, tpl, proxy, ms)
            })
        })
        .collect();
    let mut probed: Vec<(String, String, Option<u16>, Option<u128>)> = handles
        .into_iter()
        .map(|h| h.join().unwrap_or((String::new(), String::new(), None, None)))
        .collect();
    probed.sort_by_key(|p| p.3.unwrap_or(u128::MAX));
    let speed_line = probed
        .iter()
        .map(|(l, _, _, ms)| match ms {
            Some(t) => format!("{l} {t}ms"),
            None => format!("{l} 超时"),
        })
        .collect::<Vec<_>>()
        .join(" / ");
    st.log(&format!("geo 源测速：{speed_line}，按此顺序尝试"));

    // Fetch both files, walking sources fastest-first. The file set follows
    // v2rayN's Xray logic: geoip.dat + geosite.dat only — Country.mmdb /
    // geoip.metadb / geoip-only-cn-private.dat belong to the mihomo core
    // (and an optional slim geoip), which this plugin does not ship.
    let mut fetched: Vec<(String, Vec<u8>)> = Vec::new();
    for name in ["geoip.dat", "geosite.dat"] {
        let mut body = None;
        for (label, tpl, proxy, _ms) in &probed {
            let url = tpl.replace("{name}", name);
            st.log(&format!("下载 {name} ← {label}：{url}"));
            match net::http_get_via(&url, 180, *proxy) {
                Ok(b) if !b.is_empty() => {
                    st.log(&format!("{name}：{label} 下载成功 {:.1}MB", b.len() as f64 / 1e6));
                    body = Some(b);
                    break;
                }
                Ok(_) => st.log(&format!("{name}：{label} 返回空内容，换下一个源")),
                Err(e) => st.log(&format!("{name}：{label} 失败（{e}），换下一个源")),
            }
        }
        let b = body.ok_or_else(|| {
            st.log("geo 下载失败：所有候选源（GitHub/CDN/镜像）均不可用");
            "geo 下载失败：所有候选源均不可用，请检查网络或在设置里配置镜像".to_string()
        })?;
        fetched.push((name.to_string(), b));
    }

    // swap them in with the core stopped
    let res = with_core_stopped(st, "Geo 文件更新", || {
        cleanup_old_files(st);
        std::fs::create_dir_all(&st.bin_dir).ok();
        let mut done = Vec::new();
        for (name, body) in fetched {
            done.push(format!("{name} {:.1}MB", body.len() as f64 / 1e6));
            replace_file(&st.bin_dir.join(name), &body)?;
        }
        st.log(&format!("Geo 文件就绪：{}", done.join(" / ")));
        Ok(json!({ "ok": true, "files": done }))
    });
    if res.is_ok() {
        if let Some(t) = &latest {
            let mut p = st.data.lock().unwrap_or_else(|e| e.into_inner());
            p.geo_tag = t.clone();
            st.persist(&p);
        }
    }
    res
}

/// Master switch, v2rayN style: one toggle = core up + system proxy taken
/// over (on), or system proxy restored + core stopped (off).
fn h_proxy_toggle(st: &State, v: &Value) -> Result<Value, String> {
    let on = v.get("on").and_then(|x| x.as_bool()).ok_or("缺少 on")?;
    if on {
        core_start(st)?;
        let http = st.data.lock().unwrap_or_else(|e| e.into_inner()).http_port;
        winapi::set_system_proxy(true, http)?;
        st.log("总开关：代理开启（核心运行 + 系统代理已接管）");
    } else {
        let http = st.data.lock().unwrap_or_else(|e| e.into_inner()).http_port;
        if let Err(e) = winapi::set_system_proxy(false, http) {
            st.log(&format!("总开关：还原系统代理失败（继续停核心）: {e}"));
        }
        st.take_core();
        st.log("总开关：代理关闭（系统代理已还原，核心已停止）");
    }
    Ok(json!({ "ok": true, "on": on }))
}

// ---------- settings: ports / routing / dns -------------------------------

/// Save something into Persist, persist it, and hot-restart the core if it
/// was running so the change takes effect immediately.
fn save_and_restart<F>(st: &State, mutate: F) -> Result<Value, String>
where
    F: FnOnce(&mut Persist),
{
    let was_running = st.core_running();
    {
        let mut p = st.data.lock().unwrap_or_else(|e| e.into_inner());
        mutate(&mut p);
        st.persist(&p);
    }
    if was_running {
        st.log("配置已保存，重启核心使新配置生效…");
        core_start(st)?;
        st.log("核心已按新配置重启");
    }
    Ok(json!({ "ok": true, "restarted": was_running }))
}

fn h_settings(st: &State) -> Value {
    let p = st.data.lock().unwrap_or_else(|e| e.into_inner());
    json!({
        "socks_port": p.socks_port,
        "http_port": p.http_port,
        "routing": p.routing,
        "routing_strategy": p.routing_strategy,
        "dns": p.dns,
    })
}

/// Port conflict probe, same semantics as process-manager's /api/port/check:
/// real bind attempt on 127.0.0.1, owner lookup via the TCP table when busy.
/// A candidate equal to our own service port is always rejected.
fn h_ports_check(st: &State, v: &Value) -> Value {
    let parse = |k: &str| -> Option<u16> {
        v.get(k).and_then(|x| x.as_u64()).map(|n| n as u16)
            .or_else(|| v.get(k).and_then(|x| x.as_str()).and_then(|s| s.trim().parse().ok()))
    };
    let service_port = HEALTH_PORT.load(Ordering::Relaxed);
    let core_pid = st.core_pid();
    let mut out = serde_json::Map::new();
    for k in ["socks", "http"] {
        let Some(p) = parse(k) else {
            out.insert(k.into(), json!({ "ok": false, "reason": "端口无效" }));
            continue;
        };
        if p < 1024 || p > 65535 {
            out.insert(k.into(), json!({ "ok": false, "reason": "需在 1024–65535 之间" }));
            continue;
        }
        if p == service_port {
            out.insert(k.into(), json!({ "ok": false, "reason": format!("与插件服务端口 {service_port} 冲突") }));
            continue;
        }
        match std::net::TcpListener::bind(("127.0.0.1", p)) {
            Ok(l) => drop(l),
            Err(_) => {
                let (owner, pid) = winapi::listener_owner(p);
                // our own running xray holds this inbound — usable by definition
                if pid.is_some() && pid == core_pid {
                    out.insert(k.into(), json!({ "ok": true, "self": true }));
                    continue;
                }
                let who = if owner.is_empty() { format!("未知进程(pid {pid:?})") } else { owner };
                out.insert(k.into(), json!({ "ok": false, "reason": format!("已被 {who} 占用"), "pid": pid }));
                continue;
            }
        }
        out.insert(k.into(), json!({ "ok": true }));
    }
    // cross-check only matters when both parsed fine
    if let (Some(a), Some(b)) = (parse("socks"), parse("http")) {
        if a == b && a >= 1024 {
            out.insert("socks".into(), json!({ "ok": false, "reason": "socks 与 http 端口相同" }));
            out.insert("http".into(), json!({ "ok": false, "reason": "socks 与 http 端口相同" }));
        }
    }
    let all_ok = out.values().all(|x| x.get("ok").and_then(|y| y.as_bool()).unwrap_or(false));
    json!({ "ok": all_ok, "ports": out })
}

fn h_ports_set(st: &State, v: &Value) -> Result<Value, String> {
    let parse = |k: &str| -> Result<u16, String> {
        v.get(k)
            .and_then(|x| x.as_u64())
            .map(|n| n as u16)
            .or_else(|| v.get(k).and_then(|x| x.as_str()).and_then(|s| s.trim().parse().ok()))
            .ok_or(format!("缺少或无效的 {k} 端口"))
    };
    let socks = parse("socks")?;
    let http = parse("http")?;
    let service_port = HEALTH_PORT.load(Ordering::Relaxed);
    for (name, p) in [("socks", socks), ("http", http)] {
        if p < 1024 {
            return Err(format!("{name} 端口需在 1024–65535 之间"));
        }
        if p == service_port {
            return Err(format!("{name} 端口与插件服务端口 {service_port} 冲突"));
        }
    }
    if socks == http {
        return Err("socks 与 http 端口不能相同".into());
    }
    // belt and braces: re-run the conflict probe before committing
    let probe = h_ports_check(st, &json!({ "socks": socks, "http": http }));
    if !probe.get("ok").and_then(|x| x.as_bool()).unwrap_or(false) {
        return Err(format!("端口检测未通过：{probe}"));
    }
    let socks_str = socks; let http_str = http;
    let r = save_and_restart(st, |p| {
        p.socks_port = socks_str;
        p.http_port = http_str;
    })?;
    st.log(&format!("入站端口改为 socks:{socks} / http:{http}"));
    Ok(r)
}

// ---------- service (listen) port: check / set / manifest rewrite ----------

fn h_service_port_check(st: &State, v: &Value) -> Result<Value, String> {
    let p = v
        .get("port")
        .and_then(|x| x.as_u64())
        .or_else(|| v.get("port").and_then(|x| x.as_str()).and_then(|s| s.trim().parse().ok()))
        .ok_or("缺少或无效的 port")?;
    if !(1024..=65535).contains(&p) {
        return Err("端口需在 1024–65535 之间".into());
    }
    let p = p as u16;
    let cur = HEALTH_PORT.load(Ordering::Relaxed);
    let (socks, http) = {
        let g = st.data.lock().unwrap_or_else(|e| e.into_inner());
        (g.socks_port, g.http_port)
    };
    if p == socks || p == http {
        return Ok(json!({ "port": p, "free": false, "owner": "本插件代理入站端口" }));
    }
    if p == cur {
        // Our own listener holds it — usable by definition.
        return Ok(json!({ "port": p, "free": true, "self": true }));
    }
    match std::net::TcpListener::bind(("127.0.0.1", p)) {
        Ok(l) => drop(l),
        Err(_) => {
            let (owner, pid) = winapi::listener_owner(p);
            let who = if owner.is_empty() { format!("未知进程(pid {pid:?})") } else { owner };
            return Ok(json!({ "port": p, "free": false, "owner": who, "pid": pid }));
        }
    }
    Ok(json!({ "port": p, "free": true }))
}

fn h_service_port_set(st: &State, v: &Value) -> Result<Value, String> {
    let p = v
        .get("port")
        .and_then(|x| x.as_u64())
        .or_else(|| v.get("port").and_then(|x| x.as_str()).and_then(|s| s.trim().parse().ok()))
        .ok_or("缺少或无效的 port")?;
    if !(1024..=65535).contains(&p) {
        return Err("端口需在 1024–65535 之间".into());
    }
    let p = p as u16;
    let cur = HEALTH_PORT.load(Ordering::Relaxed);
    let (socks, http) = {
        let g = st.data.lock().unwrap_or_else(|e| e.into_inner());
        (g.socks_port, g.http_port)
    };
    if p == socks || p == http {
        return Err(format!("端口 {p} 与代理入站端口冲突（socks:{socks} / http:{http}）"));
    }
    if p != cur && TcpListener::bind(("127.0.0.1", p)).is_err() {
        return Err(format!("端口 {p} 已被占用，无法应用"));
    }

    update_manifest_port(p)?;

    if p == cur {
        // Same port: manifest is now consistent, nothing to restart.
        return Ok(json!({ "ok": true, "port": p, "restarting": false }));
    }

    // Handover: remember whether the core was running so the replacement
    // restores it — otherwise the system proxy would point at a dead port.
    let was_running = st.core_running();
    {
        let mut g = st.data.lock().unwrap_or_else(|e| e.into_inner());
        g.resume_core = was_running;
        st.persist(&g);
    }
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    st.log(&format!("服务端口切换 {cur} → {p}，重启伴随服务（核心{}）", if was_running { "将在新实例恢复" } else { "未运行" }));
    std::process::Command::new(&exe)
        .args(["--serve", "--port", &p.to_string()])
        .spawn()
        .map_err(|e| format!("manifest 已更新但新进程启动失败: {e}"))?;
    // Let the HTTP response flush before terminating; xray (if any) dies with
    // this process via the Job Object and is restarted by the replacement.
    std::thread::spawn(|| {
        std::thread::sleep(Duration::from_millis(400));
        std::process::exit(0);
    });
    Ok(json!({ "ok": true, "port": p, "restarting": true, "resume_core": was_running }))
}

/// Rewrite <plugin>/manifest.json so `service.port`, `service.health_url` and
/// `service.args` all point at `new_port` — the host re-reads it next launch.
fn update_manifest_port(new_port: u16) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    // Layout: <plugin>/sidecar/xray-service.exe -> <plugin>/manifest.json
    let manifest_path = exe
        .parent()
        .and_then(|d| d.parent())
        .map(|d| d.join("manifest.json"))
        .ok_or_else(|| "cannot resolve plugin dir".to_string())?;

    let raw = std::fs::read_to_string(&manifest_path)
        .map_err(|e| format!("read {}: {e}", manifest_path.display()))?;
    let mut v: Value = serde_json::from_str(&raw).map_err(|e| format!("parse manifest: {e}"))?;

    let cur = HEALTH_PORT.load(Ordering::Relaxed);
    let svc = v
        .get_mut("service")
        .and_then(|s| s.as_object_mut())
        .ok_or("manifest has no service object")?;

    svc.insert("port".into(), json!(new_port));

    if let Some(hu) = svc
        .get("health_url")
        .and_then(|x| x.as_str())
        .map(String::from)
    {
        let updated =
            hu.replace(&format!("127.0.0.1:{cur}"), &format!("127.0.0.1:{new_port}"));
        svc.insert("health_url".into(), json!(updated));
    }

    // Rebuild args: keep everything except port tokens, then ensure --serve
    // and the new --port are present.
    let old_args: Vec<String> = svc
        .get("args")
        .and_then(|a| a.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_default();
    let mut kept: Vec<String> = Vec::new();
    let mut skip_next = false;
    for a in &old_args {
        if skip_next {
            skip_next = false;
            continue;
        }
        if a == "--port" {
            skip_next = true;
            continue;
        }
        if a.starts_with("--port=") || a == "--serve" {
            continue;
        }
        kept.push(a.clone());
    }
    let mut args = vec!["--serve".to_string()];
    args.extend(kept);
    args.push("--port".to_string());
    args.push(new_port.to_string());
    svc.insert("args".into(), json!(args));

    let out = serde_json::to_string_pretty(&v).map_err(|e| e.to_string())?;
    std::fs::write(&manifest_path, out).map_err(|e| format!("write manifest: {e}"))?;
    Ok(())
}

fn parse_rules(v: &Value) -> Result<Vec<xconf::Rule>, String> {
    let arr = v.get("rules").and_then(|x| x.as_array()).ok_or("缺少 rules")?;
    let mut out = Vec::new();
    for r in arr {
        let ob = r.get("outbound").and_then(|x| x.as_str()).unwrap_or("direct").to_string();
        if !matches!(ob.as_str(), "proxy" | "direct" | "block") {
            return Err(format!("未知出站: {ob}"));
        }
        let split = |k: &str| -> Vec<String> {
            r.get(k).and_then(|x| x.as_str()).unwrap_or("")
                .split([',', '，', ';', '；', '\n'])
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        };
        let domain = split("domain");
        let ip = split("ip");
        let port = r.get("port").and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
        let network = r.get("network").and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
        let protocol: Vec<String> = r
            .get("protocol")
            .and_then(|x| x.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_str().map(|s| s.trim().to_string())).filter(|s| !s.is_empty()).collect())
            .unwrap_or_default();
        if domain.is_empty() && ip.is_empty() && port.is_empty() && protocol.is_empty() {
            return Err("存在没有任何匹配条件的规则".into());
        }
        out.push(xconf::Rule { outbound: ob, domain, ip, port, network, protocol });
    }
    if out.len() > 64 {
        return Err("规则过多（上限 64 条）".into());
    }
    Ok(out)
}

fn h_routing_set(st: &State, v: &Value) -> Result<Value, String> {
    let rules = parse_rules(v)?;
    let strategy = jstr(v, "strategy");
    if !matches!(strategy.as_str(), "AsIs" | "IPIfNonMatch" | "IPOnDemand" | "") {
        return Err(format!("未知的域名解析策略: {strategy}"));
    }
    let n = rules.len();
    let r = save_and_restart(st, |p| {
        p.routing = rules;
        if !strategy.is_empty() {
            p.routing_strategy = strategy;
        }
    })?;
    st.log(&format!("路由规则已保存（{n} 条）"));
    Ok(r)
}

fn h_dns_set(st: &State, v: &Value) -> Result<Value, String> {
    let enabled = v.get("enabled").and_then(|x| x.as_bool()).unwrap_or(false);
    let direct = jstr(v, "direct_dns");
    let remote = jstr(v, "remote_dns");
    let bootstrap = jstr(v, "bootstrap_dns");
    if enabled && direct.is_empty() && remote.is_empty() {
        return Err("启用 DNS 时至少填一个 DNS 服务器".into());
    }
    // per-outbound resolve strategies, v2rayN DomainStrategy values; "" = default
    let ok_strat = |s: &str| matches!(s, "" | "AsIs" | "UseIP" | "UseIPv4v6" | "UseIPv6v4" | "UseIPv4" | "UseIPv6");
    let strategy_direct = jstr(v, "strategy_direct");
    let strategy_remote = jstr(v, "strategy_remote");
    let strategy_dial = jstr(v, "strategy_dial");
    for (name, s) in [
        ("直连解析策略", &strategy_direct),
        ("远程解析策略", &strategy_remote),
        ("代理拨号解析策略", &strategy_dial),
    ] {
        if !ok_strat(s) {
            return Err(format!("未知的{name}: {s}"));
        }
    }
    let block_aaaa = v.get("block_aaaa").and_then(|x| x.as_bool()).unwrap_or(false);
    let parallel_query = v.get("parallel_query").and_then(|x| x.as_bool()).unwrap_or(false);
    let serve_stale = v.get("serve_stale").and_then(|x| x.as_bool()).unwrap_or(false);
    let r = save_and_restart(st, |p| {
        p.dns = xconf::DnsCfg {
            enabled,
            direct_dns: direct.clone(),
            remote_dns: remote.clone(),
            bootstrap_dns: bootstrap.clone(),
            strategy_direct: strategy_direct.clone(),
            strategy_remote: strategy_remote.clone(),
            strategy_dial: strategy_dial.clone(),
            block_aaaa,
            parallel_query,
            serve_stale,
        };
    })?;
    st.log(&format!(
        "DNS 设置已保存（{}，直连 {} / 远程 {} / bootstrap {}）",
        if enabled { "启用" } else { "停用" },
        if direct.is_empty() { "默认" } else { &direct },
        if remote.is_empty() { "默认" } else { &remote },
        if bootstrap.is_empty() { "默认" } else { &bootstrap },
    ));
    Ok(r)
}

// ---------- route handlers ----------

fn h_nodes(st: &State) -> Value {
    let p = st.data.lock().unwrap_or_else(|e| e.into_inner());
    json!({ "nodes": p.nodes, "selected": p.selected })
}

fn h_import(st: &State, v: &Value) -> Result<Value, String> {
    let text = jstr(v, "text");
    let sub_id = jstr(v, "sub_id");
    if text.is_empty() {
        return Err("导入内容为空".into());
    }
    let (parsed, errors) = node::parse_bulk(&text);
    let total = parsed.len();
    let mut added = 0usize;
    {
    let mut p = st.data.lock().unwrap_or_else(|e| e.into_inner());
    for mut n in parsed {
        n.sub_id = sub_id.clone();
        // refresh in place when the same proto/addr/port/credential/sub
        // already exists, so re-importing a subscription never piles up.
        // Index-based: reading p.selected while holding an iter_mut() item
        // would trip E0502 (field borrows through the MutexGuard cover the
        // whole struct).
        if let Some(pos) = p.nodes.iter().position(|o| {
            o.proto == n.proto && o.add == n.add && o.port == n.port && o.uuid == n.uuid && o.sub_id == n.sub_id
        }) {
            let keep_id = p.nodes[pos].id.clone();
            let was_selected = p.selected == keep_id;
            n.id = keep_id.clone();
            p.nodes[pos] = n;
            if was_selected {
                p.selected = keep_id;
            }
        } else {
            p.nodes.push(n);
            added += 1;
        }
    }
        st.persist(&p);
        st.log(&format!("导入完成：新增 {added}，刷新 {}（订阅 {}）", total - added, if sub_id.is_empty() { "手动" } else { &sub_id }));
    }
    Ok(json!({ "ok": true, "added": added, "total": total, "errors": errors }))
}

fn h_select(st: &State, v: &Value) -> Result<Value, String> {
    let id = jstr(v, "id");
    let mut p = st.data.lock().unwrap_or_else(|e| e.into_inner());
    if !p.nodes.iter().any(|n| n.id == id) {
        return Err("节点不存在".into());
    }
    p.selected = id;
    st.persist(&p);
    Ok(json!({ "ok": true, "selected": p.selected }))
}

fn h_delete(st: &State, v: &Value) -> Result<Value, String> {
    let id = jstr(v, "id");
    let mut p = st.data.lock().unwrap_or_else(|e| e.into_inner());
    let before = p.nodes.len();
    p.nodes.retain(|n| n.id != id);
    if p.selected == id {
        p.selected = String::new();
    }
    let removed = before - p.nodes.len();
    st.persist(&p);
    Ok(json!({ "ok": true, "removed": removed }))
}

fn h_share(st: &State, v: &Value) -> Result<Value, String> {
    let id = jstr(v, "id");
    let p = st.data.lock().unwrap_or_else(|e| e.into_inner());
    let n = p.nodes.iter().find(|n| n.id == id).ok_or("节点不存在")?;
    Ok(json!({ "ok": true, "link": n.to_share_link() }))
}

fn h_tcping(st: &State, v: &Value) -> Result<Value, String> {
    let id = jstr(v, "id");
    let mut results = serde_json::Map::new();
    let targets: Vec<Node> = {
        let p = st.data.lock().unwrap_or_else(|e| e.into_inner());
        if id.is_empty() {
            p.nodes.clone()
        } else {
            p.nodes.iter().filter(|n| n.id == id).cloned().collect()
        }
    };
    for chunk in targets.chunks(16) {
        let handles: Vec<_> = chunk
            .iter()
            .map(|n| {
                let n = n.clone();
                std::thread::spawn(move || {
                    let ms = net::tcping(&n.add, n.port, 2000);
                    (n.id.clone(), ms)
                })
            })
            .collect();
        for h in handles {
            if let Ok((id, ms)) = h.join() {
                results.insert(id, json!(ms));
            }
        }
    }
    // persist the caches
    let mut p = st.data.lock().unwrap_or_else(|e| e.into_inner());
    for n in p.nodes.iter_mut() {
        if let Some(Value::Number(num)) = results.get(&n.id) {
            if let Some(ms) = num.as_u64() {
                n.tcping_ms = ms as u32;
            }
        } else {
            n.tcping_ms = 0;
        }
    }
    st.persist(&p);
    Ok(json!({ "ok": true, "results": results }))
}

fn h_real(st: &State) -> Result<Value, String> {
    if !st.core_running() {
        return Err("核心未运行，先启动核心再测真延迟".into());
    }
    let http = st.data.lock().unwrap_or_else(|e| e.into_inner()).http_port;
    match net::real_latency(http, 8000) {
        Some(ms) => {
            let mut p = st.data.lock().unwrap_or_else(|e| e.into_inner());
            let sel = p.selected.clone();
            if let Some(n) = p.nodes.iter_mut().find(|n| n.id == sel) {
                n.real_ms = ms;
            }
            st.persist(&p);
            Ok(json!({ "ok": true, "ms": ms }))
        }
        None => Err("真延迟探测失败（节点不通或超时）".into()),
    }
}

fn h_subs(st: &State) -> Value {
    let p = st.data.lock().unwrap_or_else(|e| e.into_inner());
    json!({ "subs": p.subs })
}

fn h_subs_add(st: &State, v: &Value) -> Result<Value, String> {
    let url = jstr(v, "url");
    let name = jstr(v, "name");
    if url.is_empty() || !url.starts_with("http") {
        return Err("订阅地址无效".into());
    }
    let mut p = st.data.lock().unwrap_or_else(|e| e.into_inner());
    let sub = Sub { id: id_gen(), name: if name.is_empty() { "订阅".into() } else { name }, url, last_update: String::new(), count: 0 };
    p.subs.push(sub);
    st.persist(&p);
    Ok(json!({ "ok": true }))
}

fn h_subs_delete(st: &State, v: &Value) -> Result<Value, String> {
    let id = jstr(v, "id");
    let mut p = st.data.lock().unwrap_or_else(|e| e.into_inner());
    p.subs.retain(|s| s.id != id);
    // keep the nodes but orphan them? cleaner: drop nodes of that sub too
    p.nodes.retain(|n| n.sub_id != id);
    if !p.nodes.iter().any(|n| n.id == p.selected) {
        p.selected = String::new();
    }
    st.persist(&p);
    Ok(json!({ "ok": true }))
}

fn h_subs_update(st: &State, v: &Value) -> Result<Value, String> {
    let id = jstr(v, "id");
    let (url, name) = {
        let p = st.data.lock().unwrap_or_else(|e| e.into_inner());
        let s = p.subs.iter().find(|s| s.id == id).ok_or("订阅不存在")?;
        (s.url.clone(), s.name.clone())
    };
    let body = http_get_auto(st, "订阅", &url, 30)?;
    let text = String::from_utf8_lossy(&body);
    let (nodes, errors) = node::parse_bulk(&text);
    if nodes.is_empty() {
        return Err(format!("订阅未解析出节点（{} 条错误）{}", errors.len(), if errors.is_empty() { String::new() } else { format!("：{}", errors[0]) }));
    }
    let count = nodes.len();
    let mut p = st.data.lock().unwrap_or_else(|e| e.into_inner());
    // drop previous nodes of this subscription, then import fresh
    p.nodes.retain(|n| n.sub_id != id);
    let mut nodes = nodes;
    for n in nodes.iter_mut() {
        n.sub_id = id.clone();
    }
    p.nodes.extend(nodes);
    if let Some(s) = p.subs.iter_mut().find(|s| s.id == id) {
        s.last_update = stamp();
        s.count = count;
    }
    if !p.nodes.iter().any(|n| n.id == p.selected) {
        p.selected = String::new();
    }
    st.persist(&p);
    st.log(&format!("订阅「{name}」更新：{count} 个节点"));
    Ok(json!({ "ok": true, "count": count, "errors": errors }))
}

fn h_sysproxy(st: &State, v: &Value) -> Result<Value, String> {
    let on = v.get("on").and_then(|x| x.as_bool()).ok_or("缺少 on")?;
    let http = st.data.lock().unwrap_or_else(|e| e.into_inner()).http_port;
    winapi::set_system_proxy(on, http)?;
    st.log(&format!("系统代理 {}", if on { "开启" } else { "关闭" }));
    Ok(json!({ "ok": true, "on": on }))
}

/// TUN switch: toggling persists `tun_on` and restarts the core if it is
/// running, so the `tun` inbound is added/removed atomically with the rest of
/// the config. Requires admin rights (wintun adapter creation); the usual
/// startup-failure path surfaces the xray log tail when that's missing.
fn h_tun(st: &State, v: &Value) -> Result<Value, String> {
    let on = v.get("on").and_then(|x| x.as_bool()).ok_or("缺少 on")?;
    let was_running = st.core_running();
    {
        let mut p = st.data.lock().unwrap_or_else(|e| e.into_inner());
        p.tun_on = on;
        st.persist(&p);
    }
    st.log(&format!("TUN {}", if on { "开启（下次核心启动挂载 tun 入站）" } else { "关闭" }));
    if was_running {
        core_start(st)?;
        st.log("核心已按 TUN 状态重启");
    }
    Ok(json!({ "ok": true, "tun": on, "restarted": was_running }))
}

/// `xray.exe version` with an mtime-keyed cache — never spawn a child on
/// every health poll. Must be called WITHOUT the data lock held.
fn xray_version_cached(st: &State) -> String {
    let exe = st.xray_exe();
    if !exe.is_file() {
        return String::new();
    }
    let mtime = std::fs::metadata(&exe)
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut c = st.xray_ver.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((m, v)) = c.as_ref() {
        if *m == mtime {
            return v.clone();
        }
    }
    let v = net::xray_version(&exe).unwrap_or_default();
    *c = Some((mtime, v.clone()));
    v
}

fn h_health(st: &State) -> Value {
    // Snapshot under the data lock only — registry reads, child-process
    // spawns and everything blocking happen AFTER the lock is released. A
    // health poll must never be able to wedge the data lock.
    let (selected, node_count, http_port, socks_port, running, tun_on) = {
        let p = st.data.lock().unwrap_or_else(|e| e.into_inner());
        let running = st.core_running();
        (p.selected.clone(), p.nodes.len(), p.http_port, p.socks_port, running, p.tun_on)
    };
    let (sp_enabled, sp_ours) = winapi::system_proxy_state(http_port);
    let xray_version = xray_version_cached(st);
    json!({
        "status": "ok",
        "version": VERSION,
        "port": HEALTH_PORT.load(Ordering::Relaxed),
        "xray_installed": st.xray_installed(),
        "xray_version": xray_version,
        "geo_ready": {
            "geoip": st.bin_dir.join("geoip.dat").is_file(),
            "geosite": st.bin_dir.join("geosite.dat").is_file(),
        },
        "running": running,
        "switch": running && sp_ours,
        "selected": selected,
        "nodes": node_count,
        "sysproxy": { "enabled": sp_enabled, "ours": sp_ours },
        "tun": tun_on,
        "socks_port": socks_port,
        "http_port": http_port,
    })
}

fn route(st: &Arc<State>, method: &str, path: &str, body: &[u8]) -> Result<Value, String> {
    let v = body_json(body);
    match (method, path) {
        ("GET", "/api/health") => Ok(h_health(st)),
        ("GET", "/api/nodes") => Ok(h_nodes(st)),
        ("POST", "/api/nodes/import") => h_import(st, &v),
        ("POST", "/api/nodes/select") => h_select(st, &v),
        ("POST", "/api/nodes/delete") => h_delete(st, &v),
        ("POST", "/api/nodes/clear") => {
            let mut p = st.data.lock().unwrap_or_else(|e| e.into_inner());
            p.nodes.clear();
            p.selected = String::new();
            st.persist(&p);
            Ok(json!({ "ok": true }))
        }
        ("POST", "/api/nodes/share") => h_share(st, &v),
        ("POST", "/api/test/tcping") => h_tcping(st, &v),
        ("POST", "/api/test/real") => h_real(st),
        ("GET", "/api/subs") => Ok(h_subs(st)),
        ("POST", "/api/subs/add") => h_subs_add(st, &v),
        ("POST", "/api/subs/delete") => h_subs_delete(st, &v),
        ("POST", "/api/subs/update") => h_subs_update(st, &v),
        ("POST", "/api/core/start") => core_start(st),
        ("POST", "/api/core/stop") => core_stop(st),
        ("POST", "/api/core/restart") => {
            core_stop(st)?;
            core_start(st)
        }
        ("POST", "/api/core/download") => core_download(st, &jstr(&v, "mirror")),
        ("POST", "/api/geo/download") => geo_download(st, &jstr(&v, "mirror")),
        ("POST", "/api/proxy/toggle") => h_proxy_toggle(st, &v),
        ("GET", "/api/settings") => Ok(h_settings(st)),
        ("POST", "/api/ports/check") => Ok(h_ports_check(st, &v)),
        ("POST", "/api/ports/set") => h_ports_set(st, &v),
        ("POST", "/api/service_port/check") => h_service_port_check(st, &v),
        ("POST", "/api/service_port/set") => h_service_port_set(st, &v),
        ("POST", "/api/routing/set") => h_routing_set(st, &v),
        ("POST", "/api/dns/set") => h_dns_set(st, &v),
        ("GET", "/api/log") => {
            let ring = st.logs.lock().unwrap_or_else(|e| e.into_inner());
            Ok(json!({ "log": ring.iter().cloned().collect::<Vec<_>>().join("\n") }))
        }
        ("POST", "/api/sysproxy") => h_sysproxy(st, &v),
        ("POST", "/api/tun") => h_tun(st, &v),
        ("GET", "/api/sysproxy") => {
            let p = st.data.lock().unwrap_or_else(|e| e.into_inner());
            let (enabled, ours) = winapi::system_proxy_state(p.http_port);
            Ok(json!({ "enabled": enabled, "ours": ours }))
        }
        _ => Err(format!("unknown endpoint {method} {path}")),
    }
}

// ---------- main ----------

static HEALTH_PORT: AtomicU16 = AtomicU16::new(18957);

fn serve(mut stream: TcpStream, st: Arc<State>) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
    let Some((method, path, body)) = read_request(&mut stream) else {
        return;
    };
    if method == "OPTIONS" {
        json_resp(&mut stream, 204, &json!({}));
        return;
    }
    match route(&st, &method, &path, &body) {
        Ok(v) => json_resp(&mut stream, 200, &v),
        Err(e) => {
            st.log(&format!("[{method} {path}] {e}"));
            err_resp(&mut stream, &e);
        }
    }
}

fn load_state(data_dir: &Path) -> Persist {
    let mut p: Persist = std::fs::read_to_string(data_dir.join("state.json"))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    // Persist::default() zeroes the ports (serde(default=) only fires for
    // missing fields in an existing file, not for a wholly absent file), so
    // re-anchor them here — a fresh install must get 20808/20809.
    if p.socks_port == 0 {
        p.socks_port = default_socks();
    }
    if p.http_port == 0 {
        p.http_port = default_http();
    }
    p
}

fn main() {
    let mut args = std::env::args().skip(1);
    let mut serve_mode = false;
    let mut port: u16 = 18957;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--serve" => serve_mode = true,
            "--port" => {
                if let Some(p) = args.next().and_then(|x| x.parse().ok()) {
                    port = p;
                }
            }
            _ => {}
        }
    }
    if !serve_mode {
        println!("xray-service {VERSION} — 用 --serve --port N 启动");
        return;
    }

    // exe lives at <plugin>/sidecar/xray-service.exe → data dir <plugin>/data
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."));
    let plugin_dir = exe_dir.parent().map(|p| p.to_path_buf()).unwrap_or_else(|| exe_dir.clone());
    let data_dir = plugin_dir.join("data");
    let bin_dir = data_dir.join("bin");
    std::fs::create_dir_all(&data_dir).ok();
    std::fs::create_dir_all(&bin_dir).ok();

    let st = Arc::new(State {
        data: Mutex::new(load_state(&data_dir)),
        core: Mutex::new(None),
        logs: Mutex::new(VecDeque::new()),
        data_dir,
        bin_dir,
        xray_ver: Mutex::new(None),
    });

    // The struct doesn't carry the port; store it in a static for health.
    HEALTH_PORT.store(port, Ordering::Relaxed);

    // sweep leftover `.old` backups from previous locked-file updates
    cleanup_old_files(&st);

    // System proxy defaults to OFF on every service start: if the registry
    // still points at our HTTP port from a previous session, restore it. A
    // proxy the user set themselves (not ours) is left untouched.
    {
        let http = st.data.lock().unwrap_or_else(|e| e.into_inner()).http_port;
        let (enabled, ours) = winapi::system_proxy_state(http);
        if enabled && ours {
            match winapi::set_system_proxy(false, http) {
                Ok(()) => st.log("服务启动：系统代理恢复默认关闭"),
                Err(e) => st.log(&format!("服务启动：系统代理还原失败: {e}")),
            }
        }
    }

    // xray crash watcher: keep the state honest if the core dies on its own.
    {
        let st2 = st.clone();
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_secs(2));
            st2.core_running();
        });
    }

    // Port handover: /api/service_port/set spawns a replacement before the
    // old process releases the listener, so retry the bind briefly to absorb
    // the gap. Cold starts succeed on the first attempt.
    let listener = match bind_with_retry(port) {
        Ok(l) => l,
        Err(e) => {
            st.log(&format!("端口 {port} 绑定失败: {e}"));
            eprintln!("bind {port} failed: {e}");
            std::process::exit(2);
        }
    };

    // Resume the core after a port-switch handover (or if the flag was left
    // set by an unclean exit while the core was running).
    if st.data.lock().unwrap_or_else(|e| e.into_inner()).resume_core {
        let st3 = st.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(800));
            match core_start(&st3) {
                Ok(_) => {
                    st3.log("服务重启后核心已自动恢复");
                    let mut p = st3.data.lock().unwrap_or_else(|e| e.into_inner());
                    p.resume_core = false;
                    st3.persist(&p);
                }
                Err(e) => st3.log(&format!("核心自动恢复失败: {e}")),
            }
        });
    }

    eprintln!("xray-service {VERSION} listening on 127.0.0.1:{port}");
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let st2 = st.clone();
                std::thread::spawn(move || serve(s, st2));
            }
            Err(_) => continue,
        }
    }
}

/// Retry the listener bind for up to 5s — covers the port-handover gap where
/// the previous instance is still shutting down.
fn bind_with_retry(port: u16) -> std::io::Result<TcpListener> {
    let mut last: Option<std::io::Error> = None;
    for _ in 0..25 {
        match TcpListener::bind(("127.0.0.1", port)) {
            Ok(l) => return Ok(l),
            Err(e) => {
                last = Some(e);
                std::thread::sleep(Duration::from_millis(200));
            }
        }
    }
    Err(last.unwrap_or_else(|| std::io::Error::other("bind failed")))
}
