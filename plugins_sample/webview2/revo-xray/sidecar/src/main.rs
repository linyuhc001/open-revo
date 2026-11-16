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

const VERSION: &str = "0.9.2";
const LOG_RING: usize = 400;
/// v2rayN's geo template: Global.GeoUrl in ServiceLib/Global.cs.
/// `{0}` is filled with "geoip" / "geosite".
const GEO_URL_TEMPLATE: &str =
    "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download";

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
    #[serde(default)]
    dns: xconf::DnsCfg,
}

fn default_socks() -> u16 { 10808 }
fn default_http() -> u16 { 10809 }

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
            let mut ring = self.logs.lock().unwrap();
            if ring.len() >= LOG_RING {
                ring.pop_front();
            }
            ring.push_back(line.clone());
        }
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.data_dir.join("service.log"))
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
        let mut guard = self.core.lock().unwrap();
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
        let mut guard = self.core.lock().unwrap();
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
        let guard = self.core.lock().unwrap();
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
    let mut p = st.data.lock().unwrap();
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
    let cfg = xconf::build_config(&node, &ports, geoip_ok, geosite_ok, &rules, &dns)?;
    let cfg_path = st.data_dir.join("config.json");
    std::fs::write(&cfg_path, &cfg).map_err(|e| format!("写配置失败: {e}"))?;

    // take down any previous instance first
    let mut guard = st.core.lock().unwrap();
    if let Some(h) = guard.take() {
        if winapi::is_running(h.0) {
            winapi::kill(h.0);
            std::thread::sleep(Duration::from_millis(300));
        }
    }
    drop(p);
    drop(guard);

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
    *st.core.lock().unwrap() = Some(winapi::CoreHandle(handle));
    std::thread::sleep(Duration::from_millis(500));
    if !winapi::is_running(handle) {
        *st.core.lock().unwrap() = None;
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

fn core_download(st: &State, mirror: &str) -> Result<Value, String> {
    let url = if mirror.is_empty() {
        net::XRAY_RELEASE_URL.to_string()
    } else {
        format!("{}{}", mirror.trim_end_matches('/'), "/XTLS/Xray-core/releases/latest/download/Xray-windows-64.zip")
    };
    st.log(&format!("开始下载内核：{url}"));
    let zip_bytes = net::http_get(&url, 120)?;
    st.log(&format!("内核下载完成 {} 字节，解压中", zip_bytes.len()));
    let zip_path = st.data_dir.join("xray-core.zip");
    std::fs::write(&zip_path, &zip_bytes).map_err(|e| format!("写 zip 失败: {e}"))?;
    std::fs::create_dir_all(&st.bin_dir).ok();
    let files = net::unzip_into(&zip_path, &st.bin_dir)?;
    let _ = std::fs::remove_file(&zip_path);
    let ver = net::xray_version(&st.xray_exe()).unwrap_or_else(|| "unknown".into());
    st.log(&format!("内核就绪：{}（{} 个文件）", ver, files.len()));
    // recent Xray zips no longer ship the geo dat files; grab them separately
    // (best-effort — the panel keeps working without them, just without CN rules)
    let missing = !st.bin_dir.join("geoip.dat").is_file() || !st.bin_dir.join("geosite.dat").is_file();
    if missing {
        match geo_download(st, mirror) {
            Ok(_) => {}
            Err(e) => st.log(&format!("geo 文件下载失败（可稍后点「下载 Geo 文件」重试）: {e}")),
        }
    }
    Ok(json!({ "ok": true, "version": ver, "files": files.len() }))
}

fn geo_download(st: &State, mirror: &str) -> Result<Value, String> {
    let base = if mirror.is_empty() {
        GEO_URL_TEMPLATE.to_string()
    } else {
        format!("{}{}", mirror.trim_end_matches('/'), "/Loyalsoldier/v2ray-rules-dat/releases/latest/download")
    };
    std::fs::create_dir_all(&st.bin_dir).ok();
    let mut done = Vec::new();
    for name in ["geoip.dat", "geosite.dat"] {
        let url = format!("{base}/{name}");
        st.log(&format!("下载 {name}：{url}"));
        let body = net::http_get(&url, 180)?;
        std::fs::write(st.bin_dir.join(name), &body).map_err(|e| format!("写 {name} 失败: {e}"))?;
        done.push(format!("{name} {:.1}MB", body.len() as f64 / 1e6));
    }
    st.log(&format!("Geo 文件就绪：{}", done.join(" / ")));
    Ok(json!({ "ok": true, "files": done }))
}

/// Master switch, v2rayN style: one toggle = core up + system proxy taken
/// over (on), or system proxy restored + core stopped (off).
fn h_proxy_toggle(st: &State, v: &Value) -> Result<Value, String> {
    let on = v.get("on").and_then(|x| x.as_bool()).ok_or("缺少 on")?;
    if on {
        core_start(st)?;
        let http = st.data.lock().unwrap().http_port;
        winapi::set_system_proxy(true, http)?;
        st.log("总开关：代理开启（核心运行 + 系统代理已接管）");
    } else {
        let http = st.data.lock().unwrap().http_port;
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
        let mut p = st.data.lock().unwrap();
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
    let p = st.data.lock().unwrap();
    json!({
        "socks_port": p.socks_port,
        "http_port": p.http_port,
        "routing": p.routing,
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
        if domain.is_empty() && ip.is_empty() {
            return Err("存在既无域名也无 IP 的规则".into());
        }
        out.push(xconf::Rule { outbound: ob, domain, ip });
    }
    if out.len() > 64 {
        return Err("规则过多（上限 64 条）".into());
    }
    Ok(out)
}

fn h_routing_set(st: &State, v: &Value) -> Result<Value, String> {
    let rules = parse_rules(v)?;
    let n = rules.len();
    let r = save_and_restart(st, |p| p.routing = rules)?;
    st.log(&format!("路由规则已保存（{n} 条）"));
    Ok(r)
}

fn h_dns_set(st: &State, v: &Value) -> Result<Value, String> {
    let enabled = v.get("enabled").and_then(|x| x.as_bool()).unwrap_or(false);
    let servers: Vec<String> = v
        .get("servers")
        .and_then(|x| x.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()))
                .collect()
        })
        .unwrap_or_default();
    if enabled && servers.is_empty() {
        return Err("启用 DNS 时至少填一个服务器".into());
    }
    let mut strat = jstr(v, "query_strategy");
    if !matches!(strat.as_str(), "UseIP" | "UseIPv4" | "UseIPv6") {
        strat = "UseIP".into();
    }
    let n = servers.len();
    let r = save_and_restart(st, |p| {
        p.dns = xconf::DnsCfg { enabled, servers: servers.clone(), query_strategy: strat.clone() };
    })?;
    st.log(&format!(
        "DNS 设置已保存（{}，{n} 个服务器）",
        if enabled { "启用" } else { "停用" }
    ));
    Ok(r)
}

// ---------- route handlers ----------

fn h_nodes(st: &State) -> Value {
    let p = st.data.lock().unwrap();
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
    let mut p = st.data.lock().unwrap();
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
    let mut p = st.data.lock().unwrap();
    if !p.nodes.iter().any(|n| n.id == id) {
        return Err("节点不存在".into());
    }
    p.selected = id;
    st.persist(&p);
    Ok(json!({ "ok": true, "selected": p.selected }))
}

fn h_delete(st: &State, v: &Value) -> Result<Value, String> {
    let id = jstr(v, "id");
    let mut p = st.data.lock().unwrap();
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
    let p = st.data.lock().unwrap();
    let n = p.nodes.iter().find(|n| n.id == id).ok_or("节点不存在")?;
    Ok(json!({ "ok": true, "link": n.to_share_link() }))
}

fn h_tcping(st: &State, v: &Value) -> Result<Value, String> {
    let id = jstr(v, "id");
    let mut results = serde_json::Map::new();
    let targets: Vec<Node> = {
        let p = st.data.lock().unwrap();
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
    let mut p = st.data.lock().unwrap();
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
    let http = st.data.lock().unwrap().http_port;
    match net::real_latency(http, 8000) {
        Some(ms) => {
            let mut p = st.data.lock().unwrap();
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
    let p = st.data.lock().unwrap();
    json!({ "subs": p.subs })
}

fn h_subs_add(st: &State, v: &Value) -> Result<Value, String> {
    let url = jstr(v, "url");
    let name = jstr(v, "name");
    if url.is_empty() || !url.starts_with("http") {
        return Err("订阅地址无效".into());
    }
    let mut p = st.data.lock().unwrap();
    let sub = Sub { id: id_gen(), name: if name.is_empty() { "订阅".into() } else { name }, url, last_update: String::new(), count: 0 };
    p.subs.push(sub);
    st.persist(&p);
    Ok(json!({ "ok": true }))
}

fn h_subs_delete(st: &State, v: &Value) -> Result<Value, String> {
    let id = jstr(v, "id");
    let mut p = st.data.lock().unwrap();
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
        let p = st.data.lock().unwrap();
        let s = p.subs.iter().find(|s| s.id == id).ok_or("订阅不存在")?;
        (s.url.clone(), s.name.clone())
    };
    let body = net::http_get(&url, 30)?;
    let text = String::from_utf8_lossy(&body);
    let (nodes, errors) = node::parse_bulk(&text);
    if nodes.is_empty() {
        return Err(format!("订阅未解析出节点（{} 条错误）{}", errors.len(), if errors.is_empty() { String::new() } else { format!("：{}", errors[0]) }));
    }
    let count = nodes.len();
    let mut p = st.data.lock().unwrap();
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
    let http = st.data.lock().unwrap().http_port;
    winapi::set_system_proxy(on, http)?;
    st.log(&format!("系统代理 {}", if on { "开启" } else { "关闭" }));
    Ok(json!({ "ok": true, "on": on }))
}

fn h_health(st: &State) -> Value {
    let p = st.data.lock().unwrap();
    let (sp_enabled, sp_ours) = winapi::system_proxy_state(p.http_port);
    let exe = st.xray_exe();
    let xray_version = if exe.is_file() {
        net::xray_version(&exe).unwrap_or_default()
    } else {
        String::new()
    };
    let running = st.core_running();
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
        "selected": p.selected,
        "nodes": p.nodes.len(),
        "sysproxy": { "enabled": sp_enabled, "ours": sp_ours },
        "socks_port": p.socks_port,
        "http_port": p.http_port,
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
            let mut p = st.data.lock().unwrap();
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
        ("POST", "/api/routing/set") => h_routing_set(st, &v),
        ("POST", "/api/dns/set") => h_dns_set(st, &v),
        ("GET", "/api/log") => {
            let ring = st.logs.lock().unwrap();
            Ok(json!({ "log": ring.iter().cloned().collect::<Vec<_>>().join("\n") }))
        }
        ("POST", "/api/sysproxy") => h_sysproxy(st, &v),
        ("GET", "/api/sysproxy") => {
            let p = st.data.lock().unwrap();
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
    // re-anchor them here — a fresh install must get 10808/10809.
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
    });

    // The struct doesn't carry the port; store it in a static for health.
    HEALTH_PORT.store(port, Ordering::Relaxed);

    // xray crash watcher: keep the state honest if the core dies on its own.
    {
        let st2 = st.clone();
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_secs(2));
            st2.core_running();
        });
    }

    st.log(&format!("xray-service {VERSION} starting on 127.0.0.1:{port}"));

    match TcpListener::bind(("127.0.0.1", port)) {
        Ok(listener) => {
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
        Err(e) => {
            st.log(&format!("端口 {port} 绑定失败: {e}"));
            eprintln!("bind {port} failed: {e}");
        }
    }
}
