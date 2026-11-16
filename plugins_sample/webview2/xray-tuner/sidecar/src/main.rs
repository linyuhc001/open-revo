// xray-service — OpenRevo xray-tuner companion service.
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
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use windows_sys::Win32::Foundation::HANDLE;

const VERSION: &str = "0.9.0";
const LOG_RING: usize = 400;

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
    core: Mutex<Option<HANDLE>>,
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
            if winapi::is_running(*h) {
                return true;
            }
            self.log("xray 进程已退出");
            *guard = None;
        }
        false
    }

    fn take_core(&self) -> Option<HANDLE> {
        let mut guard = self.core.lock().unwrap();
        let h = guard.take();
        if let Some(h) = h {
            if winapi::is_running(h) {
                winapi::kill(h);
            }
        }
        None
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
    let cfg = xconf::build_config(&node, &ports)?;
    let cfg_path = st.data_dir.join("config.json");
    std::fs::write(&cfg_path, &cfg).map_err(|e| format!("写配置失败: {e}"))?;

    // take down any previous instance first
    let mut guard = st.core.lock().unwrap();
    if let Some(h) = guard.take() {
        if winapi::is_running(h) {
            winapi::kill(h);
            std::thread::sleep(Duration::from_millis(300));
        }
    }
    drop(p);
    drop(guard);

    st.log(&format!("启动 xray：节点「{}」({})", node.name, node.addr_port()));
    let handle = winapi::spawn_tracked(
        st.xray_exe().to_str().ok_or("路径含非 UTF-8")?,
        &["run", "-c", cfg_path.to_str().ok_or("配置路径非 UTF-8")?],
        Some(&st.bin_dir),
    )?;
    *st.core.lock().unwrap() = Some(handle);
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
    Ok(json!({ "ok": true, "version": ver, "files": files.len() }))
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
            // already exists, so re-importing a subscription never piles up
            if let Some(old) = p.nodes.iter_mut().find(|o| {
                o.proto == n.proto && o.add == n.add && o.port == n.port && o.uuid == n.uuid && o.sub_id == n.sub_id
            }) {
                let keep_id = old.id.clone();
                let was_selected = p.selected == keep_id;
                *old = n;
                old.id = keep_id;
                if was_selected {
                    p.selected = old.id.clone();
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
            if let Some(n) = p.nodes.iter_mut().find(|n| n.id == p.selected) {
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
    json!({
        "status": "ok",
        "version": VERSION,
        "port": HEALTH_PORT.load(Ordering::Relaxed),
        "xray_installed": st.xray_installed(),
        "xray_version": xray_version,
        "running": st.core_running(),
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

static HEALTH_PORT: AtomicU32 = AtomicU32::new(18957);

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
    std::fs::read_to_string(data_dir.join("state.json"))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
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
