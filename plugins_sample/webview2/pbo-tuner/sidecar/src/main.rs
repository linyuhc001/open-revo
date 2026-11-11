// OpenRevo PBO service — companion sidecar for the pbo-tuner plugin.
//
// Why this exists: the PBO feature originally lived in the OpenRevo host
// (`smu_*` commands in src-tauri), which meant every release needed host
// source changes. This binary carries the same code so the plugin is
// self-contained: the host only has to launch it via the manifest `service`
// block, and nothing in src-tauri has to know about AMD SMU.
//
// Protocol: plain HTTP on 127.0.0.1, one endpoint per former Tauri command.
// The page's `rpc()` helper posts JSON and reads `result` back. No framework,
// no async runtime — std::net plus two serde crates, so the build is fast and
// the binary stays small.

mod pawnio;
mod smu;

use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;

const VERSION: &str = "1.0.0";
const DEFAULT_PORT: u16 = 18955;

fn main() {
    let port = parse_port();
    log(&format!("pbo-service {VERSION} starting on 127.0.0.1:{port}"));

    // Announce the profile path early: the only way to debug a "profile not
    // found" report is to know which directory the service resolved.
    log(&format!("config dir: {}", config_dir().display()));

    let listener = match TcpListener::bind(("127.0.0.1", port)) {
        Ok(l) => l,
        Err(e) => {
            log(&format!("bind failed: {e}"));
            std::process::exit(2);
        }
    };

    // The host launches this at boot with auto_start, before any plugin tab
    // exists — that is what makes "apply my profile on startup" possible now
    // that the host no longer runs it.
    std::thread::spawn(|| {
        std::thread::sleep(std::time::Duration::from_secs(8));
        match auto_apply_profile() {
            Ok(msg) => log(&format!("auto-apply: {msg}")),
            Err(e) => log(&format!("auto-apply skipped: {e}")),
        }
    });

    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                std::thread::spawn(move || {
                    let _ = handle(s);
                });
            }
            Err(e) => log(&format!("accept failed: {e}")),
        }
    }
}

fn parse_port() -> u16 {
    let args: Vec<String> = std::env::args().collect();
    let mut i = 0;
    while i < args.len() {
        if let Some(v) = args[i].strip_prefix("--port=") {
            return v.parse().unwrap_or(DEFAULT_PORT);
        }
        if args[i] == "--port" {
            if let Some(v) = args.get(i + 1) {
                return v.parse().unwrap_or(DEFAULT_PORT);
            }
        }
        i += 1;
    }
    DEFAULT_PORT
}

// ---- HTTP plumbing ----

fn handle(mut stream: TcpStream) -> std::io::Result<()> {
    stream.set_read_timeout(Some(std::time::Duration::from_secs(15)))?;

    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 8192];
    let head_end;
    loop {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(p) = find(&buf, b"\r\n\r\n") {
            head_end = p + 4;
            break;
        }
        if buf.len() > 128 * 1024 {
            return Ok(());
        }
    }

    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or("").to_string();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("").to_string();

    let content_length = lines
        .filter_map(|l| {
            let (k, v) = l.split_once(':')?;
            if k.eq_ignore_ascii_case("content-length") {
                v.trim().parse::<usize>().ok()
            } else {
                None
            }
        })
        .next()
        .unwrap_or(0);

    let mut body = buf[head_end..].to_vec();
    while body.len() < content_length {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }

    // A browser page on a different origin (file:// or the host's webview)
    // always preflights a JSON POST.
    if method == "OPTIONS" {
        return write_response(&mut stream, 204, "");
    }

    let result = route(&method, &path, &body);
    match result {
        Ok(v) => write_response(&mut stream, 200, &v.to_string()),
        Err(e) => write_response(&mut stream, 200, &json!({ "__error": e }).to_string()),
    }
}

fn route(method: &str, path: &str, body: &[u8]) -> Result<Value, String> {
    if method == "GET" && path == "/api/health" {
        return Ok(json!({
            "status": "ok",
            "version": VERSION,
            "cpu": smu::cpu_name(),
        }));
    }
    if method != "POST" {
        return Err(format!("unsupported {method} {path}"));
    }

    let req: Value = if body.is_empty() {
        json!({})
    } else {
        serde_json::from_slice(body).map_err(|e| format!("bad json: {e}"))?
    };

    match path {
        "/api/smu_init" => Ok(serde_json::to_value(smu::init_smu()?).unwrap_or(Value::Null)),
        "/api/smu_get_core_layout" => {
            Ok(serde_json::to_value(smu::get_core_layout()).unwrap_or(Value::Null))
        }
        "/api/smu_get_co_single_core" => {
            let (core, ccd, ccx) = placement(&req)?;
            Ok(json!(smu::get_co_single_core(core, ccd, ccx)?))
        }
        "/api/smu_set_co_single_core" => {
            let (core, ccd, ccx) = placement(&req)?;
            let margin = params(&req)
                .get("margin")
                .and_then(|v| v.as_i64())
                .ok_or("margin missing")? as i32;
            Ok(json!(smu::set_co_single_core(core, ccd, ccx, margin)?))
        }
        "/api/smu_set_co_all_cores" => {
            let margin = req
                .get("margin")
                .and_then(|v| v.as_i64())
                .ok_or("margin missing")? as i32;
            Ok(json!(smu::set_co_all_cores(margin)?))
        }
        "/api/smu_get_pbo_scalar" => Ok(json!(smu::get_pbo_scalar()?)),
        "/api/smu_set_pbo_scalar" => {
            let v = req
                .get("scalarX1000")
                .or_else(|| req.get("scalar_x1000"))
                .and_then(|v| v.as_u64())
                .ok_or("scalarX1000 missing")? as u32;
            Ok(json!(smu::set_pbo_scalar(v)?))
        }
        "/api/smu_get_fmax" => Ok(json!(smu::get_fmax()?)),
        "/api/smu_set_fmax" => {
            let v = req
                .get("frequencyMhz")
                .or_else(|| req.get("frequency_mhz"))
                .and_then(|v| v.as_u64())
                .ok_or("frequencyMhz missing")? as u32;
            Ok(json!(smu::set_fmax(v)?))
        }
        "/api/smu_profile_save" => {
            let content = req
                .get("content")
                .and_then(|v| v.as_str())
                .ok_or("content missing")?;
            Ok(json!(save_profile(content)?))
        }
        "/api/smu_profile_load" => Ok(json!(load_profile()?)),
        other => Err(format!("unknown endpoint {other}")),
    }
}

/// Endpoints take a flat JSON body (`{core, ccd, ccx, margin}`). The page used
/// to wrap them in a `{"request": {...}}` envelope — the shape the host-scoped
/// invoke expected — and a cached page can still send that, so unwrap it here
/// instead of answering "core missing" and silently failing every write.
fn params(req: &Value) -> &Value {
    let flat = req.get("core").is_some() || req.get("margin").is_some();
    match req.get("request") {
        Some(inner) if !flat && inner.is_object() => inner,
        _ => req,
    }
}

/// `{core, ccd, ccx}` — the page always sends all three.
fn placement(req: &Value) -> Result<(u32, u32, u32), String> {
    let p = params(req);
    let get = |k: &str| -> Result<u32, String> {
        p.get(k)
            .and_then(|v| v.as_u64())
            .map(|v| v as u32)
            .ok_or_else(|| format!("{k} missing"))
    };
    Ok((get("core")?, get("ccd")?, get("ccx")?))
}

fn write_response(stream: &mut TcpStream, code: u16, body: &str) -> std::io::Result<()> {
    let reason = match code {
        200 => "OK",
        204 => "No Content",
        _ => "Error",
    };
    let head = format!(
        "HTTP/1.1 {code} {reason}\r\n\
         Content-Type: application/json; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Access-Control-Allow-Origin: *\r\n\
         Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n\
         Access-Control-Allow-Headers: Content-Type\r\n\
         Cache-Control: no-store\r\n\
         Connection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(body.as_bytes())?;
    stream.flush()
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
}

// ---- Config dir / profile ----
//
// Mirrors the host's resolution order so an existing profile keeps working:
// portable `data/` next to the executable, then `data_dir.ptr`, then the
// HKCU\Software\OpenRevo\DataPath value, then %APPDATA%\OpenRevo.
fn config_dir() -> PathBuf {
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()));

    let appdata = std::env::var("APPDATA").unwrap_or_default();
    let roaming = if appdata.is_empty() {
        PathBuf::from(".")
    } else {
        PathBuf::from(&appdata).join("OpenRevo")
    };

    if let Some(dir) = &exe_dir {
        let portable = dir.join("data");
        if portable.is_dir() {
            return portable;
        }
    }

    if let Ok(ptr) = std::fs::read_to_string(roaming.join("data_dir.ptr")) {
        let t = ptr.trim();
        if !t.is_empty() {
            return PathBuf::from(t);
        }
    }

    if let Some(p) = registry_datapath() {
        return PathBuf::from(p);
    }

    roaming
}

fn profile_path() -> PathBuf {
    config_dir().join("pbo_tuner_profile.json")
}

fn save_profile(content: &str) -> Result<String, String> {
    // Reject anything that is not valid JSON before it lands on disk: a broken
    // profile would otherwise only surface at the next boot.
    serde_json::from_str::<Value>(content).map_err(|e| format!("profile is not valid JSON: {e}"))?;
    let path = profile_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    std::fs::write(&path, content).map_err(|e| e.to_string())?;
    Ok(path.display().to_string())
}

fn load_profile() -> Result<String, String> {
    let path = profile_path();
    if !path.exists() {
        return Ok(String::new());
    }
    std::fs::read_to_string(&path).map_err(|e| e.to_string())
}

/// Apply the saved profile at startup when the user opted in.
///
/// Runs from this process, not the host: the service is launched by the host's
/// plugin bootstrap before any tab exists, which is exactly the moment the
/// margins need to be restored.
fn auto_apply_profile() -> Result<String, String> {
    let path = profile_path();
    if !path.exists() {
        return Ok("no profile saved".into());
    }
    let text = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
    let profile: Value = serde_json::from_str(&text).map_err(|e| format!("profile corrupt: {e}"))?;

    if profile.get("autoApply").and_then(|v| v.as_bool()) != Some(true) {
        return Ok("auto-apply is off for this profile".into());
    }

    let info = smu::init_smu()?;
    if !info.curve_optimizer_supported {
        return Err(format!("{} does not expose Curve Optimizer", info.code_name));
    }

    let layout = smu::get_core_layout();
    if layout.is_empty() {
        return Err("core topology unavailable".into());
    }

    let co = profile
        .get("co")
        .and_then(|v| v.as_object())
        .ok_or("profile has no core map")?;

    let (mut applied, mut failed) = (0usize, 0usize);
    for core in &layout {
        let Some(margin) = co.get(&core.core.to_string()).and_then(|v| v.as_i64()) else {
            continue;
        };
        match smu::set_co_single_core(core.core, core.ccd, core.ccx, margin as i32) {
            Ok(_) => applied += 1,
            Err(_) => failed += 1,
        }
    }

    if let Some(fmax) = profile.get("fmax").and_then(|v| v.as_i64()) {
        if fmax > 0 && info.fmax_supported {
            let _ = smu::set_fmax(fmax as u32);
        }
    }
    if let Some(scalar) = profile.get("scalar").and_then(|v| v.as_i64()) {
        if scalar >= 1 && info.pbo_scalar_supported {
            let _ = smu::set_pbo_scalar((scalar as u32) * 1000);
        }
    }

    Ok(format!("applied {applied} cores ({failed} failed)"))
}

// ---- Logging ----

fn log(msg: &str) {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let line = format!("[{ts}] {msg}\n");
    let path = config_dir().join("pbo_service.log");
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        let _ = f.write_all(line.as_bytes());
    }
    eprintln!("{}", line.trim_end());
}

// ---- Registry (HKCU\Software\OpenRevo DataPath) ----

#[cfg(windows)]
fn registry_datapath() -> Option<String> {
    #[link(name = "advapi32")]
    extern "system" {
        fn RegOpenKeyExW(hkey: isize, sub: *const u16, opt: u32, sam: u32, out: *mut isize) -> i32;
        fn RegQueryValueExW(
            hkey: isize,
            name: *const u16,
            reserved: *mut u32,
            ty: *mut u32,
            data: *mut u8,
            len: *mut u32,
        ) -> i32;
        fn RegCloseKey(hkey: isize) -> i32;
    }

    // HKEY_CURRENT_USER is 0xFFFFFFFF80000001 on 64-bit; sign-extend from i32
    // instead of widening the bare u32, which would address the wrong root.
    const HKEY_CURRENT_USER: isize = 0x8000_0001u32 as i32 as isize;
    const KEY_READ: u32 = 0x20019;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    unsafe {
        let mut hkey: isize = 0;
        if RegOpenKeyExW(
            HKEY_CURRENT_USER,
            wide("Software\\OpenRevo").as_ptr(),
            0,
            KEY_READ,
            &mut hkey,
        ) != 0
        {
            return None;
        }
        let mut ty: u32 = 0;
        let mut len: u32 = 4096;
        let mut buf = vec![0u8; len as usize];
        let rc = RegQueryValueExW(
            hkey,
            wide("DataPath").as_ptr(),
            std::ptr::null_mut(),
            &mut ty,
            buf.as_mut_ptr(),
            &mut len,
        );
        RegCloseKey(hkey);
        if rc != 0 || len < 2 {
            return None;
        }
        // REG_SZ (1) or REG_EXPAND_SZ (2): UTF-16LE, trailing NUL.
        let units = len as usize / 2;
        let mut v: Vec<u16> = Vec::with_capacity(units);
        for i in 0..units {
            v.push(u16::from_le_bytes([buf[i * 2], buf[i * 2 + 1]]));
        }
        while matches!(v.last(), Some(0)) {
            v.pop();
        }
        let s = String::from_utf16_lossy(&v);
        if s.trim().is_empty() {
            None
        } else {
            Some(s)
        }
    }
}

#[cfg(not(windows))]
fn registry_datapath() -> Option<String> {
    None
}
