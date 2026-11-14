// sys-service — OpenRevo sys-inspector companion service.
//
// Standalone HTTP sidecar exposing system-level introspection over localhost:
//   GET  /api/health                  liveness probe
//   GET  /api/system                  CPU per-core / memory / disks / network counters
//   GET  /api/processes               process list (cpu%, memory, path, ppid)
//   POST /api/process/kill            {pid, tree}     end process (optionally whole tree)
//   GET  /api/connections             TCP/UDP endpoint table with owning PID
//   POST /api/connections/close       {local_addr, local_port, remote_addr?, remote_port?} force TCP close
//   GET  /api/file/occupiers?path=    Restart Manager: which processes lock this file
//
// The host (open-revo daemon) starts/stops this process per manifest.json
// `service` configuration and spawns it elevated when requested. This binary
// never touches host code.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use sysinfo::{Disks, Networks, Pid, ProcessesToUpdate, System};

const LOG_FILE: &str = "sys_service.log";

// ---------------------------------------------------------------- logging ---

fn log_path() -> PathBuf {
    let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("sys-service.exe"));
    let dir = exe.parent().map(|p| p.to_path_buf()).unwrap_or_default();
    let cand = dir.join(LOG_FILE);
    // Probing writability once at startup; %APPDATA% plugin dirs are writable.
    if std::fs::OpenOptions::new().create(true).append(true).open(&cand).is_ok() {
        cand
    } else {
        std::env::temp_dir().join(LOG_FILE)
    }
}

fn log(msg: &str) {
    use std::fmt::Write as _;
    let path = log_path();
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut line = String::new();
        let _ = writeln!(line, "[{}] {}", now, msg);
        let _ = f.write_all(line.as_bytes());
    }
}

// ------------------------------------------------------------ app state -----

struct AppState {
    sys: System,
    nets: Networks,
    disks: Disks,
    started: Instant,
    // PDH disk-throughput counters (\PhysicalDisk(_Total)); 0 = unavailable.
    pdh_query: isize,
    pdh_read: isize,
    pdh_write: isize,
    disk_read_bps: f64,
    disk_write_bps: f64,
}

impl AppState {
    fn new() -> Self {
        let mut sys = System::new_all();
        sys.refresh_processes(ProcessesToUpdate::All, true);
        sys.refresh_memory();
        sys.refresh_cpu_all();
        let (pdh_query, pdh_read, pdh_write) = pdh_init();
        AppState {
            sys,
            nets: Networks::new_with_refreshed_list(),
            disks: Disks::new_with_refreshed_list(),
            started: Instant::now(),
            pdh_query,
            pdh_read,
            pdh_write,
            disk_read_bps: 0.0,
            disk_write_bps: 0.0,
        }
    }

    fn refresh_all(&mut self) {
        self.sys.refresh_processes(ProcessesToUpdate::All, true);
        self.sys.refresh_memory();
        self.sys.refresh_cpu_all();
        let _ = self.nets.refresh(true);
        self.disks.refresh(false);
    }

    // Rate counters: each collect finalizes the interval since the previous
    // collect, so call this from a fixed-cadence ticker and read right after.
    #[cfg(windows)]
    fn collect_disk_io(&mut self) {
        if self.pdh_query == 0 {
            return;
        }
        unsafe {
            if PdhCollectQueryData(self.pdh_query) != 0 {
                return;
            }
            let mut ctype: u32 = 0;
            let mut val = PDH_FMT_COUNTERVALUE {
                CStatus: 0,
                Anonymous: PDH_FMT_COUNTERVALUE_0 { doubleValue: 0.0 },
            };
            if PdhGetFormattedCounterValue(self.pdh_read, PDH_FMT_DOUBLE, &mut ctype, &mut val) == 0 {
                self.disk_read_bps = val.Anonymous.doubleValue;
            }
            if PdhGetFormattedCounterValue(self.pdh_write, PDH_FMT_DOUBLE, &mut ctype, &mut val) == 0 {
                self.disk_write_bps = val.Anonymous.doubleValue;
            }
        }
    }

    #[cfg(not(windows))]
    fn collect_disk_io(&mut self) {}
}

#[cfg(windows)]
fn pdh_init() -> (isize, isize, isize) {
    use std::os::windows::ffi::OsStrExt;
    let to_wide = |s: &str| -> Vec<u16> {
        std::ffi::OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
    };
    unsafe {
        let mut q: isize = 0;
        if PdhOpenQueryW(std::ptr::null(), 0, &mut q) != 0 {
            return (0, 0, 0);
        }
        let mut r: isize = 0;
        let mut w: isize = 0;
        let read_ok = PdhAddEnglishCounterW(q, to_wide("\\PhysicalDisk(_Total)\\Disk Read Bytes/sec").as_ptr(), 0, &mut r) == 0;
        let write_ok = PdhAddEnglishCounterW(q, to_wide("\\PhysicalDisk(_Total)\\Disk Write Bytes/sec").as_ptr(), 0, &mut w) == 0;
        if !read_ok || !write_ok || PdhCollectQueryData(q) != 0 {
            let _ = PdhCloseQuery(q);
            return (0, 0, 0);
        }
        (q, r, w)
    }
}

#[cfg(not(windows))]
fn pdh_init() -> (isize, isize, isize) {
    (0, 0, 0)
}

static STATE: std::sync::OnceLock<Mutex<AppState>> = std::sync::OnceLock::new();

fn state() -> &'static Mutex<AppState> {
    STATE.get_or_init(|| Mutex::new(AppState::new()))
}

// ------------------------------------------------------------------ main ----

fn main() {
    let mut port: u16 = 18956;
    let args: Vec<String> = std::env::args().collect();
    let mut serve = false;
    let mut i = 1;
    while i < args.len() {
        if let Some(v) = args[i].strip_prefix("--port=") {
            port = v.parse().unwrap_or(port);
        } else if args[i] == "--port" && i + 1 < args.len() {
            i += 1;
            port = args[i].parse().unwrap_or(port);
        } else if args[i] == "--serve" {
            serve = true;
        }
        i += 1;
    }
    if !serve {
        // Started without --serve (e.g. manual probe): just report and exit.
        println!("sys-service v{} (pass --serve --port N to run)", env!("CARGO_PKG_VERSION"));
        return;
    }

    // Pre-warm the telemetry snapshot so the first /api/system call has deltas.
    let _ = state();

    // Background ticker: refresh the snapshot on a fixed 1s cadence so that
    // (a) process CPU% windows are stable regardless of request timing and
    // (b) the first request after opening a tab already has fresh deltas.
    std::thread::spawn(|| loop {
        std::thread::sleep(Duration::from_secs(1));
        if let Ok(mut st) = state().lock() {
            st.refresh_all();
            st.collect_disk_io();
        }
    });

    let addr = ("127.0.0.1", port);
    let listener = match TcpListener::bind(addr) {
        Ok(l) => l,
        Err(e) => {
            log(&format!("FATAL: cannot bind {:?}: {}", addr, e));
            std::process::exit(1);
        }
    };
    log(&format!("sys-service listening on 127.0.0.1:{}", port));

    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                // Thread per connection: keeps the listener responsive even
                // while a slow /api/processes refresh is in flight.
                std::thread::spawn(move || handle_client(s));
            }
            Err(e) => log(&format!("accept error: {}", e)),
        }
    }
}

// ---------------------------------------------------------- http plumbing ---

fn handle_client(mut stream: TcpStream) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(8)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(8)));

    let req = match read_request(&mut stream) {
        Some(r) => r,
        None => {
            respond(&mut stream, 400, &json!({"error": "bad request"}));
            return;
        }
    };

    let (method, target) = (req.0, req.1);

    // CORS preflight: the browser sends OPTIONS before any POST with a
    // non-safelisted Content-Type (application/json). Without this the
    // preflight fails and the page sees "Failed to fetch" on every POST.
    if method == "OPTIONS" {
        let preflight = "HTTP/1.1 204 No Content\r\n\
            Access-Control-Allow-Origin: *\r\n\
            Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n\
            Access-Control-Allow-Headers: Content-Type\r\n\
            Access-Control-Max-Age: 86400\r\n\
            Connection: close\r\n\
            Content-Length: 0\r\n\r\n";
        let _ = stream.write_all(preflight.as_bytes());
        let _ = stream.flush();
        return;
    }

    let (path, query) = split_target(&target);
    let started = Instant::now();
    let (status, value) = route(method.as_str(), path.as_str(), &query, &req.2);
    let ms = started.elapsed().as_millis();
    if ms > 800 || status != 200 {
        log(&format!("{} {} -> {} ({} ms)", method, path, status, ms));
    }
    respond(&mut stream, status, &value);
}

type Request = (String, String, Vec<u8>); // method, target, body

fn read_request(stream: &mut TcpStream) -> Option<Request> {
    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    let mut tmp = [0u8; 8192];
    let mut header_end: Option<usize> = None;

    loop {
        let n = stream.read(&mut tmp).ok()?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find(&buf, b"\r\n\r\n") {
            header_end = Some(pos);
            break;
        }
        if buf.len() > 1_048_576 {
            return None; // header too large
        }
    }
    let header_end = header_end?;
    let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut lines = head.split("\r\n");
    let reqline = lines.next()?.to_string();
    let mut parts = reqline.split_whitespace();
    let method = parts.next()?.to_string();
    let target = parts.next()?.to_string();

    let mut content_length: usize = 0;
    for line in lines {
        let lower = line.to_ascii_lowercase();
        if let Some(v) = lower.strip_prefix("content-length:") {
            content_length = v.trim().parse().unwrap_or(0);
        }
    }
    if content_length > 1_048_576 {
        return None; // body too large
    }

    let mut body: Vec<u8> = buf[header_end + 4..].to_vec();
    while body.len() < content_length {
        let n = stream.read(&mut tmp).ok()?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
    }
    body.truncate(content_length);
    Some((method, target, body))
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn split_target(target: &str) -> (String, HashMap<String, String>) {
    let mut it = target.splitn(2, '?');
    let path = it.next().unwrap_or("/").to_string();
    let mut query = HashMap::new();
    if let Some(qs) = it.next() {
        for pair in qs.split('&') {
            let mut kv = pair.splitn(2, '=');
            if let (Some(k), Some(v)) = (kv.next(), kv.next()) {
                query.insert(url_decode(k), url_decode(v));
            }
        }
    }
    (path, query)
}

fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hi = (bytes[i + 1] as char).to_digit(16);
                let lo = (bytes[i + 2] as char).to_digit(16);
                if let (Some(h), Some(l)) = (hi, lo) {
                    out.push((h * 16 + l) as u8);
                    i += 3;
                    continue;
                }
                out.push(b'%');
                i += 1;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

fn respond(stream: &mut TcpStream, status: u16, value: &Value) {
    let body = serde_json::to_string(value).unwrap_or_else(|_| "{\"error\":\"serialize\"}".into());
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "OK",
    };
    let resp = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json; charset=utf-8\r\nAccess-Control-Allow-Origin: *\r\nCache-Control: no-store\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}",
        status,
        reason,
        body.len(),
        body
    );
    let _ = stream.write_all(resp.as_bytes());
    let _ = stream.flush();
}

// ---------------------------------------------------------------- routing ---

fn route(method: &str, path: &str, query: &HashMap<String, String>, body: &[u8]) -> (u16, Value) {
    match (method, path) {
        ("GET", "/api/health") => (
            200,
            json!({
                "status": "ok",
                "service": "sys-service",
                "version": env!("CARGO_PKG_VERSION"),
                "uptime_s": state().lock().map(|s| s.started.elapsed().as_secs()).unwrap_or(0),
                "elevated": is_elevated()
            }),
        ),
        ("GET", "/api/system") => api_system(),
        ("GET", "/api/processes") => api_processes(),
        ("POST", "/api/process/kill") => with_json_body(body, api_process_kill),
        ("GET", "/api/connections") => api_connections(),
        ("POST", "/api/connections/close") => with_json_body(body, api_connection_close),
        ("GET", "/api/file/occupiers") => match query.get("path") {
            Some(p) if !p.trim().is_empty() => api_file_occupiers(p.trim()),
            _ => (400, json!({"error": "missing ?path= parameter"})),
        },
        ("GET", "/") => (200, json!({"service": "sys-service", "version": env!("CARGO_PKG_VERSION")})),
        _ => (404, json!({"error": format!("no route: {} {}", method, path)})),
    }
}

fn with_json_body(body: &[u8], f: fn(&Value) -> (u16, Value)) -> (u16, Value) {
    if body.is_empty() {
        return (400, json!({"error": "empty body"}));
    }
    match serde_json::from_slice::<Value>(body) {
        Ok(v) => f(&v),
        Err(e) => (400, json!({"error": format!("invalid JSON body: {}", e)})),
    }
}

// ------------------------------------------------------------- /api/system --

fn api_system() -> (u16, Value) {
    let st = match state().lock() {
        Ok(g) => g,
        Err(_) => return (500, json!({"error": "state poisoned"})),
    };
    // Snapshot is refreshed by the background ticker; do NOT refresh here or
    // request timing would skew the CPU delta windows.

    let cores: Vec<f32> = st.sys.cpus().iter().map(|c| c.cpu_usage()).collect();
    let freq = st.sys.cpus().first().map(|c| c.frequency()).unwrap_or(0);
    // Computed manually instead of System::global_cpu_usage() to stay
    // independent of minor-version API churn.
    let global = if cores.is_empty() {
        0.0
    } else {
        cores.iter().sum::<f32>() / cores.len() as f32
    };
    let mem_total = st.sys.total_memory();
    let mem_used = st.sys.used_memory();
    let swap_total = st.sys.total_swap();
    let swap_used = st.sys.used_swap();

    let disks: Vec<Value> = st
        .disks
        .list()
        .iter()
        .map(|d| {
            json!({
                "mount": d.mount_point().to_string_lossy(),
                "label": d.name().to_string_lossy(),
                "kind": format!("{:?}", d.kind()),
                "total": d.total_space(),
                "free": d.available_space(),
            })
        })
        .collect();

    let mut net: Vec<Value> = Vec::new();
    for (name, data) in &st.nets {
        net.push(json!({
            "iface": name.to_string(),
            "rx_total": data.total_received(),
            "tx_total": data.total_transmitted(),
            "rx_delta": data.received(),
            "tx_delta": data.transmitted(),
        }));
    }

    (
        200,
        json!({
            "uptime_s": st.started.elapsed().as_secs(),
            "cpu": { "global": global, "freq_mhz": freq, "cores": cores },
            "memory": { "total": mem_total, "used": mem_used, "swap_total": swap_total, "swap_used": swap_used },
            "disk_io": {
                "read_bps": st.disk_read_bps,
                "write_bps": st.disk_write_bps,
            },
            "disks": disks,
            "networks": net,
        }),
    )
}

// ----------------------------------------------------------- /api/processes --

fn api_processes() -> (u16, Value) {
    let st = match state().lock() {
        Ok(g) => g,
        Err(_) => return (500, json!({"error": "state poisoned"})),
    };
    // CPU% is normalized by the ticker's fixed 1s windows; serving the cached
    // snapshot keeps values identical across consecutive polls.

    let mut list: Vec<Value> = Vec::with_capacity(st.sys.processes().len());
    for (pid, p) in st.sys.processes() {
        list.push(json!({
            "pid": pid.as_u32(),
            "ppid": p.parent().map(|x| x.as_u32()),
            "name": p.name().to_string_lossy(),
            "cpu": p.cpu_usage(),
            "mem": p.memory(),
            "exe": p.exe().map(|e| e.to_string_lossy()).unwrap_or_default(),
        }));
    }

    (200, json!({ "count": list.len(), "processes": list }))
}

// ------------------------------------------------------- process actions ----

fn kill_pid(pid: u32) -> Result<(), String> {
    unsafe {
        let h = OpenProcess(PROCESS_TERMINATE, 0, pid);
        if h.is_null() {
            return Err(format!("OpenProcess({}) failed (err {})", pid, GetLastError()));
        }
        let ok = TerminateProcess(h, 1);
        CloseHandle(h);
        if ok == 0 {
            return Err(format!("TerminateProcess({}) failed (err {})", pid, GetLastError()));
        }
    }
    Ok(())
}

fn api_process_kill(v: &Value) -> (u16, Value) {
    let pid = match v.get("pid").and_then(|x| x.as_u64()) {
        Some(p) if p > 0 => p as u32,
        _ => return (400, json!({"error": "missing pid"})),
    };
    let tree = v.get("tree").and_then(|x| x.as_bool()).unwrap_or(false);

    if !tree {
        return match kill_pid(pid) {
            Ok(()) => (200, json!({"ok": true, "killed": [pid]})),
            Err(e) => (500, json!({"error": e})),
        };
    }

    // Tree kill: snapshot, walk descendants, terminate leaves-first.
    let mut sys = System::new();
    sys.refresh_processes(ProcessesToUpdate::All, true);
    let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
    for (p, info) in sys.processes() {
        if let Some(pp) = info.parent() {
            children.entry(pp.as_u32()).or_default().push(p.as_u32());
        }
    }
    let mut order: Vec<u32> = Vec::new();
    let mut stack = vec![pid];
    let mut seen = std::collections::HashSet::new();
    while let Some(cur) = stack.pop() {
        if !seen.insert(cur) {
            continue;
        }
        order.push(cur);
        if let Some(kids) = children.get(&cur) {
            for k in kids.clone() {
                stack.push(k);
            }
        }
    }
    // Descendants first, root last.
    order.reverse();

    let mut killed = Vec::new();
    let mut failed: Vec<Value> = Vec::new();
    for target in &order {
        match kill_pid(*target) {
            Ok(()) => killed.push(*target),
            Err(e) => {
                // Self-kill of an already-exited child is not an error.
                if *target != pid {
                    failed.push(json!({ "pid": target, "error": e }));
                }
            }
        }
    }
    if failed.is_empty() {
        (200, json!({ "ok": true, "killed": killed }))
    } else {
        (500, json!({ "killed": killed, "failed": failed }))
    }
}

// --------------------------------------------------------- /api/connections --

#[repr(C)]
struct TcpRow {
    state: u32,
    local_addr: u32,
    local_port: u32,
    remote_addr: u32,
    remote_port: u32,
    pid: u32,
}

#[repr(C)]
struct UdpRow {
    local_addr: u32,
    local_port: u32,
    pid: u32,
}

const TCP_TABLE_OWNER_PID_ALL: u32 = 5;
const UDP_TABLE_OWNER_PID: u32 = 1;
const MIB_TCP_STATE_DELETE_TCB: u32 = 12;

fn addr_to_string(dw: u32) -> String {
    format!("{}.{}.{}.{}", dw & 0xff, (dw >> 8) & 0xff, (dw >> 16) & 0xff, (dw >> 24) & 0xff)
}

// Ports in the tables are stored big-endian (network order) in the low word.
fn port_from_dw(dw: u32) -> u16 {
    (((dw >> 8) & 0xff) | ((dw & 0xff) << 8)) as u16
}

fn pid_names(pids: &[u32]) -> HashMap<u32, String> {
    let mut sys = System::new();
    sys.refresh_processes(ProcessesToUpdate::All, true);
    let mut map = HashMap::new();
    for pid in pids {
        if let Some(p) = sys.process(Pid::from_u32(*pid)) {
            map.insert(*pid, p.name().to_string_lossy().to_string());
        }
    }
    map
}

fn api_connections() -> (u16, Value) {
    let mut tcp: Vec<TcpRow> = Vec::new();
    let mut udp: Vec<UdpRow> = Vec::new();

    unsafe {
        // ---- TCP ----
        let mut size: u32 = 0;
        let rc = GetExtendedTcpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            2, // AF_INET
            TCP_TABLE_OWNER_PID_ALL as i32,
            0,
        );
        if rc == 122 {
            // ERROR_INSUFFICIENT_BUFFER
            let mut buf = vec![0u8; size as usize];
            let rc = GetExtendedTcpTable(
                buf.as_mut_ptr() as *mut core::ffi::c_void,
                &mut size,
                0,
                2,
                TCP_TABLE_OWNER_PID_ALL as i32,
                0,
            );
            if rc == 0 {
                let base = buf.as_mut_ptr() as *const u32;
                let count = *base as usize;
                let row_ptr = base.add(1) as *const TcpRow;
                for i in 0..count {
                    tcp.push(std::ptr::read(row_ptr.add(i)));
                }
            }
        }

        // ---- UDP ----
        let mut size: u32 = 0;
        let rc = GetExtendedUdpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            2,
            UDP_TABLE_OWNER_PID as i32,
            0,
        );
        if rc == 122 {
            let mut buf = vec![0u8; size as usize];
            let rc = GetExtendedUdpTable(
                buf.as_mut_ptr() as *mut core::ffi::c_void,
                &mut size,
                0,
                2,
                UDP_TABLE_OWNER_PID as i32,
                0,
            );
            if rc == 0 {
                let base = buf.as_mut_ptr() as *const u32;
                let count = *base as usize;
                let row_ptr = base.add(1) as *const UdpRow;
                for i in 0..count {
                    udp.push(std::ptr::read(row_ptr.add(i)));
                }
            }
        }
    }

    let mut all_pids: Vec<u32> = tcp.iter().map(|r| r.pid).collect();
    all_pids.extend(udp.iter().map(|r| r.pid));
    let names = pid_names(&all_pids);

    let tcp_json: Vec<Value> = tcp
        .iter()
        .map(|r| {
            json!({
                "proto": "tcp",
                "state": tcp_state_name(r.state),
                "local": format!("{}:{}", addr_to_string(r.local_addr), port_from_dw(r.local_port)),
                "remote": format!("{}:{}", addr_to_string(r.remote_addr), port_from_dw(r.remote_port)),
                "pid": r.pid,
                "process": names.get(&r.pid).cloned().unwrap_or_default(),
            })
        })
        .collect();

    let udp_json: Vec<Value> = udp
        .iter()
        .map(|r| {
            json!({
                "proto": "udp",
                "local": format!("{}:{}", addr_to_string(r.local_addr), port_from_dw(r.local_port)),
                "pid": r.pid,
                "process": names.get(&r.pid).cloned().unwrap_or_default(),
            })
        })
        .collect();

    (200, json!({ "tcp": tcp_json, "udp": udp_json }))
}

fn tcp_state_name(s: u32) -> String {
    let name = match s {
        1 => "CLOSED",
        2 => "LISTEN",
        3 => "SYN_SENT",
        4 => "SYN_RCVD",
        5 => "ESTABLISHED",
        6 => "FIN_WAIT1",
        7 => "FIN_WAIT2",
        8 => "CLOSE_WAIT",
        9 => "CLOSING",
        10 => "LAST_ACK",
        11 => "TIME_WAIT",
        12 => "DELETE_TCB",
        _ => "UNKNOWN",
    };
    name.to_string()
}

fn api_connection_close(v: &Value) -> (u16, Value) {
    let parse_ip = |s: &str| -> Option<u32> {
        let parts: Vec<u32> = s.split('.').filter_map(|p| p.parse().ok()).collect();
        if parts.len() != 4 {
            return None;
        }
        // Network byte order DWORD
        Some(parts[0] | (parts[1] << 8) | (parts[2] << 16) | (parts[3] << 24))
    };
    let port_dw = |p: u16| -> u32 { ((p >> 8) & 0xff) as u32 | ((p & 0xff) << 8) as u32 };

    let laddr = match v.get("local_addr").and_then(|x| x.as_str()).and_then(parse_ip) {
        Some(a) => a,
        None => return (400, json!({"error": "missing/invalid local_addr"})),
    };
    let lport = match v.get("local_port").and_then(|x| x.as_u64()) {
        Some(p) if p > 0 && p < 65536 => port_dw(p as u16),
        _ => return (400, json!({"error": "missing/invalid local_port"})),
    };
    let raddr = v.get("remote_addr").and_then(|x| x.as_str()).and_then(parse_ip).unwrap_or(0);
    let rport = v.get("remote_port").and_then(|x| x.as_u64()).map(|p| port_dw(p as u16)).unwrap_or(0);

    let row = MIB_TCPROW_W2K {
        dwState: MIB_TCP_STATE_DELETE_TCB,
        dwLocalAddr: laddr,
        dwLocalPort: lport,
        dwRemoteAddr: raddr,
        dwRemotePort: rport,
    };
    // windows-sys 0.59 has no plain MIB_TCPROW; MIB_TCPROW_W2K is layout-identical
    // to MIB_TCPROW_LH (what SetTcpEntry actually takes).
    let rc = unsafe { SetTcpEntry(&row as *const MIB_TCPROW_W2K as *const MIB_TCPROW_LH) };
    if rc != 0 {
        return (500, json!({"error": format!("SetTcpEntry failed (err {}), requires admin", rc)}));
    }
    (200, json!({"ok": true}))
}

// ------------------------------------------------------ file occupancy (RM) --

fn api_file_occupiers(path: &str) -> (u16, Value) {
    let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    let path_ptr = [wide.as_ptr()];

    unsafe {
        let mut session: u32 = 0;
        // Session key: build a pseudo-GUID string (must be unique per session).
        let tick = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let key_str = format!(
            "{{{:08X}-{:04X}-{:04X}-{:04X}-{:012X}}}",
            std::process::id(),
            (tick >> 48) as u16,
            (tick >> 32) as u16,
            (tick >> 16) as u16,
            tick & 0xFFFF_FFFF_FFFF
        );
        let mut key: Vec<u16> = key_str.encode_utf16().chain(std::iter::once(0)).collect();

        let rc = RmStartSession(&mut session, 0, key.as_mut_ptr());
        if rc != 0 {
            return (500, json!({"error": format!("RmStartSession failed (err {})", rc)}));
        }

        // NOTE: closures never inherit the enclosing unsafe block, so the
        // whole body is wrapped in its own `unsafe { ... }`.
        let result = |session: u32| -> (u16, Value) { unsafe {
            let rc = RmRegisterResources(session, 1, path_ptr.as_ptr(), 0, std::ptr::null(), 0, std::ptr::null());
            if rc != 0 {
                return (500, json!({"error": format!("RmRegisterResources failed (err {}): verify the path exists", rc)}));
            }

            let mut needed: u32 = 0;
            let mut count: u32 = 0;
            // First call to learn the array size, then retry with the buffer.
            let _ = RmGetList(session, &mut needed, &mut count, std::ptr::null_mut(), std::ptr::null_mut());
            let mut list: Vec<RM_PROCESS_INFO> =
                (0..needed.max(1)).map(|_| unsafe { std::mem::zeroed() }).collect();
            count = list.len() as u32;
            let mut reasons: u32 = 0;
            let rc = RmGetList(session, &mut needed, &mut count, list.as_mut_ptr(), &mut reasons);
            if rc != 0 {
                return (500, json!({"error": format!("RmGetList failed (err {})", rc)}));
            }

            let pids: Vec<u32> = list.iter().take(count as usize).map(|i| i.Process.dwProcessId).collect();
            let names = pid_names(&pids);

            let occupiers: Vec<Value> = list
                .iter()
                .take(count as usize)
                .map(|i| {
                    json!({
                        "pid": i.Process.dwProcessId,
                        "app": wide_to_string(&i.strAppName),
                        "service": wide_to_string(&i.strServiceShortName),
                        "app_type": rm_app_type_name(i.ApplicationType as i32),
                        "process": names.get(&i.Process.dwProcessId).cloned().unwrap_or_default(),
                    })
                })
                .collect();

            (200, json!({ "path": path, "count": occupiers.len(), "occupiers": occupiers }))
            }
        };

        let out = result(session);
        let _ = RmEndSession(session);
        out
    }
}

fn wide_to_string(w: &[u16]) -> String {
    let len = w.iter().position(|&c| c == 0).unwrap_or(w.len());
    String::from_utf16_lossy(&w[..len])
}

fn rm_app_type_name(t: i32) -> String {
    let name = match t {
        1 => "Console",
        2 => "Windows GUI",
        3 => "Service",
        4 => "Explorer",
        5 => "Console (legacy)",
        6 => "Windows (legacy)",
        7 => "Service (legacy)",
        8 => "Critical",
        100 => "Other",
        _ => "Unknown",
    };
    name.to_string()
}

// --------------------------------------------------------------- elevated ----

fn is_elevated() -> bool {
    #[cfg(windows)]
    unsafe {
        let mut token: windows_sys::Win32::Foundation::HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elev: TOKEN_ELEVATION = std::mem::zeroed();
        let mut len: u32 = 0;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            &mut elev as *mut _ as *mut core::ffi::c_void,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        );
        CloseHandle(token);
        ok != 0 && elev.TokenIsElevated != 0
    }
    #[cfg(not(windows))]
    {
        false
    }
}

// -------------------------------------------------- windows-sys re-exports ---

#[cfg(windows)]
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError};
#[cfg(windows)]
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, SetTcpEntry, MIB_TCPROW_LH, MIB_TCPROW_W2K,
};
#[cfg(windows)]
use windows_sys::Win32::Security::{
    GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
};
#[cfg(windows)]
use windows_sys::Win32::System::Performance::{
    PdhAddEnglishCounterW, PdhCloseQuery, PdhCollectQueryData, PdhGetFormattedCounterValue,
    PdhOpenQueryW, PDH_FMT_COUNTERVALUE, PDH_FMT_COUNTERVALUE_0, PDH_FMT_DOUBLE,
};
#[cfg(windows)]
use windows_sys::Win32::System::RestartManager::{
    RmEndSession, RmGetList, RmRegisterResources, RmStartSession, RM_PROCESS_INFO,
};
#[cfg(windows)]
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, TerminateProcess, PROCESS_TERMINATE,
};
