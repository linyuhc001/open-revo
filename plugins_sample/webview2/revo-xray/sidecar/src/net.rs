// Networking + packaging: core zip download, minimal zip extraction,
// subscription fetch, tcping and real (through-proxy) latency probes.

use std::io::{Read, Write};
use std::path::Path;
use std::time::{Duration, Instant};

use flate2::read::DeflateDecoder;

pub fn http_get(url: &str, timeout_s: u64) -> Result<Vec<u8>, String> {
    http_get_via(url, timeout_s, None)
}

/// Direct (no-proxy) ranged probe of `url`: fetch the first `bytes` bytes and
/// return the total elapsed ms (connect + TTFB + transfer). Used to race the
/// GitHub release URL against jsDelivr CDNs before a geo download. None =
/// source unusable within the timeout.
pub fn probe_speed(url: &str, bytes: usize, timeout_s: u64, proxy_port: Option<u16>) -> Option<u128> {
    let mut builder = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(timeout_s))
        .redirects(8);
    if let Some(p) = proxy_port {
        let proxy = ureq::Proxy::new(&format!("http://127.0.0.1:{p}")).ok()?;
        builder = builder.proxy(proxy);
    }
    let agent = builder.build();
    let start = Instant::now();
    let resp = agent
        .get(url)
        .set("Range", &format!("bytes=0-{}", bytes.saturating_sub(1)))
        .call()
        .ok()?;
    let mut buf = Vec::new();
    resp.into_reader()
        .take(bytes as u64)
        .read_to_end(&mut buf)
        .ok()?;
    if buf.is_empty() {
        return None;
    }
    Some(start.elapsed().as_millis())
}

/// GET with an optional local HTTP proxy (our own http inbound). Core/geo/
/// subscription downloads prefer the running core's tunnel so GitHub is
/// reachable behind the GFW, and fall back to direct on failure.
pub fn http_get_via(url: &str, timeout_s: u64, proxy_port: Option<u16>) -> Result<Vec<u8>, String> {
    let mut builder = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(timeout_s))
        .redirects(8);
    if let Some(p) = proxy_port {
        let proxy =
            ureq::Proxy::new(&format!("http://127.0.0.1:{p}")).map_err(|e| format!("代理地址无效: {e}"))?;
        builder = builder.proxy(proxy);
    }
    let agent = builder.build();
    let resp = agent.get(url).call().map_err(|e| format!("GET {url}: {e}"))?;
    let mut buf = Vec::new();
    resp.into_reader()
        .take(64 * 1024 * 1024)
        .read_to_end(&mut buf)
        .map_err(|e| format!("读取响应失败: {e}"))?;
    Ok(buf)
}

pub fn tcping(host: &str, port: u16, timeout_ms: u32) -> Option<u32> {
    use std::net::{TcpStream, ToSocketAddrs};
    let addr = format!("{host}:{port}");
    let target = addr.to_socket_addrs().ok()?.next()?;
    let start = Instant::now();
    let sock = TcpStream::connect_timeout(&target, Duration::from_millis(timeout_ms as u64)).ok()?;
    sock.set_read_timeout(Some(Duration::from_millis(timeout_ms as u64))).ok();
    drop(sock);
    Some(start.elapsed().as_millis() as u32)
}

/// Real latency: HTTP 204 probe through our own http inbound, so the path
/// actually exercises the selected node end to end.
pub fn real_latency(http_port: u16, timeout_ms: u32) -> Option<u32> {
    let proxy = ureq::Proxy::new(&format!("http://127.0.0.1:{http_port}")).ok()?;
    let agent = ureq::AgentBuilder::new()
        .proxy(proxy)
        .timeout(Duration::from_millis(timeout_ms as u64))
        .build();
    let start = Instant::now();
    let r = agent
        .get("http://www.gstatic.com/generate_204")
        .call();
    match r {
        Ok(resp) if resp.status() == 204 => Some(start.elapsed().as_millis() as u32),
        _ => None,
    }
}

// ---------- zip (minimal reader: central directory, stored + deflate) ----------

fn u16le(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn u32le(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

pub fn unzip_into(zip_path: &Path, dest: &Path) -> Result<Vec<String>, String> {
    let mut data = Vec::new();
    std::fs::File::open(zip_path)
        .and_then(|mut f| f.read_to_end(&mut data))
        .map_err(|e| format!("打开 zip 失败: {e}"))?;

    // locate end-of-central-directory (scan the last 64KB)
    let mut eocd = None;
    let scan_from = data.len().saturating_sub(65_536 + 22);
    let mut i = data.len();
    while i >= scan_from + 4 {
        if &data[i - 4..i] == b"PK\x05\x06" {
            eocd = Some(i - 4);
            break;
        }
        i -= 1;
    }
    let eocd = eocd.ok_or("不是有效的 zip（找不到 EOCD）")?;
    let entries = u16le(&data, eocd + 10) as usize;
    let cd_off = u32le(&data, eocd + 16) as usize;

    let mut extracted = Vec::new();
    let mut p = cd_off;
    for _ in 0..entries {
        if p + 46 > data.len() || &data[p..p + 4] != b"PK\x01\x02" {
            break;
        }
        let method = u16le(&data, p + 10);
        let csize = u32le(&data, p + 20) as usize;
        let usize_ = u32le(&data, p + 24) as usize;
        let name_len = u16le(&data, p + 28) as usize;
        let extra_len = u16le(&data, p + 30) as usize;
        let comment_len = u16le(&data, p + 32) as usize;
        let local_off = u32le(&data, p + 42) as usize;
        let name = String::from_utf8_lossy(&data[p + 46..p + 46 + name_len]).into_owned();
        p += 46 + name_len + extra_len + comment_len;

        // local header
        if local_off + 30 > data.len() || &data[local_off..local_off + 4] != b"PK\x03\x04" {
            return Err(format!("{name}: 本地头损坏"));
        }
        let l_name_len = u16le(&data, local_off + 26) as usize;
        let l_extra_len = u16le(&data, local_off + 28) as usize;
        let data_start = local_off + 30 + l_name_len + l_extra_len;
        let data_end = data_start + csize;
        if data_end > data.len() {
            return Err(format!("{name}: 数据越界（zip64 暂不支持）"));
        }
        let raw = &data[data_start..data_end];

        // zip-slip guard
        let safe = name.replace('\\', "/");
        if safe.starts_with('/') || safe.contains("..") {
            return Err(format!("{name}: 可疑路径，拒绝解压"));
        }
        let out_path = dest.join(&safe);
        if let Some(parent) = out_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("{name}: {e}"))?;
        }
        if safe.ends_with('/') {
            continue;
        }
        let content: Vec<u8> = match method {
            0 => raw.to_vec(),
            8 => {
                let mut out = Vec::with_capacity(usize_);
                DeflateDecoder::new(raw)
                    .read_to_end(&mut out)
                    .map_err(|e| format!("{name}: 解压失败 {e}"))?;
                out
            }
            m => return Err(format!("{name}: 不支持的压缩方法 {m}")),
        };
        std::fs::File::create(&out_path)
            .and_then(|mut f| f.write_all(&content))
            .map_err(|e| format!("{name}: 写入失败 {e}"))?;
        extracted.push(name);
    }
    if extracted.is_empty() {
        return Err("zip 里没有条目".into());
    }
    // The official release zip ships a few manual-run helper scripts
    // (xray_no_window.{cmd,ps1,vbs}) that the plugin never uses — it spawns
    // the core itself, already window-less. Drop them like v2rayN does.
    for junk in ["xray_no_window.cmd", "xray_no_window.ps1", "xray_no_window.vbs"] {
        let p = dest.join(junk);
        if p.is_file() {
            let _ = std::fs::remove_file(&p);
            extracted.retain(|n| n != junk);
        }
    }
    Ok(extracted)
}

// ---------- xray core ----------

pub const XRAY_RELEASE_URL: &str = "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-windows-64.zip";

pub fn xray_version(exe: &Path) -> Option<String> {
    let out = crate::winapi::capture_output(exe.to_str()?, &["version"]).ok()?;
    let line = out.lines().find(|l| l.contains("Xray"))?;
    Some(line.trim().to_string())
}
