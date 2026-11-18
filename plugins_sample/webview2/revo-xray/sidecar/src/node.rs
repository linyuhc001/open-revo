// Node model, share-link parsing and share-link building.
//
// Scope (v1, xray-only): vless / vmess / trojan / shadowsocks nodes coming in
// as share links or as base64/plain subscription bodies. Everything else is
// reported as a per-line error instead of failing the whole import.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct Node {
    pub id: String,
    pub name: String,
    pub proto: String, // vless | vmess | trojan | ss
    pub add: String,
    pub port: u16,

    // credential: uuid (vless/vmess), password (trojan/ss)
    #[serde(default)]
    pub uuid: String,
    #[serde(default)]
    pub security: String, // ss method
    #[serde(default)]
    pub password: String,

    #[serde(default)]
    pub aid: u32,
    #[serde(default)]
    pub scy: String, // vmess cipher

    // transport
    #[serde(default)]
    pub net: String, // tcp | ws | grpc | h2 | httpupgrade | xhttp | kcp
    #[serde(default)]
    pub header_type: String,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub host: String, // ws/h2 Host header, grpc authoring is serviceName
    #[serde(default)]
    pub service_name: String,
    #[serde(default)]
    pub mode: String, // xhttp mode (auto/packet-up/stream-up)

    // security
    #[serde(default)]
    pub tls: String, // "" | tls | reality
    #[serde(default)]
    pub sni: String,
    #[serde(default)]
    pub alpn: String,
    #[serde(default)]
    pub fp: String,
    #[serde(default)]
    pub pbk: String,
    #[serde(default)]
    pub sid: String,
    #[serde(default)]
    pub spx: String,
    #[serde(default)]
    pub flow: String,
    #[serde(default)]
    pub allow_insecure: bool,

    #[serde(default)]
    pub sub_id: String, // "" = manual node

    // runtime caches, not persisted semantics
    #[serde(default)]
    pub tcping_ms: u32,
    #[serde(default)]
    pub real_ms: u32,
}

impl Node {
    pub fn addr_port(&self) -> String {
        format!("{}:{}", self.add, self.port)
    }
}

// ---------- small helpers ----------

fn b64_decode(s: &str) -> Option<Vec<u8>> {
    // Accept both padded standard and unpadded URL-safe alphabets, with or
    // without line breaks — subscription bodies are messy in the wild.
    let mut cleaned = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\r' | '\n' | ' ' | '\t' => {}
            '-' => cleaned.push('+'),
            '_' => cleaned.push('/'),
            _ => cleaned.push(c),
        }
    }
    while cleaned.len() % 4 != 0 {
        cleaned.push('=');
    }
    // tiny base64 decoder, avoids a whole dependency for one function
    const TBL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::with_capacity(cleaned.len() / 4 * 3);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for c in cleaned.bytes() {
        if c == b'=' {
            break;
        }
        let v = TBL.iter().position(|&t| t == c)? as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

pub fn b64_encode(data: &[u8]) -> String {
    const TBL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(TBL[(n >> 18) as usize & 63] as char);
        out.push(TBL[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { TBL[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { TBL[n as usize & 63] as char } else { '=' });
    }
    out
}

fn url_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if i + 2 < b.len() => {
                let hex = std::str::from_utf8(&b[i + 1..i + 3]).unwrap_or("");
                if let Ok(v) = u8::from_str_radix(hex, 16) {
                    out.push(v);
                    i += 3;
                    continue;
                }
                out.push(b[i]);
                i += 1;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn parse_query(q: &str) -> Vec<(String, String)> {
    q.split('&')
        .filter(|p| !p.is_empty())
        .map(|p| match p.split_once('=') {
            Some((k, v)) => (url_decode(k), url_decode(v)),
            None => (url_decode(p), String::new()),
        })
        .collect()
}

fn qget<'a>(q: &'a [(String, String)], key: &str) -> String {
    q.iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.clone())
        .unwrap_or_default()
}

fn id_gen() -> String {
    // 8 hex chars from a monotonic-ish entropy source; uniqueness inside one
    // data file is all we need.
    use std::time::{SystemTime, UNIX_EPOCH};
    let t = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let mut x = t.as_nanos() as u64;
    // xorshift for a bit of spread
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    format!("{:08x}", (x & 0xFFFF_FFFF) ^ (t.subsec_nanos() as u64))
}

// ---------- single-link parsers ----------

fn parse_vless(u: &str, name_fb: &str) -> Option<Node> {
    let rest = u.strip_prefix("vless://")?;
    let (userinfo_host, query_frag) = rest.split_once('?')?;
    let (query, frag) = match query_frag.split_once('#') {
        Some((q, f)) => (q, f),
        None => (query_frag, ""),
    };
    let (uuid, hostport) = userinfo_host.split_once('@')?;
    let (add, port) = hostport.rsplit_once(':')?;
    let q = parse_query(query);
    let mut n = Node {
        id: id_gen(),
        name: if frag.is_empty() { name_fb.into() } else { url_decode(frag) },
        proto: "vless".into(),
        add: add.trim_matches(['[', ']']).into(),
        port: port.parse().ok()?,
        uuid: uuid.into(),
        net: {
            let t = qget(&q, "type");
            if t.is_empty() { "tcp".into() } else { t }
        },
        tls: qget(&q, "security"),
        ..Default::default()
    };
    if n.tls == "none" || n.tls == "tls" || n.tls == "reality" {
        // keep
    } else {
        n.tls = String::new();
    }
    n.flow = qget(&q, "flow");
    n.sni = qget(&q, "sni");
    n.alpn = qget(&q, "alpn");
    n.fp = qget(&q, "fp");
    n.pbk = qget(&q, "pbk");
    n.sid = qget(&q, "sid");
    n.spx = qget(&q, "spx");
    n.header_type = qget(&q, "headerType");
    n.path = qget(&q, "path");
    n.host = qget(&q, "host");
    n.service_name = qget(&q, "serviceName");
    n.mode = qget(&q, "mode");
    Some(n)
}

fn parse_trojan(u: &str, name_fb: &str) -> Option<Node> {
    let rest = u.strip_prefix("trojan://")?;
    let (userinfo_host, after) = rest.split_once('?').unwrap_or((rest, ""));
    let (query, frag) = match after.split_once('#') {
        Some((q, f)) => (q, f),
        None => ("", after),
    };
    let (pass, hostport) = userinfo_host.split_once('@')?;
    let (add, port) = hostport.rsplit_once(':')?;
    let q = parse_query(query);
    let mut n = Node {
        id: id_gen(),
        name: if frag.is_empty() { name_fb.into() } else { url_decode(frag) },
        proto: "trojan".into(),
        add: add.trim_matches(['[', ']']).into(),
        port: port.parse().ok()?,
        password: url_decode(pass),
        net: {
            let t = qget(&q, "type");
            if t.is_empty() { "tcp".into() } else { t }
        },
        tls: {
            let s = qget(&q, "security");
            if s.is_empty() { "tls".into() } else { s }
        },
        ..Default::default()
    };
    n.sni = {
        let s = qget(&q, "sni");
        if s.is_empty() { qget(&q, "peer") } else { s }
    };
    n.alpn = qget(&q, "alpn");
    n.fp = qget(&q, "fp");
    n.allow_insecure = qget(&q, "allowInsecure") == "1";
    n.header_type = qget(&q, "headerType");
    n.path = qget(&q, "path");
    n.host = qget(&q, "host");
    n.service_name = qget(&q, "serviceName");
    Some(n)
}

fn parse_ss(u: &str, name_fb: &str) -> Option<Node> {
    let rest = u.strip_prefix("ss://")?;
    let (body, frag) = match rest.split_once('#') {
        Some((b, f)) => (b, url_decode(f)),
        None => (rest, String::new()),
    };
    let name = if frag.is_empty() { name_fb.into() } else { frag };
    // Supported forms:
    //   SIP002 plaintext: ss://method:pass@host:port[?type=..]#name
    //   SIP002 base64:    ss://base64(method:pass)@host:port[?plugin=..]#name
    //   legacy:           ss://base64(method:pass@host:port)#name
    // The credential may contain extra colons — SS2022 multi-user uses
    // `method:serverKey:userPassword`, and the whole tail after the first
    // colon is the password. Percent-encoding (%3D, %2F, ...) is decoded.
    fn build(method: &str, pass: &str, hostport: &str, query: &str, name: &str) -> Option<Node> {
        let (add, port) = hostport.rsplit_once(':')?;
        let net = if query.to_ascii_lowercase().contains("type=udp") {
            "udp"
        } else {
            "tcp"
        };
        Some(Node {
            id: id_gen(),
            name: name.into(),
            proto: "ss".into(),
            add: add.trim_matches(['[', ']']).into(),
            port: port.parse().ok()?,
            security: method.into(),
            password: pass.into(),
            net: net.into(),
            ..Default::default()
        })
    }

    // Split `method:rest-of-password` at the FIRST colon only, keeping any
    // further colons in the password (SS2022 serverKey:userPassword).
    fn split_cred(cred: &str) -> Option<(&str, &str)> {
        let (m, p) = cred.split_once(':')?;
        Some((m, p))
    }

    let node = if let Some((cred, hostport_full)) = body.split_once('@') {
        let (hostport, query) = hostport_full.split_once('?').unwrap_or((hostport_full, ""));
        // Try base64 first (classic SIP002); if that fails, the userinfo is
        // plaintext and only needs percent-decoding.
        let decoded = b64_decode(cred);
        let cred_owned;
        let cred = match decoded {
            Some(d) if !d.is_empty() => {
                cred_owned = String::from_utf8_lossy(&d).into_owned();
                cred_owned.as_str()
            }
            _ => {
                cred_owned = url_decode(cred);
                cred_owned.as_str()
            }
        };
        let (method, pass) = split_cred(cred)?;
        build(method, pass, hostport, query, &name)?
    } else {
        let decoded = b64_decode(body)?;
        let s = String::from_utf8_lossy(&decoded);
        let (cred, hostport_full) = s.split_once('@')?;
        let (hostport, query) = hostport_full.split_once('?').unwrap_or((hostport_full, ""));
        let (method, pass) = split_cred(cred)?;
        build(method, pass, hostport, query, &name)?
    };
    Some(node)
}

fn parse_vmess(u: &str, name_fb: &str) -> Option<Node> {
    let rest = u.strip_prefix("vmess://")?;
    let decoded = b64_decode(rest)?;
    let s = String::from_utf8_lossy(&decoded).into_owned();
    let v: serde_json::Value = serde_json::from_str(&s).ok()?;
    let g = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
    let add = g("add");
    if add.is_empty() {
        return None;
    }
    let port: u16 = v.get("port").and_then(|p| {
        p.as_u64()
            .map(|x| x as u16)
            .or_else(|| p.as_str().and_then(|s| s.parse().ok()))
    })?;
    Some(Node {
        id: id_gen(),
        name: {
            let ps = g("ps");
            if ps.is_empty() { name_fb.into() } else { ps }
        },
        proto: "vmess".into(),
        add,
        port,
        uuid: g("id"),
        aid: v.get("aid").and_then(|a| {
            a.as_u64()
                .map(|x| x as u32)
                .or_else(|| a.as_str().and_then(|s| s.parse().ok()))
        }).unwrap_or(0),
        scy: {
            let s = g("scy");
            if s.is_empty() { "auto".into() } else { s }
        },
        net: {
            let n = g("net");
            if n.is_empty() { "tcp".into() } else { n }
        },
        header_type: g("type"),
        path: g("path"),
        host: g("host"),
        tls: {
            let t = g("tls");
            if t == "tls" { "tls".into() } else { String::new() }
        },
        sni: g("sni"),
        alpn: g("alpn"),
        fp: g("fp"),
        ..Default::default()
    })
}

/// Parse one share link. Returns Err with a human-readable reason.
pub fn parse_link(line: &str) -> Result<Node, String> {
    let line = line.trim();
    if line.is_empty() {
        return Err("空行".into());
    }
    let lower = line.to_ascii_lowercase();
    let fallback = format!("节点 {}", id_gen());
    if lower.starts_with("vless://") {
        parse_vless(line, &fallback).ok_or_else(|| "vless 链接解析失败".into())
    } else if lower.starts_with("vmess://") {
        parse_vmess(line, &fallback).ok_or_else(|| "vmess 链接解析失败".into())
    } else if lower.starts_with("trojan://") {
        parse_trojan(line, &fallback).ok_or_else(|| "trojan 链接解析失败".into())
    } else if lower.starts_with("ss://") {
        parse_ss(line, &fallback).ok_or_else(|| "ss 链接解析失败".into())
    } else {
        Err("不支持的协议（仅 vless/vmess/trojan/ss）".into())
    }
}

/// Parse a whole block of text: share links, or a base64 subscription body.
pub fn parse_bulk(text: &str) -> (Vec<Node>, Vec<String>) {
    let mut nodes = Vec::new();
    let mut errors = Vec::new();

    let looks_base64 = |s: &str| {
        let t: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        !t.is_empty()
            && t.len() % 4 == 0
            && t.bytes().all(|c| {
                c.is_ascii_alphanumeric() || c == b'+' || c == b'/' || c == b'-' || c == b'_' || c == b'='
            })
            && !t.to_ascii_lowercase().starts_with("vless")
            && !t.to_ascii_lowercase().starts_with("vmess")
            && !t.to_ascii_lowercase().starts_with("ss://")
            && !t.to_ascii_lowercase().starts_with("trojan")
    };

    if looks_base64(text) {
        if let Some(decoded) = b64_decode(text) {
            let body = String::from_utf8_lossy(&decoded).into_owned();
            for l in body.lines() {
                match parse_link(l) {
                    Ok(n) => nodes.push(n),
                    Err(e) if !l.trim().is_empty() => errors.push(format!("{e}: {}", short(l))),
                    _ => {}
                }
            }
            if !nodes.is_empty() {
                return (nodes, errors);
            }
        }
    }

    for l in text.lines() {
        match parse_link(l) {
            Ok(n) => nodes.push(n),
            Err(e) if !l.trim().is_empty() => errors.push(format!("{e}: {}", short(l))),
            _ => {}
        }
    }
    (nodes, errors)
}

fn short(s: &str) -> String {
    let t = s.trim();
    if t.len() > 48 {
        format!("{}…", &t[..48.min(t.len())])
    } else {
        t.to_string()
    }
}

// ---------- share-link building ----------

fn q_enc(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

impl Node {
    pub fn to_share_link(&self) -> String {
        match self.proto.as_str() {
            "vless" => {
                let mut q = vec![
                    format!("encryption=none"),
                    format!("type={}", self.net),
                ];
                if !self.flow.is_empty() { q.push(format!("flow={}", self.flow)); }
                if !self.tls.is_empty() { q.push(format!("security={}", self.tls)); }
                if !self.sni.is_empty() { q.push(format!("sni={}", self.sni)); }
                if !self.fp.is_empty() { q.push(format!("fp={}", self.fp)); }
                if !self.alpn.is_empty() { q.push(format!("alpn={}", self.alpn)); }
                if !self.pbk.is_empty() { q.push(format!("pbk={}", self.pbk)); }
                if !self.sid.is_empty() { q.push(format!("sid={}", self.sid)); }
                if !self.spx.is_empty() { q.push(format!("spx={}", self.spx)); }
                if !self.header_type.is_empty() { q.push(format!("headerType={}", self.header_type)); }
                if !self.path.is_empty() { q.push(format!("path={}", q_enc(&self.path))); }
                if !self.host.is_empty() { q.push(format!("host={}", self.host)); }
                if !self.service_name.is_empty() { q.push(format!("serviceName={}", self.service_name)); }
                format!("vless://{}@{}:{}?{}#{}", self.uuid, self.add, self.port, q.join("&"), q_enc(&self.name))
            }
            "trojan" => {
                let mut q = vec![format!("security={}", if self.tls.is_empty() { "tls" } else { &self.tls })];
                if !self.sni.is_empty() { q.push(format!("sni={}", self.sni)); }
                if !self.fp.is_empty() { q.push(format!("fp={}", self.fp)); }
                if !self.alpn.is_empty() { q.push(format!("alpn={}", self.alpn)); }
                if !self.net.is_empty() { q.push(format!("type={}", self.net)); }
                if !self.path.is_empty() { q.push(format!("path={}", q_enc(&self.path))); }
                if !self.host.is_empty() { q.push(format!("host={}", self.host)); }
                format!("trojan://{}@{}:{}?{}#{}", q_enc(&self.password), self.add, self.port, q.join("&"), q_enc(&self.name))
            }
            "ss" => {
                let cred = b64_encode(format!("{}:{}", self.security, self.password).as_bytes());
                format!("ss://{}@{}:{}#{}", cred, self.add, self.port, q_enc(&self.name))
            }
            "vmess" => {
                let j = serde_json::json!({
                    "v": "2", "ps": self.name, "add": self.add, "port": self.port.to_string(),
                    "id": self.uuid, "aid": self.aid.to_string(), "scy": self.scy,
                    "net": self.net, "type": self.header_type, "host": self.host,
                    "path": self.path, "tls": self.tls, "sni": self.sni, "alpn": self.alpn, "fp": self.fp,
                });
                format!("vmess://{}", b64_encode(j.to_string().as_bytes()))
            }
            _ => String::new(),
        }
    }
}
