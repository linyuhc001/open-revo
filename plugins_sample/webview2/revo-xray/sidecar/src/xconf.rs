// Xray client config generation.
//
// Two socks/http local inbounds + the selected node's outbound, plus the
// standard CN-direct routing set (geosite/geoip from the dat files shipped in
// the Xray zip). Unsupported transport/security combinations are rejected with
// a readable message instead of producing a config that silently fails.

use crate::node::Node;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub struct Ports {
    pub socks: u16,
    pub http: u16,
}

/// One user-defined routing rule (v2rayN simplified form). `domain` entries
/// accept `geosite:xx` / `domain:xx` / plain substrings, `ip` accepts
/// `geoip:xx` / `geoip:private` / CIDR.
#[derive(Clone, Serialize, Deserialize)]
pub struct Rule {
    #[serde(default)]
    pub outbound: String, // proxy | direct | block
    #[serde(default)]
    pub domain: Vec<String>,
    #[serde(default)]
    pub ip: Vec<String>,
}

/// Basic DNS settings, v2rayN's "DNS 基础设置" (simple mode). Three slots:
/// direct DNS (CN domains, queried direct), remote DNS (DoH, queried through
/// the proxy outbound) and bootstrap DNS (plain-IP servers used only to
/// resolve the DoH servers' own domain names). All resolution itself is done
/// by the xray core — the plugin only writes the `dns` block and the matching
/// `inboundTag: dns-module` routing rules.
#[derive(Clone, Serialize, Deserialize)]
pub struct DnsCfg {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub direct_dns: String, // v2rayN default: 119.29.29.29
    #[serde(default)]
    pub remote_dns: String, // v2rayN default: https://cloudflare-dns.com/dns-query
    #[serde(default)]
    pub bootstrap_dns: String, // v2rayN default: 119.29.29.29 (pure IP)
    #[serde(default)]
    pub query_strategy: String, // UseIP | UseIPv4 | UseIPv6 (empty = UseIP)
}

impl Default for DnsCfg {
    fn default() -> Self {
        DnsCfg {
            enabled: false,
            direct_dns: DEFAULT_DIRECT_DNS.into(),
            remote_dns: DEFAULT_REMOTE_DNS.into(),
            bootstrap_dns: DEFAULT_BOOTSTRAP_DNS.into(),
            query_strategy: String::new(),
        }
    }
}

pub const DEFAULT_DIRECT_DNS: &str = "119.29.29.29";
pub const DEFAULT_REMOTE_DNS: &str = "https://cloudflare-dns.com/dns-query";
pub const DEFAULT_BOOTSTRAP_DNS: &str = "119.29.29.29";

/// Extract the host part of a DNS address (`https://dns.google/dns-query`,
/// `tcp://8.8.8.8:853`, `223.5.5.5`) when it is a real domain name — those
/// domains need bootstrap resolution. Returns None for plain IPs / localhost.
fn dns_server_domain(addr: &str) -> Option<String> {
    let a = addr.trim();
    if a.is_empty() || a == "localhost" {
        return None;
    }
    let rest = match a.find("://") {
        Some(i) => &a[i + 3..],
        None => a,
    };
    let host = rest.split(['/', ':']).next().unwrap_or("");
    if host.is_empty() {
        return None;
    }
    let ipv4 = host.contains('.') && host.split('.').all(|p| p.parse::<u8>().is_ok());
    let ipv6 = host.contains(':') && host.parse::<std::net::Ipv6Addr>().is_ok();
    if ipv4 || ipv6 {
        None
    } else {
        Some(host.to_string())
    }
}

/// Build the `dns` block the v2rayN simple-mode way:
/// 1. bootstrap (pure IP) servers constrained to the DoH servers' domains,
/// 2. remote DNS with `skipFallback`, reachable only via its tag + routing,
/// 3. direct DNS as the last, fallback-permitted server.
/// The direct servers get `direct-dns-N` tags; build_config adds the routing
/// rules `inboundTag direct-dns-N -> direct` and `dns-module -> proxy`.
fn dns_servers(dns: &DnsCfg) -> (Vec<Value>, Vec<String>) {
    let direct = if dns.direct_dns.is_empty() { DEFAULT_DIRECT_DNS } else { dns.direct_dns.trim() };
    let remote = if dns.remote_dns.is_empty() { DEFAULT_REMOTE_DNS } else { dns.remote_dns.trim() };
    let bootstrap = if dns.bootstrap_dns.is_empty() { DEFAULT_BOOTSTRAP_DNS } else { dns.bootstrap_dns.trim() };

    // domains that need bootstrap resolution = the domain-form servers above
    let mut boot_domains: Vec<String> = [direct, remote]
        .iter()
        .filter_map(|s| dns_server_domain(s))
        .map(|d| format!("full:{d}"))
        .collect();
    boot_domains.sort();
    boot_domains.dedup();

    let mut servers = Vec::new();
    if !boot_domains.is_empty() {
        for b in bootstrap.split(',') {
            let b = b.trim();
            if b.is_empty() {
                continue;
            }
            servers.push(json!({
                "address": b,
                "domains": boot_domains,
                "skipFallback": true,
            }));
        }
    }
    servers.push(json!({
        "address": remote,
        "skipFallback": true,
        "tag": "remote-dns",
    }));
    let mut direct_tags = Vec::new();
    for (i, d) in direct.split(',').enumerate() {
        let d = d.trim();
        if d.is_empty() {
            continue;
        }
        let tag = format!("direct-dns-{}", i + 1);
        direct_tags.push(tag.clone());
        servers.push(json!({
            "address": d,
            "skipFallback": false,
            "tag": tag,
        }));
    }
    (servers, direct_tags)
}

pub fn build_config(
    node: &Node,
    ports: &Ports,
    geoip_ok: bool,
    geosite_ok: bool,
    rules: &[Rule],
    dns: &DnsCfg,
    routing_strategy: &str,
) -> Result<String, String> {
    let outbound = node_outbound(node)?;
    // Drop rules that reference geo dat files we don't have — xray refuses to
    // load the whole config otherwise. Plain domain/CIDR rules always survive.
    let rule_keeps = |r: &Value| -> bool {
        let ip_ok = r.get("ip").and_then(|v| v.as_array())
            .map(|a| geoip_ok || !a.iter().any(|x| x.as_str().map_or(false, |s| s.starts_with("geoip:"))))
            .unwrap_or(true);
        let dom_ok = r.get("domain").and_then(|v| v.as_array())
            .map(|a| geosite_ok || !a.iter().any(|x| x.as_str().map_or(false, |s| s.starts_with("geosite:"))))
            .unwrap_or(true);
        ip_ok && dom_ok
    };
    let default_rules = json!([
        { "type": "field", "ip": ["geoip:private"], "outboundTag": "direct" },
        { "type": "field", "domain": ["geosite:private"], "outboundTag": "direct" },
        { "type": "field", "domain": ["geosite:cn"], "outboundTag": "direct" },
        { "type": "field", "ip": ["geoip:cn"], "outboundTag": "direct" }
    ]);
    let rule_list: Vec<Value> = if rules.is_empty() {
        default_rules.as_array().unwrap()
            .iter().filter(|r| rule_keeps(r)).cloned().collect()
    } else {
        rules.iter().filter_map(|r| {
            let mut obj = serde_json::Map::new();
            obj.insert("type".into(), json!("field"));
            obj.insert("outboundTag".into(), json!(r.outbound));
            if !r.domain.is_empty() {
                obj.insert("domain".into(), json!(r.domain));
            }
            if !r.ip.is_empty() {
                obj.insert("ip".into(), json!(r.ip));
            }
            let v = Value::Object(obj);
            rule_keeps(&v).then_some(v)
        }).collect()
    };
    let strategy = match routing_strategy {
        "AsIs" | "IPIfNonMatch" | "IPOnDemand" if !routing_strategy.is_empty() => routing_strategy,
        _ => "IPIfNonMatch",
    };
    // DNS module routing, v2rayN simple-mode style: direct DNS queries leave
    // via the direct outbound, everything else the DNS module dials (remote
    // DoH) goes through the proxy.
    let mut rule_list: Vec<Value> = rule_list;
    let mut dns_block: Option<Value> = None;
    if dns.enabled {
        let (servers, direct_tags) = dns_servers(dns);
        if !servers.is_empty() {
            if !direct_tags.is_empty() {
                rule_list.push(json!({
                    "type": "field",
                    "inboundTag": direct_tags,
                    "outboundTag": "direct",
                }));
            }
            rule_list.push(json!({
                "type": "field",
                "inboundTag": ["dns-module"],
                "outboundTag": "proxy",
            }));
            let strat = if dns.query_strategy.is_empty() { "UseIP".to_string() } else { dns.query_strategy.clone() };
            dns_block = Some(json!({
                "tag": "dns-module",
                "servers": servers,
                "queryStrategy": strat,
            }));
        }
    }
    let mut cfg = json!({
        "log": { "loglevel": "warning" },
        "inbounds": [
            {
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "port": ports.socks,
                "protocol": "socks",
                "settings": { "udp": true },
                "sniffing": { "enabled": true, "destOverride": ["http", "tls", "quic"] }
            },
            {
                "tag": "http-in",
                "listen": "127.0.0.1",
                "port": ports.http,
                "protocol": "http",
                "settings": {}
            }
        ],
        "outbounds": [
            outbound,
            { "tag": "direct", "protocol": "freedom", "settings": {} },
            { "tag": "block", "protocol": "blackhole", "settings": {} }
        ],
        "routing": {
            "domainStrategy": strategy,
            "rules": rule_list
        }
    });
    if let Some(d) = dns_block {
        cfg.as_object_mut().unwrap().insert("dns".into(), d);
    }
    Ok(cfg.to_string())
}

fn stream_settings(node: &Node) -> Result<Value, String> {
    let net = if node.net.is_empty() { "tcp" } else { node.net.as_str() };
    let mut s = json!({ "network": net });
    let mut obj = s.as_object_mut().unwrap();

    match node.tls.as_str() {
        "tls" => {
            let mut t = json!({
                "serverName": if node.sni.is_empty() { node.add.clone() } else { node.sni.clone() },
                "allowInsecure": node.allow_insecure,
            });
            let tls = t.as_object_mut().unwrap();
            if !node.alpn.is_empty() {
                tls.insert("alpn".into(), json!(node.alpn.split(',').map(|x| x.trim().to_string()).collect::<Vec<_>>()));
            }
            if !node.fp.is_empty() {
                tls.insert("fingerprint".into(), json!(node.fp));
            }
            obj.insert("security".into(), json!("tls"));
            obj.insert("tlsSettings".into(), t);
        }
        "reality" => {
            if node.pbk.is_empty() || node.sni.is_empty() {
                return Err("reality 节点缺少 pbk 或 sni 参数".into());
            }
            let mut r = json!({
                "serverName": node.sni,
                "fingerprint": if node.fp.is_empty() { "chrome".to_string() } else { node.fp.clone() },
                "publicKey": node.pbk,
                "shortId": node.sid,
            });
            if !node.spx.is_empty() {
                r.as_object_mut().unwrap().insert("spiderX".into(), json!(node.spx));
            }
            obj.insert("security".into(), json!("reality"));
            obj.insert("realitySettings".into(), r);
        }
        "" | "none" => {
            obj.insert("security".into(), json!("none"));
        }
        other => return Err(format!("不支持的安全层: {other}")),
    }

    match net {
        "tcp" => {
            let mut t = json!({});
            if node.header_type == "http" {
                let mut header = json!({ "type": "http" });
                if !node.host.is_empty() || !node.path.is_empty() {
                    let mut req = json!({});
                    if !node.host.is_empty() {
                        req.as_object_mut().unwrap().insert("Host".into(), json!(node.host.split(',').collect::<Vec<_>>()));
                    }
                    if !node.path.is_empty() {
                        req.as_object_mut().unwrap().insert("path".into(), json!(node.path));
                    }
                    header.as_object_mut().unwrap().insert("request".into(), req);
                }
                t.as_object_mut().unwrap().insert("header".into(), header);
            }
            obj.insert("tcpSettings".into(), t);
        }
        "ws" | "websocket" => {
            let mut w = json!({ "path": if node.path.is_empty() { "/".to_string() } else { node.path.clone() } });
            if !node.host.is_empty() {
                w.as_object_mut().unwrap().insert("headers".into(), json!({ "Host": node.host }));
            }
            obj.insert("network".into(), json!("ws"));
            obj.insert("wsSettings".into(), w);
        }
        "grpc" => {
            obj.insert("grpcSettings".into(), json!({
                "serviceName": node.service_name,
                "multiMode": false,
            }));
        }
        "h2" | "http" => {
            obj.insert("network".into(), json!("h2"));
            obj.insert("httpSettings".into(), json!({
                "path": node.path,
                "host": if node.host.is_empty() { vec![node.add.clone()] } else { node.host.split(',').map(|x| x.trim().to_string()).collect::<Vec<_>>() },
            }));
        }
        "httpupgrade" => {
            obj.insert("httpupgradeSettings".into(), json!({
                "path": node.path,
                "host": node.host,
            }));
        }
        "xhttp" | "splithttp" => {
            obj.insert("network".into(), json!("xhttp"));
            let mut x = json!({
                "path": node.path,
                "host": node.host,
            });
            if !node.mode.is_empty() {
                x.as_object_mut().unwrap().insert("mode".into(), json!(node.mode));
            }
            obj.insert("xhttpSettings".into(), x);
        }
        "kcp" => {
            let mut k = json!({ "mtu": 1350, "tti": 50 });
            if !node.header_type.is_empty() {
                k.as_object_mut().unwrap().insert("header".into(), json!({ "type": node.header_type }));
            }
            obj.insert("kcpSettings".into(), k);
        }
        other => return Err(format!("不支持的传输层: {other}")),
    }
    Ok(s)
}

fn node_outbound(node: &Node) -> Result<Value, String> {
    let stream = stream_settings(node)?;
    let settings = match node.proto.as_str() {
        "vless" => json!({
            "vnext": [{
                "address": node.add,
                "port": node.port,
                "users": [{
                    "id": node.uuid,
                    "encryption": "none",
                    "flow": node.flow,
                    "level": 0,
                }],
            }]
        }),
        "vmess" => json!({
            "vnext": [{
                "address": node.add,
                "port": node.port,
                "users": [{
                    "id": node.uuid,
                    "alterId": node.aid,
                    "security": if node.scy.is_empty() { "auto".to_string() } else { node.scy.clone() },
                    "level": 0,
                }],
            }]
        }),
        "trojan" => json!({
            "servers": [{
                "address": node.add,
                "port": node.port,
                "password": node.password,
                "level": 0,
            }]
        }),
        "ss" => json!({
            "servers": [{
                "address": node.add,
                "port": node.port,
                "method": node.security,
                "password": node.password,
                "level": 0,
            }]
        }),
        other => return Err(format!("不支持的协议: {other}")),
    };
    Ok(json!({
        "tag": "proxy",
        "protocol": match node.proto.as_str() {
            "ss" => "shadowsocks",
            p => p,
        },
        "settings": settings,
        "streamSettings": stream,
    }))
}
