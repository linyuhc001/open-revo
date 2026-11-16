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

/// One user-defined routing rule (v2rayN rule form). `domain` entries accept
/// `geosite:xx` / `domain:xx` / plain substrings, `ip` accepts `geoip:xx` /
/// `geoip:private` / CIDR; `port` / `network` / `protocol` mirror the v2rayN
/// rule editor (e.g. block udp 443 → outbound=block, port="443",
/// network="udp").
#[derive(Clone, Serialize, Deserialize)]
pub struct Rule {
    #[serde(default)]
    pub outbound: String, // proxy | direct | block
    #[serde(default)]
    pub domain: Vec<String>,
    #[serde(default)]
    pub ip: Vec<String>,
    #[serde(default)]
    pub port: String,
    #[serde(default)]
    pub network: String,
    #[serde(default)]
    pub protocol: Vec<String>,
}

/// DNS settings, v2rayN "DNS 基础设置" simple mode, field-for-field:
/// three server slots (direct / remote / bootstrap, comma-separated lists)
/// plus the per-outbound resolve strategies. All resolution is done by the
/// xray core — the plugin only writes the `dns` block and routing rules.
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
    /// v2rayN Strategy4Freedom → direct (freedom) outbound sockopt.domainStrategy
    #[serde(default)]
    pub strategy_direct: String,
    /// v2rayN Strategy4Proxy → proxy outbound targetStrategy
    #[serde(default)]
    pub strategy_remote: String,
    /// v2rayN Strategy4ProxyDial → proxy outbound sockopt.domainStrategy
    #[serde(default)]
    pub strategy_dial: String,
    /// v2rayN BlockAAAAQuery → dns.queryStrategy = UseIPv4
    #[serde(default)]
    pub block_aaaa: bool,
    #[serde(default)]
    pub parallel_query: bool,
    #[serde(default)]
    pub serve_stale: bool,
}

impl Default for DnsCfg {
    fn default() -> Self {
        DnsCfg {
            enabled: false,
            direct_dns: DEFAULT_DIRECT_DNS.into(),
            remote_dns: DEFAULT_REMOTE_DNS.into(),
            bootstrap_dns: DEFAULT_BOOTSTRAP_DNS.into(),
            strategy_direct: String::new(),
            strategy_remote: String::new(),
            strategy_dial: String::new(),
            block_aaaa: false,
            parallel_query: false,
            serve_stale: false,
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

/// v2rayN ParseDnsAddresses: comma split, `dhcp*` → localhost, dedup, fall
/// back to the slot's default when empty.
fn parse_dns_addrs(input: &str, default: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for s in input.split(',') {
        let s = s.trim();
        if s.is_empty() {
            continue;
        }
        let s = if s.to_ascii_lowercase().starts_with("dhcp") {
            "localhost".to_string()
        } else {
            s.to_string()
        };
        if !out.contains(&s) {
            out.push(s);
        }
    }
    if out.is_empty() {
        out.push(default.to_string());
    }
    out
}

/// v2rayN CreateDnsServer: `https://…` kept verbatim, `tcp://host[:port]` →
/// `tcp://host` + port, plain/udp `host[:port][/path]` → host + port.
fn dns_server_entry(addr: &str, domains: &[String]) -> Value {
    let a = addr.trim();
    let (scheme, rest) = match a.find("://") {
        Some(i) => (a[..i].to_ascii_lowercase(), &a[i + 3..]),
        None => (String::new(), a),
    };
    let mut obj = serde_json::Map::new();
    let mut port: Option<u16> = None;
    let address;
    if scheme.is_empty() || scheme == "udp" {
        let hostport = rest.split('/').next().unwrap_or(rest);
        match hostport.rsplit_once(':') {
            Some((h, ps)) if !h.is_empty() && !ps.is_empty() && ps.chars().all(|c| c.is_ascii_digit()) => {
                address = h.to_string();
                port = ps.parse::<u16>().ok();
            }
            _ => address = hostport.to_string(),
        }
    } else if scheme == "tcp" {
        let hostport = rest.split('/').next().unwrap_or(rest);
        match hostport.rsplit_once(':') {
            Some((h, ps)) if !h.is_empty() && !ps.is_empty() && ps.chars().all(|c| c.is_ascii_digit()) => {
                address = format!("tcp://{h}");
                port = ps.parse::<u16>().ok();
            }
            _ => address = format!("tcp://{hostport}"),
        }
    } else {
        address = a.to_string(); // https and friends stay whole
    }
    obj.insert("address".into(), json!(address));
    if let Some(p) = port {
        obj.insert("port".into(), json!(p));
    }
    obj.insert("skipFallback".into(), json!(true));
    if !domains.is_empty() {
        obj.insert("domains".into(), json!(domains));
    }
    Value::Object(obj)
}

/// v2rayN FillDnsServers domain extraction: walk the effective routing rules
/// and bucket domain conditions by outbound — direct rules' domains must be
/// resolved by the direct DNS, everything else by the remote DNS. `geosite:` /
/// `ext:` entries go to separate buckets (still per-outbound).
fn extract_dns_domains(rule_list: &[Value]) -> (Vec<String>, Vec<String>, Vec<String>, Vec<String>) {
    let bucket = |lists: &mut [Vec<String>; 2], d: &str| {
        let is_geo = d.starts_with("geosite:") || d.starts_with("ext:");
        let l = &mut lists[if is_geo { 1 } else { 0 }];
        if !l.iter().any(|x| x == d) {
            l.push(d.to_string());
        }
    };
    let mut direct = [Vec::new(), Vec::new()]; // [plain, geo]
    let mut proxy = [Vec::new(), Vec::new()];
    for r in rule_list {
        let ob = r.get("outboundTag").and_then(|x| x.as_str()).unwrap_or("");
        let Some(dom) = r.get("domain").and_then(|x| x.as_array()) else {
            continue;
        };
        for d in dom.iter().filter_map(|x| x.as_str()) {
            if d.starts_with('#') {
                continue;
            }
            match ob {
                "direct" => bucket(&mut direct, d),
                "block" => {}
                _ => bucket(&mut proxy, d),
            }
        }
    }
    (direct[0].clone(), direct[1].clone(), proxy[0].clone(), proxy[1].clone())
}

/// v2rayN useDirectDns: the last routing rule is an unconditional
/// everything→direct catch-all (whitelist / 绕过大陆 style).
fn last_is_direct_catchall(rule_list: &[Value]) -> bool {
    let Some(r) = rule_list.last() else { return false };
    if r.get("outboundTag").and_then(|x| x.as_str()).unwrap_or("") != "direct" {
        return false;
    }
    let is_empty_list = |k: &str| -> bool {
        r.get(k).and_then(|x| x.as_array()).map_or(true, |a| a.is_empty())
    };
    let ip_any = is_empty_list("ip")
        || r.get("ip").and_then(|x| x.as_array()).map_or(false, |a| {
            a.iter().any(|x| x.as_str() == Some("0.0.0.0/0"))
        });
    let port = r.get("port").and_then(|x| x.as_str()).unwrap_or("");
    let port_any = port.is_empty() || port == "0-65535" || port == "1-65535";
    let net = r.get("network").and_then(|x| x.as_str()).unwrap_or("");
    let net_any = net.is_empty() || net == "tcp,udp" || net == "udp,tcp";
    is_empty_list("domain") && is_empty_list("protocol") && ip_any && port_any && net_any
}

/// Build the `dns` block the v2rayN simple-mode way (FillDnsServers):
/// 1. bootstrap (pure IP) servers constrained to the DoH servers' domains,
/// 2. remote DNS for proxy-side domains, direct DNS (tagged `direct-dns-N`)
///    for direct-side domains — pulled from the routing rules,
/// 3. fallback servers: direct DNS when the last routing rule is a direct
///    catch-all, otherwise remote DNS — matching v2rayN exactly.
fn fill_dns_servers(dns: &DnsCfg, rule_list: &[Value]) -> (Vec<Value>, Vec<String>) {
    let direct = parse_dns_addrs(&dns.direct_dns, DEFAULT_DIRECT_DNS);
    let remote = parse_dns_addrs(&dns.remote_dns, DEFAULT_REMOTE_DNS);
    let bootstrap = parse_dns_addrs(&dns.bootstrap_dns, DEFAULT_BOOTSTRAP_DNS);

    // domains that need bootstrap resolution = the domain-form servers above
    let mut boot_domains: Vec<String> = direct
        .iter()
        .chain(remote.iter())
        .filter_map(|s| dns_server_domain(s))
        .map(|d| format!("full:{d}"))
        .collect();
    boot_domains.sort();
    boot_domains.dedup();

    let (direct_dom, direct_geo, proxy_dom, proxy_geo) = extract_dns_domains(rule_list);

    let mut servers: Vec<Value> = Vec::new();
    let mut direct_tags: Vec<String> = Vec::new();
    let mut tag_n = 1usize;

    if !boot_domains.is_empty() {
        for b in &bootstrap {
            let mut e = dns_server_entry(b, &boot_domains);
            e.as_object_mut().unwrap().insert("tag".into(), json!(format!("boot-dns-{tag_n}")));
            tag_n += 1;
            servers.push(e);
        }
    }

    let mut add = |servers: &mut Vec<Value>, addrs: &[String], domains: &[String], is_direct: bool| {
        if domains.is_empty() {
            return;
        }
        for a in addrs {
            let mut e = dns_server_entry(a, domains);
            let obj = e.as_object_mut().unwrap();
            if is_direct {
                let t = format!("direct-dns-{tag_n}");
                tag_n += 1;
                direct_tags.push(t.clone());
                obj.insert("tag".into(), json!(t));
            } else {
                obj.insert("tag".into(), json!(format!("remote-dns-{tag_n}")));
                tag_n += 1;
            }
            servers.push(e);
        }
    };
    // order mirrors v2rayN FillDnsServers
    add(&mut servers, &remote, &proxy_dom, false);
    add(&mut servers, &direct, &direct_dom, true);
    add(&mut servers, &remote, &proxy_geo, false);
    add(&mut servers, &direct, &direct_geo, true);

    // fallback servers for domains matched by no rule
    if last_is_direct_catchall(rule_list) {
        for a in &direct {
            let mut e = dns_server_entry(a, &[]);
            e.as_object_mut().unwrap().insert("skipFallback".into(), json!(false));
            let t = format!("direct-dns-{tag_n}");
            tag_n += 1;
            direct_tags.push(t.clone());
            e.as_object_mut().unwrap().insert("tag".into(), json!(t));
            servers.push(e);
        }
    } else {
        for a in &remote {
            // v2rayN appends these as plain strings — no skipFallback, no tag
            servers.push(json!(a));
        }
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
    tun: bool,
) -> Result<String, String> {
    let mut outbound = node_outbound(node)?;
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
        { "type": "field", "domain": ["geosite:category-ads-all"], "outboundTag": "block" },
        { "type": "field", "domain": ["geosite:cn"], "outboundTag": "direct" },
        { "type": "field", "ip": ["geoip:cn"], "outboundTag": "direct" }
    ]);
    let rule_from = |r: &Rule| -> Value {
        let mut obj = serde_json::Map::new();
        obj.insert("type".into(), json!("field"));
        obj.insert("outboundTag".into(), json!(r.outbound));
        if !r.domain.is_empty() {
            obj.insert("domain".into(), json!(r.domain));
        }
        if !r.ip.is_empty() {
            obj.insert("ip".into(), json!(r.ip));
        }
        if !r.port.is_empty() {
            obj.insert("port".into(), json!(r.port));
        }
        if !r.network.is_empty() {
            obj.insert("network".into(), json!(r.network));
        }
        if !r.protocol.is_empty() {
            obj.insert("protocol".into(), json!(r.protocol));
        }
        Value::Object(obj)
    };
    let mut rule_list: Vec<Value> = if rules.is_empty() {
        default_rules.as_array().unwrap()
            .iter().filter(|r| rule_keeps(r)).cloned().collect()
    } else {
        rules.iter().map(rule_from).filter(|v| rule_keeps(v)).collect()
    };
    let strategy = match routing_strategy {
        "AsIs" | "IPIfNonMatch" | "IPOnDemand" if !routing_strategy.is_empty() => routing_strategy,
        _ => "IPIfNonMatch",
    };

    // Outbound resolve strategies, v2rayN GenDns style. Only applied when
    // nonempty and not "AsIs".
    let apply_sockopt_strategy = |out: &mut Value, s: &str| {
        let o = out.as_object_mut().unwrap();
        let stream = o.entry("streamSettings".to_string())
            .or_insert_with(|| json!({}))
            .as_object_mut().unwrap();
        let sock = stream.entry("sockopt".to_string())
            .or_insert_with(|| json!({}))
            .as_object_mut().unwrap();
        sock.insert("domainStrategy".into(), json!(s));
    };

    // DNS block, v2rayN simple-mode style. Domain buckets + the catch-all
    // check are computed from the USER rules only (before the final
    // catch-all is appended), matching FillDnsServers' input.
    let mut dns_block: Option<Value> = None;
    let mut dns_direct_rule: Option<Value> = None;
    if dns.enabled {
        let (servers, direct_tags) = fill_dns_servers(dns, &rule_list);
        if !servers.is_empty() {
            if !direct_tags.is_empty() {
                dns_direct_rule = Some(json!({
                    "type": "field",
                    "inboundTag": direct_tags,
                    "outboundTag": "direct",
                }));
            }
            let mut d = serde_json::Map::new();
            d.insert("tag".into(), json!("dns-module"));
            d.insert("servers".into(), Value::Array(servers));
            if dns.block_aaaa {
                d.insert("queryStrategy".into(), json!("UseIPv4"));
            }
            if dns.serve_stale {
                d.insert("serveStale".into(), json!(true));
            }
            if dns.parallel_query {
                d.insert("enableParallelQuery".into(), json!(true));
            }
            dns_block = Some(Value::Object(d));
        }
    }

    // Final catch-all rule, v2rayN BuildFinalRule: everything unmatched goes
    // to the proxy. With IPIfNonMatch it matches by IP (0.0.0.0/0, ::/0)
    // instead of network.
    let mut final_rule = json!({ "type": "field", "outboundTag": "proxy" });
    {
        let f = final_rule.as_object_mut().unwrap();
        if strategy == "IPIfNonMatch" {
            f.insert("ip".into(), json!(["0.0.0.0/0", "::/0"]));
        } else {
            f.insert("network".into(), json!("tcp,udp"));
        }
    }
    rule_list.push(final_rule);

    if let Some(r) = dns_direct_rule {
        // direct DNS queries leave via direct — inserted before the final
        // catch-all (v2rayN inserts ahead of the first proxy catch-all)
        let idx = rule_list.len() - 1;
        rule_list.insert(idx, r);
        rule_list.push(json!({
            "type": "field",
            "inboundTag": ["dns-module"],
            "outboundTag": "proxy",
        }));
    }

    // Outbound resolve strategies (after final rules are known).
    let set_outbound_strategy = |ob: &mut Value, target: Option<&str>, sockopt: Option<&str>| {
        if let Some(t) = target {
            ob.as_object_mut().unwrap().insert("targetStrategy".into(), json!(t));
        }
        if let Some(s) = sockopt {
            apply_sockopt_strategy(ob, s);
        }
    };
    // proxy outbound (outbounds[0]) — but we build the outbounds array inline
    // in the cfg json below, so mutate `outbound` (the node/proxy outbound)
    // directly here.
    let proxy_target = if dns.strategy_remote.is_empty() || dns.strategy_remote == "AsIs" { None } else { Some(dns.strategy_remote.as_str()) };
    let proxy_sock = if dns.strategy_dial.is_empty() || dns.strategy_dial == "AsIs" { None } else { Some(dns.strategy_dial.as_str()) };
    set_outbound_strategy(&mut outbound, proxy_target, proxy_sock);

    let mut direct_outbound = json!({ "tag": "direct", "protocol": "freedom", "settings": {} });
    if !dns.strategy_direct.is_empty() && dns.strategy_direct != "AsIs" {
        apply_sockopt_strategy(&mut direct_outbound, &dns.strategy_direct);
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
            direct_outbound,
            { "tag": "block", "protocol": "blackhole", "settings": {} }
        ],
        "routing": {
            "domainStrategy": strategy,
            "rules": rule_list
        }
    });
    if tun {
        // Xray-native TUN inbound (proxy/tun + wintun.dll, must sit next to
        // xray.exe; needs admin rights). Field names verified against
        // infra/conf/tun.go on the Xray-core tree:
        // - autoSystemRoutingTable installs the catch-all route via wintun's
        //   LUID (Metric 0) and auto-sets autoOutboundsInterface="auto",
        //   which binds the node dialing sockets to the physical adapter
        //   (IP_UNICAST_IF) — loop protection is built in.
        // - autoSystemWfpBlockLeak requires autoSystemRoutingTable (Windows
        //   check in TunConfig.Build) and blocking DNS leaks requires the
        //   `dns` list on the adapter — both satisfied here.
        // - "misconfigtun" blackholes traffic that would re-enter the TUN.
        let tun_in = json!({
            "tag": "tun-in",
            "protocol": "tun",
            "settings": {
                "name": "revo_tun",
                "mtu": 9000,
                "gateway": ["172.19.0.1/30"],
                "dns": ["223.5.5.5", "119.29.29.29"],
                "autoSystemRoutingTable": ["0.0.0.0/0"],
                "autoSystemWfpBlockLeak": ["dns", "misconfigtun"]
            },
            "sniffing": { "enabled": true, "destOverride": ["http", "tls", "quic"] }
        });
        cfg.as_object_mut().unwrap()
            .get_mut("inbounds").unwrap().as_array_mut().unwrap()
            .push(tun_in);
    }
    if let Some(d) = dns_block {
        cfg.as_object_mut().unwrap().insert("dns".into(), d);
    }
    Ok(cfg.to_string())
}

fn stream_settings(node: &Node) -> Result<Value, String> {
    let net = if node.net.is_empty() { "tcp" } else { node.net.as_str() };
    let mut s = json!({ "network": net });
    let obj = s.as_object_mut().unwrap();

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
