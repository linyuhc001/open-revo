// Xray client config generation.
//
// Two socks/http local inbounds + the selected node's outbound, plus the
// standard CN-direct routing set (geosite/geoip from the dat files shipped in
// the Xray zip). Unsupported transport/security combinations are rejected with
// a readable message instead of producing a config that silently fails.

use crate::node::Node;
use serde_json::{json, Value};

pub struct Ports {
    pub socks: u16,
    pub http: u16,
}

pub fn build_config(node: &Node, ports: &Ports, geoip_ok: bool, geosite_ok: bool) -> Result<String, String> {
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
    let rules: Vec<Value> = default_rules.as_array().unwrap()
        .iter().filter(|r| rule_keeps(r)).cloned().collect();
    let cfg = json!({
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
            "domainStrategy": "IPIfNonMatch",
            "rules": rules
        }
    });
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
