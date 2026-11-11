//! The MCP tools: each one a thin adapter over a REST handler, so what an
//! assistant sees and does is exactly what the panel sees and does — same
//! validation, same persistence, same log lines.
//!
//! Read tools are always listed. Tools that change things are listed only
//! while `[mcp] allow_changes` is on, and refuse to run otherwise.

use axum::{
    Json,
    extract::{Path, Query, State},
};
use serde_json::{Value, json};

use super::diagnose::{self, find_device};
use crate::ApiError;
use ferrite_app::AppState;
use ferrite_core::config::{BlocklistProfileConfig, RuleConfig};

/// What a call came to.
pub(super) enum Outcome {
    /// No tool by that name — a protocol error.
    Unknown,
    /// The tool's answer.
    Done(Value),
    /// The tool ran and failed; the message is for the assistant to read.
    Failed(String),
}

impl From<Result<Value, String>> for Outcome {
    fn from(r: Result<Value, String>) -> Self {
        match r {
            Ok(v) => Outcome::Done(v),
            Err(e) => Outcome::Failed(e),
        }
    }
}

fn api_err(e: ApiError) -> String {
    e.0.to_string()
}

/// What a tool does to the box, as the client is told in its annotations.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Effect {
    /// Only reads.
    Read,
    /// Adds or sets something; doing it twice changes nothing more.
    Set,
    /// Takes something away.
    Remove,
    /// Each call counts again (a pause runs from now).
    Again,
    /// Reaches outside the box (fetches the lists).
    Fetch,
}

/// One tool's listing.
fn tool(name: &str, title: &str, description: &str, schema: Value, effect: Effect) -> Value {
    json!({
        "name": name,
        "title": title,
        "description": description,
        "inputSchema": schema,
        "annotations": {
            "title": title,
            "readOnlyHint": effect == Effect::Read,
            "destructiveHint": effect == Effect::Remove,
            "idempotentHint": effect != Effect::Again,
            "openWorldHint": effect == Effect::Fetch,
        },
    })
}

fn no_args() -> Value {
    json!({ "type": "object", "properties": {}, "additionalProperties": false })
}

/// Tools that change things — refused unless `allow_changes` is on.
const WRITE_TOOLS: &[&str] = &[
    "block_domain",
    "allow_domain",
    "remove_domain_rule",
    "keep_blocked",
    "pause_filtering",
    "resume_filtering",
    "set_service_blocked",
    "set_device_profile",
    "route_through_tunnel",
    "remove_tunnel_route",
    "refresh_lists",
];

/// A device, as every tool takes one.
const CLIENT: &str = "The device: its IP, its MAC, or its name as list_clients shows it.";

pub(super) fn definitions(allow_changes: bool) -> Vec<Value> {
    let mut tools = vec![
        tool(
            "get_status",
            "Status",
            "Overview: is filtering on or paused, query counts, blocklist size, which device profiles are on right now, services blocked network-wide, SafeSearch, tunnel health.",
            no_args(),
            Effect::Read,
        ),
        tool(
            "diagnose",
            "Why doesn't it work?",
            "Start here when a site or app doesn't work, on one device or everywhere. Looks at every name of that site the device asked for lately and what each got; why the blocked ones are blocked (a list, your own rule, a blocked service, the device's profile); whether the device is filtered at all right now; upstream failures and names that don't exist; tunnels that carry the names and whether they're up. Returns a verdict (blocked, not_filtered, tunnel_down, upstream_errors, no_queries, fine), findings in plain words, and the tool calls that would fix it. Explain those to the owner; don't make changes they haven't agreed to.",
            json!({
                "type": "object",
                "properties": {
                    "site": { "type": "string", "description": "A catalog service (instagram, youtube — see list_services) or a domain or link (graph.instagram.com, https://www.bbc.co.uk/news)." },
                    "client": { "type": "string", "description": "The device it fails on (optional): its IP, its MAC, or its name as list_clients shows it." },
                    "minutes": { "type": "integer", "minimum": 1, "maximum": 1440, "default": 30, "description": "How far back to look in the query log." }
                },
                "required": ["site"],
                "additionalProperties": false
            }),
            Effect::Read,
        ),
        tool(
            "search_queries",
            "Search the query log",
            "Recent DNS queries, newest first. Filter by domain (substring), client (IP or MAC) and status. Use it to see what a device actually asked for and what happened to each name.",
            json!({
                "type": "object",
                "properties": {
                    "domain": { "type": "string", "description": "Substring of the queried name." },
                    "client": { "type": "string", "description": "Device IP or MAC." },
                    "status": { "type": "string", "enum": ["blocked", "allowed", "cached", "upstream", "routed"] },
                    "minutes": { "type": "integer", "minimum": 1, "maximum": 10080, "description": "Only the last N minutes." },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 200, "default": 30 }
                },
                "additionalProperties": false
            }),
            Effect::Read,
        ),
        tool(
            "check_domain",
            "Check a domain",
            "Why a domain is blocked or allowed: the lists, manual rules or services that match, the whitelist entry that exempts it, and whether a tunnel routes it. Pass a client IP or MAC to get that device's decision, which applies its profile, pauses and SafeSearch.",
            json!({
                "type": "object",
                "properties": {
                    "domain": { "type": "string" },
                    "client": { "type": "string", "description": "Device IP or MAC (optional)." }
                },
                "required": ["domain"],
                "additionalProperties": false
            }),
            Effect::Read,
        ),
        tool(
            "likely_breakage",
            "Likely broken by a block",
            "Names a list blocks that a device keeps asking for while it uses the site they belong to: what an app looks like when a block broke it (it opens, but the feed or login never comes). Each with the devices, the lists and how many tries. Manual rules and blocked services aren't included: those are the owner's choice. Also lists the names the owner chose to keep blocked.",
            no_args(),
            Effect::Read,
        ),
        tool(
            "top_domains",
            "Top domains",
            "The most queried, or most blocked, domains over the last hours.",
            json!({
                "type": "object",
                "properties": {
                    "kind": { "type": "string", "enum": ["queried", "blocked"], "default": "queried" },
                    "hours": { "type": "integer", "minimum": 1, "maximum": 168, "default": 24 },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 50, "default": 15 }
                },
                "additionalProperties": false
            }),
            Effect::Read,
        ),
        tool(
            "list_clients",
            "List devices",
            "Devices on the network with their names, addresses, query and block counts, when they were last and first seen, and the profile that applies to each right now.",
            json!({
                "type": "object",
                "properties": {
                    "hours": { "type": "integer", "minimum": 1, "maximum": 168, "default": 24 },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 200, "default": 50 }
                },
                "additionalProperties": false
            }),
            Effect::Read,
        ),
        tool(
            "device_report",
            "One device",
            "Everything about one device: its addresses, the profile on for it now, whether it's filtered right now, its query and block counts, top and top-blocked domains and the services it used over the last hours, its encrypted DNS names, and names that seem broken on it.",
            json!({
                "type": "object",
                "properties": {
                    "client": { "type": "string", "description": CLIENT },
                    "hours": { "type": "integer", "minimum": 1, "maximum": 168, "default": 24 }
                },
                "required": ["client"],
                "additionalProperties": false
            }),
            Effect::Read,
        ),
        tool(
            "list_profiles",
            "List profiles",
            "Per-device profiles: their devices, blocked services, lists, own block/allow entries, SafeSearch, schedule, and which are on right now.",
            no_args(),
            Effect::Read,
        ),
        tool(
            "list_services",
            "List services",
            "The built-in service catalog (YouTube, TikTok, Steam…) with the ids the other tools take, and which are blocked network-wide.",
            no_args(),
            Effect::Read,
        ),
        tool(
            "tunnel_status",
            "Tunnel status",
            "Tunnels (egresses) with their health and traffic, and the routing rules with their hit counts.",
            no_args(),
            Effect::Read,
        ),
        tool(
            "encrypted_dns_status",
            "Encrypted DNS",
            "Encrypted DNS for devices: whether DNS over TLS, HTTPS, HTTP/3 and QUIC are listening and on which ports, the certificate and its renewal, the devices answered away from home, what each device types in, and queries turned away.",
            no_args(),
            Effect::Read,
        ),
        tool(
            "recent_logs",
            "Server log",
            "Recent lines from ferrite's own log, newest last.",
            json!({
                "type": "object",
                "properties": {
                    "level": { "type": "string", "enum": ["error", "warn", "info", "debug"], "default": "warn" },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 200, "default": 50 }
                },
                "additionalProperties": false
            }),
            Effect::Read,
        ),
    ];
    if allow_changes {
        let domain_only = json!({
            "type": "object",
            "properties": { "domain": { "type": "string", "description": "Exact domain (covers its subdomains) or *.wildcard." } },
            "required": ["domain"],
            "additionalProperties": false
        });
        tools.extend([
            tool(
                "block_domain",
                "Block a domain",
                "Add a domain to the network-wide block list. It also blocks its subdomains.",
                domain_only.clone(),
                Effect::Set,
            ),
            tool(
                "allow_domain",
                "Allow a domain",
                "Add a domain to the network-wide allow list (whitelist), so no list or rule blocks it — except a device profile's own block.",
                domain_only,
                Effect::Set,
            ),
            tool(
                "remove_domain_rule",
                "Remove a domain rule",
                "Remove a domain from the network-wide block or allow list.",
                json!({
                    "type": "object",
                    "properties": {
                        "domain": { "type": "string" },
                        "list": { "type": "string", "enum": ["block", "allow"] }
                    },
                    "required": ["domain", "list"],
                    "additionalProperties": false
                }),
                Effect::Remove,
            ),
            tool(
                "keep_blocked",
                "Keep a name blocked",
                "The block on this name is fine: stop suggesting it in likely_breakage and on the dashboard. It covers its subdomains. Nothing about the block itself changes.",
                json!({
                    "type": "object",
                    "properties": { "domain": { "type": "string" } },
                    "required": ["domain"],
                    "additionalProperties": false
                }),
                Effect::Set,
            ),
            tool(
                "pause_filtering",
                "Pause filtering",
                "Pause filtering for some minutes, for the whole network or for given devices. It resumes on its own.",
                json!({
                    "type": "object",
                    "properties": {
                        "minutes": { "type": "integer", "minimum": 1, "maximum": 1440 },
                        "clients": { "type": "array", "items": { "type": "string" }, "description": "Device IPs or MACs; empty pauses the whole network." }
                    },
                    "required": ["minutes"],
                    "additionalProperties": false
                }),
                Effect::Again,
            ),
            tool(
                "resume_filtering",
                "Resume filtering",
                "End a pause early, for the whole network or for given devices.",
                json!({
                    "type": "object",
                    "properties": {
                        "clients": { "type": "array", "items": { "type": "string" } }
                    },
                    "additionalProperties": false
                }),
                Effect::Set,
            ),
            tool(
                "set_service_blocked",
                "Block or unblock a service",
                "Block or unblock a catalog service (see list_services), network-wide or for one profile.",
                json!({
                    "type": "object",
                    "properties": {
                        "service": { "type": "string", "description": "Service id, e.g. tiktok." },
                        "blocked": { "type": "boolean" },
                        "profile": { "type": "string", "description": "Profile id; omit for the whole network." }
                    },
                    "required": ["service", "blocked"],
                    "additionalProperties": false
                }),
                Effect::Set,
            ),
            tool(
                "set_device_profile",
                "Put a device in a profile",
                "Move a device into a profile (see list_profiles), taking it out of any other; or out of every profile, back to the network-wide rules.",
                json!({
                    "type": "object",
                    "properties": {
                        "client": { "type": "string", "description": CLIENT },
                        "profile": { "type": "string", "description": "Profile id; omit to take the device out of every profile." }
                    },
                    "required": ["client"],
                    "additionalProperties": false
                }),
                Effect::Set,
            ),
            tool(
                "route_through_tunnel",
                "Route through a tunnel",
                "Send a domain (with its subdomains; *.example.com for subdomains only) or a catalog service through a tunnel (see tunnel_status for their ids), for every device or only some. A name that already has a rule is moved to this tunnel. With fail_closed, connections are refused while the tunnel is down instead of going out directly.",
                json!({
                    "type": "object",
                    "properties": {
                        "domain": { "type": "string" },
                        "service": { "type": "string", "description": "Catalog service id, instead of a domain." },
                        "egress": { "type": "string", "description": "Tunnel id." },
                        "clients": { "type": "array", "items": { "type": "string" }, "description": "Only for these devices (IPs or MACs); empty for every device." },
                        "fail_closed": { "type": "boolean", "default": true }
                    },
                    "required": ["egress"],
                    "additionalProperties": false
                }),
                Effect::Set,
            ),
            tool(
                "remove_tunnel_route",
                "Stop routing through a tunnel",
                "Remove the tunnel rule for a domain or a catalog service; its names go out directly again.",
                json!({
                    "type": "object",
                    "properties": {
                        "domain": { "type": "string" },
                        "service": { "type": "string" }
                    },
                    "additionalProperties": false
                }),
                Effect::Remove,
            ),
            tool(
                "refresh_lists",
                "Refresh lists",
                "Fetch every subscribed blocklist and allowlist again now.",
                no_args(),
                Effect::Fetch,
            ),
        ]);
    }
    tools
}

pub(super) async fn call(state: &AppState, name: &str, args: Value) -> Outcome {
    let allow_changes = state.live_config.read().mcp.allow_changes;
    if WRITE_TOOLS.contains(&name) && !allow_changes {
        return Outcome::Failed(
            "Changes are switched off for assistants. The owner can allow them in Settings → Access."
                .into(),
        );
    }
    let s = state.clone();
    let result = match name {
        "get_status" => get_status(s).await,
        "diagnose" => diagnose::diagnose(s, &args).await,
        "likely_breakage" => crate::breakage::get_breakage(State(s))
            .await
            .map(|Json(v)| v)
            .map_err(api_err),
        "device_report" => device_report(s, &args).await,
        "encrypted_dns_status" => Ok(crate::secure_dns::get_secure_dns(State(s)).await.0),
        "search_queries" => search_queries(s, &args).await,
        "check_domain" => check_domain(s, &args).await,
        "top_domains" => top_domains(s, &args).await,
        "list_clients" => list_clients(s, &args).await,
        "list_profiles" => Ok(crate::profiles::get_profiles(State(s)).await.0),
        "list_services" => Ok(list_services(&s)),
        "tunnel_status" => Ok(tunnel_status(s).await),
        "recent_logs" => recent_logs(&args).await,
        "block_domain" => domain_rule(s, &args, true).await,
        "allow_domain" => domain_rule(s, &args, false).await,
        "remove_domain_rule" => remove_domain_rule(s, &args).await,
        "keep_blocked" => keep_blocked(s, &args).await,
        "set_device_profile" => set_device_profile(s, &args).await,
        "route_through_tunnel" => route_through_tunnel(s, &args).await,
        "remove_tunnel_route" => remove_tunnel_route(s, &args).await,
        "pause_filtering" => pause_filtering(s, &args).await,
        "resume_filtering" => resume_filtering(s, &args).await,
        "set_service_blocked" => set_service_blocked(s, &args).await,
        "refresh_lists" => refresh_lists(s).await,
        _ => return Outcome::Unknown,
    };
    result.into()
}

// ── Argument helpers ──────────────────────────────────────────────────────────

fn str_arg<'a>(args: &'a Value, key: &str) -> Option<&'a str> {
    args.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

fn required<'a>(args: &'a Value, key: &str) -> Result<&'a str, String> {
    str_arg(args, key).ok_or_else(|| format!("`{key}` is required"))
}

fn int_arg(args: &Value, key: &str, default: u64, max: u64) -> u64 {
    args.get(key)
        .and_then(Value::as_u64)
        .unwrap_or(default)
        .clamp(1, max)
}

fn strings_arg(args: &Value, key: &str) -> Vec<String> {
    args.get(key)
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

// ── Read tools ────────────────────────────────────────────────────────────────

async fn get_status(s: AppState) -> Result<Value, String> {
    let summary = crate::stats::get_summary(State(s.clone()))
        .await
        .map_err(api_err)?
        .0;
    let Json(pause) = crate::pause::get_pause(State(s.clone())).await;
    let Json(proxy) = crate::proxy::get_proxy(State(s.clone())).await;
    let bl = &s.inner.blocklist;
    let safe = bl.safe_search();
    let profiles: Vec<Value> = bl
        .profile_activity()
        .into_iter()
        .map(|(id, on)| json!({ "id": id, "on_now": on }))
        .collect();
    Ok(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "filtering": {
            "enabled": bl.blocking_enabled(),
            "pause": pause,
        },
        "queries": {
            "total": summary.total_queries,
            "blocked": summary.blocked_queries,
            "cached": summary.cached_queries,
            "upstream": summary.upstream_queries,
            "block_percentage": summary.block_percentage,
        },
        "blocklist_domains": summary.total_domains_blocked,
        "profiles": profiles,
        "services_blocked_network_wide": bl.blocked_services(),
        "safe_search": { "search": safe.search, "youtube": safe.youtube },
        "tunnels": {
            "enabled": proxy["proxy"]["enabled"],
            "egress_health": proxy["egress_health"],
        },
    }))
}

async fn search_queries(s: AppState, args: &Value) -> Result<Value, String> {
    let limit = int_arg(args, "limit", 30, 200) as usize;
    let mut params = crate::queries::ListQueriesParams {
        domain: str_arg(args, "domain").map(str::to_string),
        status: str_arg(args, "status").map(str::to_string),
        limit: Some(limit),
        ..Default::default()
    };
    if let Some(client) = str_arg(args, "client") {
        // A MAC is a device token; anything else is taken as an address.
        if client.contains(':') && client.len() == 17 && !client.contains("::") {
            params.device = Some(client.to_ascii_lowercase());
        } else {
            params.client_ip = Some(client.to_string());
        }
    }
    if let Some(minutes) = args.get("minutes").and_then(Value::as_i64) {
        params.from_ts = Some(now() - minutes.clamp(1, 10_080) * 60);
    }
    let Json(v) = crate::queries::list_queries(State(s), Query(params))
        .await
        .map_err(api_err)?;
    // Keep what helps reading the log; drop ids and cursors.
    let rows: Vec<Value> = v
        .as_array()
        .map(|rows| {
            rows.iter()
                .map(|r| {
                    json!({
                        "time": r["timestamp"],
                        "domain": r["domain"],
                        "type": r["query_type"],
                        "client": r["client_ip"],
                        "client_name": r["client_name"],
                        "status": r["status"],
                        "upstream": r["upstream"],
                        "rcode": r["rcode"],
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(json!({ "count": rows.len(), "queries": rows }))
}

async fn check_domain(s: AppState, args: &Value) -> Result<Value, String> {
    let domain = ferrite_blocklist::normalise_domain(required(args, "domain")?);
    let params = crate::blocklist::CheckParams {
        client: str_arg(args, "client").map(str::to_string),
    };
    let Json(v) = crate::blocklist::check_domain(State(s), Path(domain), Query(params))
        .await
        .map_err(api_err)?;
    Ok(v)
}

async fn top_domains(s: AppState, args: &Value) -> Result<Value, String> {
    let params = crate::stats::TopStatsParams {
        limit: Some(int_arg(args, "limit", 15, 50) as usize),
        hours: Some(int_arg(args, "hours", 24, 168)),
        all_time: Some(false),
        by: None,
    };
    let blocked = str_arg(args, "kind") == Some("blocked");
    let Json(v) = if blocked {
        crate::stats::get_top_blocked(State(s), Query(params)).await
    } else {
        crate::stats::get_top_domains(State(s), Query(params)).await
    }
    .map_err(api_err)?;
    Ok(v)
}

async fn list_clients(s: AppState, args: &Value) -> Result<Value, String> {
    let params = crate::clients::ListClientsParams {
        limit: Some(int_arg(args, "limit", 50, 200) as usize),
        hours: Some(int_arg(args, "hours", 24, 168)),
        all_time: Some(false),
    };
    let Json(mut v) = crate::clients::list_clients(State(s.clone()), Query(params))
        .await
        .map_err(api_err)?;
    // Which profile each device is under right now.
    if let Some(clients) = v["clients"].as_array_mut() {
        for c in clients {
            let ip = c["ips"][0].as_str().unwrap_or_default().to_string();
            let mac = c["macs"][0].as_str().map(str::to_string);
            let profile = s.inner.blocklist.profile_for(&ip, mac.as_deref());
            c["profile"] = json!(profile.map(|p| p.id().to_string()));
        }
    }
    Ok(v)
}

async fn device_report(s: AppState, args: &Value) -> Result<Value, String> {
    let d = find_device(&s, required(args, "client")?).await?;
    let hours = int_arg(args, "hours", 24, 168);
    let bl = &s.inner.blocklist;
    let ip = d.ip.clone().unwrap_or_default();
    let profile = bl
        .profile_for(&ip, d.mac.as_deref())
        .map(|p| p.id().to_string());
    let filtering_off =
        !bl.blocking_enabled() || bl.client_filtering_off_normalized(&ip, d.mac.as_deref());
    // Statistics may be off, or the device too new to have any: say so
    // rather than fail the whole report.
    let stats = match crate::clients::client_ip_stats(
        State(s.clone()),
        Path(d.token.clone()),
        Query(crate::clients::DeviceStatsParams { hours: Some(hours) }),
    )
    .await
    {
        Ok(Json(v)) => v,
        Err(e) => json!({ "unavailable": api_err(e) }),
    };
    let encrypted_dns_names: Vec<String> = {
        let cfg = s.live_config.read();
        cfg.secure_dns
            .owners
            .iter()
            .filter(|(_, owner)| {
                [d.mac.as_deref(), d.ip.as_deref()]
                    .into_iter()
                    .flatten()
                    .any(|k| k.eq_ignore_ascii_case(owner))
            })
            .map(|(id, _)| id.clone())
            .collect()
    };
    let breakage: Vec<Value> = s
        .inner
        .live_stats
        .breakage
        .suspects()
        .into_iter()
        .filter(|x| x.device == d.token)
        .map(|x| json!({ "domain": x.domain, "site": x.site, "tries": x.tries, "last": x.last }))
        .collect();
    Ok(json!({
        "device": d.json(),
        "profile": profile,
        "filtering_off": filtering_off,
        "encrypted_dns_names": encrypted_dns_names,
        "likely_breakage": breakage,
        "stats": stats,
    }))
}

fn list_services(s: &AppState) -> Value {
    let services: Vec<Value> = ferrite_core::services::catalog()
        .iter()
        .map(|svc| {
            json!({
                "id": svc.id,
                "name": svc.name,
                "category": svc.category,
                "can_route_through_tunnel": svc.routable,
                "domains": svc.domains.len(),
            })
        })
        .collect();
    json!({
        "services": services,
        "blocked_network_wide": s.inner.blocklist.blocked_services(),
    })
}

async fn tunnel_status(s: AppState) -> Value {
    let Json(proxy) = crate::proxy::get_proxy(State(s.clone())).await;
    let Json(stats) = crate::proxy::get_proxy_stats(State(s)).await;
    let egresses: Vec<Value> = proxy["proxy"]["egresses"]
        .as_array()
        .map(|eg| {
            eg.iter()
                .map(|e| {
                    let id = e["id"].as_str().unwrap_or_default();
                    json!({
                        "id": id,
                        "name": e["name"],
                        "kind": e["kind"],
                        "enabled": e["enabled"],
                        "health": proxy["egress_health"][id],
                        "traffic": stats["egresses"][id],
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    let rules: Vec<Value> = proxy["proxy"]["rules"]
        .as_array()
        .map(|r| {
            r.iter()
                .map(|r| {
                    json!({
                        "pattern": r["pattern"],
                        "service": r["service"],
                        "egress": r["egress"],
                        "clients": r["clients"],
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    json!({
        "enabled": proxy["proxy"]["enabled"],
        "egresses": egresses,
        "rules": rules,
        "rule_hits": stats["rules"],
    })
}

async fn recent_logs(args: &Value) -> Result<Value, String> {
    let query = serde_json::from_value(json!({
        "level": str_arg(args, "level").unwrap_or("warn"),
        "limit": int_arg(args, "limit", 50, 200),
    }))
    .map_err(|e| e.to_string())?;
    Ok(crate::logs::get_logs(Query(query)).await.0)
}

// ── Change tools ──────────────────────────────────────────────────────────────

async fn domain_rule(s: AppState, args: &Value, block: bool) -> Result<Value, String> {
    let payload = crate::blocklist::DomainPayload {
        domain: required(args, "domain")?.to_string(),
    };
    let (_, Json(r)) = if block {
        crate::blocklist::add_blacklist(State(s), Json(payload)).await
    } else {
        crate::blocklist::add_whitelist(State(s), Json(payload)).await
    }
    .map_err(api_err)?;
    serde_json::to_value(r).map_err(|e| e.to_string())
}

async fn remove_domain_rule(s: AppState, args: &Value) -> Result<Value, String> {
    let domain = required(args, "domain")?.to_string();
    let Json(v) = match required(args, "list")? {
        "block" => crate::blocklist::del_blacklist(State(s), Path(domain)).await,
        "allow" => crate::blocklist::del_whitelist(State(s), Path(domain)).await,
        other => return Err(format!("`list` is block or allow, not {other}")),
    }
    .map_err(api_err)?;
    Ok(v)
}

async fn pause_filtering(s: AppState, args: &Value) -> Result<Value, String> {
    let minutes = args
        .get("minutes")
        .and_then(Value::as_u64)
        .ok_or("`minutes` is required")?;
    let payload = crate::pause::PausePayload {
        minutes: minutes.clamp(1, 1440) as u32,
        clients: strings_arg(args, "clients"),
    };
    let Json(v) = crate::pause::pause(State(s), Json(payload))
        .await
        .map_err(api_err)?;
    Ok(v)
}

async fn resume_filtering(s: AppState, args: &Value) -> Result<Value, String> {
    let payload = crate::pause::ResumePayload {
        clients: strings_arg(args, "clients"),
    };
    Ok(crate::pause::resume(State(s), Json(payload)).await.0)
}

async fn set_service_blocked(s: AppState, args: &Value) -> Result<Value, String> {
    let service = required(args, "service")?.to_ascii_lowercase();
    let blocked = args
        .get("blocked")
        .and_then(Value::as_bool)
        .ok_or("`blocked` is required")?;
    let toggle = |list: &mut Vec<String>| {
        list.retain(|id| *id != service);
        if blocked {
            list.push(service.clone());
        }
    };
    match str_arg(args, "profile") {
        None => {
            let mut ids = s.inner.blocklist.blocked_services();
            toggle(&mut ids);
            let Json(v) = crate::services::put_blocked(
                State(s),
                Json(crate::services::ServicesPayload { services: ids }),
            )
            .await
            .map_err(api_err)?;
            Ok(v)
        }
        Some(profile_id) => {
            let mut profiles: Vec<BlocklistProfileConfig> = s.inner.blocklist.get_profiles();
            let Some(p) = profiles.iter_mut().find(|p| p.id == profile_id) else {
                return Err(format!("no profile `{profile_id}` (see list_profiles)"));
            };
            toggle(&mut p.services);
            let Json(v) = crate::profiles::put_profiles(State(s), Json(profiles))
                .await
                .map_err(api_err)?;
            Ok(v)
        }
    }
}

async fn keep_blocked(s: AppState, args: &Value) -> Result<Value, String> {
    let payload = crate::breakage::IgnorePayload {
        domain: required(args, "domain")?.to_string(),
    };
    let Json(v) = crate::breakage::ignore(State(s), Json(payload))
        .await
        .map_err(api_err)?;
    Ok(v)
}

async fn set_device_profile(s: AppState, args: &Value) -> Result<Value, String> {
    let d = find_device(&s, required(args, "client")?).await?;
    let target = str_arg(args, "profile").filter(|p| !p.eq_ignore_ascii_case("none"));
    let mut profiles: Vec<BlocklistProfileConfig> = s.inner.blocklist.get_profiles();
    if let Some(id) = target
        && !profiles.iter().any(|p| p.id == id)
    {
        return Err(format!("no profile `{id}` (see list_profiles)"));
    }
    // Every way the profiles may know the device, so it ends up in one.
    let keys: Vec<&str> = [d.mac.as_deref(), d.ip.as_deref(), Some(d.token.as_str())]
        .into_iter()
        .flatten()
        .collect();
    for p in &mut profiles {
        p.clients
            .retain(|c| !keys.iter().any(|k| k.eq_ignore_ascii_case(c.trim())));
    }
    if let Some(id) = target
        && let Some(p) = profiles.iter_mut().find(|p| p.id == id)
    {
        p.clients
            .push(d.mac.clone().unwrap_or_else(|| d.token.clone()));
    }
    let _ = crate::profiles::put_profiles(State(s), Json(profiles))
        .await
        .map_err(api_err)?;
    Ok(json!({ "status": "ok", "device": d.json(), "profile": target }))
}

/// The domain or the service a tunnel rule is for: exactly one of them.
fn rule_target(args: &Value) -> Result<(String, Option<String>), String> {
    match (str_arg(args, "domain"), str_arg(args, "service")) {
        (Some(d), None) => Ok((d.trim_end_matches('.').to_ascii_lowercase(), None)),
        (None, Some(svc)) => Ok((String::new(), Some(svc.to_ascii_lowercase()))),
        _ => Err("give either `domain` or `service`".into()),
    }
}

fn same_target(r: &RuleConfig, pattern: &str, service: &Option<String>) -> bool {
    match service {
        Some(id) => r.service.as_deref() == Some(id.as_str()),
        None => r.service.is_none() && r.pattern.eq_ignore_ascii_case(pattern),
    }
}

async fn route_through_tunnel(s: AppState, args: &Value) -> Result<Value, String> {
    let egress = required(args, "egress")?.to_ascii_lowercase();
    let (pattern, service) = rule_target(args)?;
    let clients = strings_arg(args, "clients");
    let fail_closed = args
        .get("fail_closed")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    // From the live config, whose secrets are whole (GET hides them).
    let mut cfg = s.live_config.read().proxy.clone();
    if !cfg
        .egresses
        .iter()
        .any(|e| e.id.eq_ignore_ascii_case(&egress))
    {
        return Err(format!("no tunnel `{egress}` (see tunnel_status)"));
    }
    match cfg
        .rules
        .iter_mut()
        .find(|r| same_target(r, &pattern, &service))
    {
        Some(r) => {
            r.egress = egress.clone();
            r.clients = clients;
            r.fail_closed = fail_closed;
        }
        None => cfg.rules.push(RuleConfig {
            pattern,
            service,
            egress,
            fail_closed,
            clients,
        }),
    }
    let _ = crate::proxy::put_proxy(State(s.clone()), Json(cfg))
        .await
        .map_err(api_err)?;
    let enabled = s.live_config.read().proxy.enabled;
    Ok(json!({
        "status": "ok",
        "tunnels_enabled": enabled,
        "note": (!enabled).then_some(
            "Tunnels are switched off, so the rule is saved but routes nothing until they're on."
        ),
    }))
}

async fn remove_tunnel_route(s: AppState, args: &Value) -> Result<Value, String> {
    let (pattern, service) = rule_target(args)?;
    let mut cfg = s.live_config.read().proxy.clone();
    let before = cfg.rules.len();
    cfg.rules.retain(|r| !same_target(r, &pattern, &service));
    let removed = before - cfg.rules.len();
    if removed == 0 {
        return Err("no tunnel rule for that (see tunnel_status)".into());
    }
    let _ = crate::proxy::put_proxy(State(s), Json(cfg))
        .await
        .map_err(api_err)?;
    Ok(json!({ "status": "ok", "removed": removed }))
}

async fn refresh_lists(s: AppState) -> Result<Value, String> {
    s.inner
        .blocklist
        .refresh(true)
        .await
        .map_err(|e| e.to_string())?;
    Ok(json!({
        "status": "ok",
        "blocklist_domains": s.inner.blocklist.blocked_count(),
    }))
}
