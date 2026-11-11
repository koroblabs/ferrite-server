//! "Why doesn't this work?" in one call: what a device actually asked of a
//! site lately and what each name got, why the blocked ones are blocked (a
//! list, a rule, a service, its profile), whether the device is filtered at
//! all right now, what the upstream said, and which tunnel carries the names
//! — boiled down to findings and the tool calls that would fix them. The
//! assistant explains; the owner decides.

use std::collections::BTreeMap;

use axum::{
    Json,
    extract::{Query, State},
};
use serde_json::{Value, json};

use ferrite_app::AppState;
use ferrite_core::services::Service;

/// Names looked at in detail, at most.
const NAMES: usize = 25;
/// Query log rows read for the window.
const ROWS: usize = 1000;

/// A device as the assistant named it, and how the box knows it.
pub(super) struct Device {
    pub name: Option<String>,
    pub ip: Option<String>,
    pub mac: Option<String>,
    /// What the query log files its queries under: the MAC when known, else
    /// the address (or `id:<name>` for encrypted DNS without an owner).
    pub token: String,
}

impl Device {
    /// What `client_view` and profiles take: an address, else the MAC.
    fn client(&self) -> &str {
        self.ip
            .as_deref()
            .or(self.mac.as_deref())
            .unwrap_or(&self.token)
    }

    pub fn json(&self) -> Value {
        json!({ "name": self.name, "ip": self.ip, "mac": self.mac, "key": self.token })
    }
}

/// An address, a MAC, `id:<name>`, or a device's name as Clients shows it.
pub(super) async fn find_device(s: &AppState, asked: &str) -> Result<Device, String> {
    use ferrite_core::net::{normalize_client_key, parse_ip};
    let reg = &s.inner.client_registry;
    let asked = asked.trim();
    if let Some(key) = normalize_client_key(asked) {
        if key.starts_with("id:") {
            return Ok(Device {
                name: None,
                ip: None,
                mac: None,
                token: key,
            });
        }
        if let Some(ip) = parse_ip(&key) {
            let mac = reg.get_mac(ip);
            let name = reg.describe_device(mac.as_deref().unwrap_or(&key)).name;
            return Ok(Device {
                name,
                token: mac.clone().unwrap_or_else(|| key.clone()),
                ip: Some(key),
                mac,
            });
        }
        let info = reg.describe_device(&key);
        return Ok(Device {
            name: info.name,
            ip: info.ips.first().cloned(),
            mac: Some(key.clone()),
            token: key,
        });
    }
    let params = crate::clients::ListClientsParams {
        limit: Some(500),
        hours: Some(168),
        all_time: Some(true),
    };
    let Json(v) = crate::clients::list_clients(State(s.clone()), Query(params))
        .await
        .map_err(|e| e.0.to_string())?;
    let rows = v["clients"].as_array().cloned().unwrap_or_default();
    let found = rows
        .iter()
        .find(|c| {
            c["name"]
                .as_str()
                .is_some_and(|n| n.eq_ignore_ascii_case(asked))
        })
        .or_else(|| {
            // One device whose name holds what was asked: "pixel" for pixel-8-pro.
            let lower = asked.to_lowercase();
            let mut hits = rows.iter().filter(|c| {
                c["name"]
                    .as_str()
                    .is_some_and(|n| n.to_lowercase().contains(&lower))
            });
            match (hits.next(), hits.next()) {
                (Some(one), None) => Some(one),
                _ => None,
            }
        })
        .ok_or_else(|| {
            format!("no device called `{asked}`; pass its IP or MAC, or see list_clients")
        })?;
    let ip = found["ips"][0].as_str().map(str::to_string);
    let mac = found["macs"][0].as_str().map(str::to_string);
    let token = mac
        .clone()
        .or_else(|| ip.clone())
        .ok_or_else(|| format!("`{asked}` has no address on record"))?;
    Ok(Device {
        name: found["name"].as_str().map(str::to_string),
        ip,
        mac,
        token,
    })
}

/// What was asked about: a catalog service, or the site of a domain.
struct Target {
    label: String,
    service: Option<&'static Service>,
    /// The site key names are matched by (see `ferrite_stats::breakage`).
    key: String,
    /// Names to judge when the log has none: the service's domains, or the
    /// domain asked about.
    seeds: Vec<String>,
}

impl Target {
    fn parse(asked: &str) -> Result<Self, String> {
        let raw = asked.trim().to_ascii_lowercase();
        if let Some(svc) = ferrite_core::services::catalog()
            .iter()
            .find(|s| s.id == raw || s.name.eq_ignore_ascii_case(asked.trim()))
        {
            return Ok(Self {
                label: svc.name.clone(),
                service: Some(svc),
                key: format!("service:{}", svc.id),
                seeds: svc.domains.iter().take(6).cloned().collect(),
            });
        }
        // A domain or a link: the host of it.
        let host = raw
            .split_once("://")
            .map_or(raw.as_str(), |(_, rest)| rest)
            .split(['/', '?', '#'])
            .next()
            .unwrap_or_default();
        let host = host.rsplit_once('@').map_or(host, |(_, h)| h);
        let host = match host.rsplit_once(':') {
            Some((h, port)) if port.chars().all(|c| c.is_ascii_digit()) => h,
            _ => host,
        };
        let domain = ferrite_blocklist::normalise_domain(host);
        let site = ferrite_stats::breakage::site_of(&domain).ok_or_else(|| {
            format!("`{asked}` is neither a catalog service (see list_services) nor a domain")
        })?;
        Ok(Self {
            label: site.label,
            service: ferrite_core::services::owner_of(&domain),
            key: site.key,
            seeds: vec![domain],
        })
    }

    fn covers(&self, name: &str) -> bool {
        ferrite_stats::breakage::site_of(name).is_some_and(|s| s.key == self.key)
    }
}

/// What one name got in the window.
#[derive(Default)]
struct NameUse {
    asked: u64,
    blocked: u64,
    answered: u64,
    routed: u64,
    nxdomain: u64,
    servfail: u64,
    devices: Vec<String>,
}

pub(super) async fn diagnose(s: AppState, args: &Value) -> Result<Value, String> {
    let asked = args
        .get("site")
        .and_then(Value::as_str)
        .filter(|v| !v.trim().is_empty())
        .ok_or("`site` is required: a service (instagram) or a domain")?;
    let target = Target::parse(asked)?;
    let device = match args.get("client").and_then(Value::as_str).map(str::trim) {
        Some(c) if !c.is_empty() => Some(find_device(&s, c).await?),
        _ => None,
    };
    let minutes = args
        .get("minutes")
        .and_then(Value::as_i64)
        .unwrap_or(30)
        .clamp(1, 1440);

    // ── What was asked, and what it got ──
    let log_on = s.inner.record_switches.scope().queries;
    let mut names: BTreeMap<String, NameUse> = BTreeMap::new();
    if log_on {
        let params = crate::queries::ListQueriesParams {
            from_ts: Some(chrono::Utc::now().timestamp() - minutes * 60),
            device: device.as_ref().map(|d| d.token.clone()),
            limit: Some(ROWS),
            ..Default::default()
        };
        let Json(rows) = crate::queries::list_queries(State(s.clone()), Query(params))
            .await
            .map_err(|e| e.0.to_string())?;
        for r in rows.as_array().into_iter().flatten() {
            let Some(domain) = r["domain"].as_str() else {
                continue;
            };
            if !target.covers(domain) {
                continue;
            }
            let u = names.entry(domain.to_string()).or_default();
            u.asked += 1;
            match r["status"].as_str().unwrap_or_default() {
                "blocked" => u.blocked += 1,
                "routed" => {
                    u.routed += 1;
                    u.answered += 1;
                }
                _ => u.answered += 1,
            }
            match r["rcode"].as_u64() {
                Some(3) if r["status"] != "blocked" => u.nxdomain += 1,
                Some(2) => u.servfail += 1,
                _ => {}
            }
            let who = r["client_name"]
                .as_str()
                .or(r["device"].as_str())
                .or(r["client_ip"].as_str())
                .unwrap_or_default()
                .to_string();
            if !who.is_empty() && !u.devices.contains(&who) && u.devices.len() < 5 {
                u.devices.push(who);
            }
        }
    }
    let seen = !names.is_empty();
    // Nothing in the log: judge the site's own names as they'd go now.
    if !seen {
        for d in &target.seeds {
            names.entry(d.clone()).or_default();
        }
    }
    // Blocked names first, then the busiest.
    let mut order: Vec<String> = names.keys().cloned().collect();
    order.sort_by_key(|d| {
        let u = &names[d];
        (u.blocked == 0, std::cmp::Reverse(u.asked))
    });
    order.truncate(NAMES);

    // ── Why: the network-wide explanation, and the device's own decision ──
    let blocklist = std::sync::Arc::clone(&s.inner.blocklist);
    let to_explain = order.clone();
    let explained = tokio::task::spawn_blocking(move || {
        to_explain
            .into_iter()
            .map(|d| blocklist.explain(&d))
            .collect::<Vec<_>>()
    })
    .await
    .map_err(|e| format!("explain task failed: {e}"))?;

    let bl = &s.inner.blocklist;
    let proxy = &s.inner.proxy;
    let suspects = s.inner.live_stats.breakage.suspects();
    let mut findings: Vec<String> = Vec::new();
    let mut suggestions: Vec<Value> = Vec::new();
    let mut suggest = |tool: &str, arguments: Value, why: String| {
        if !suggestions
            .iter()
            .any(|x| x["tool"] == tool && x["arguments"] == arguments)
        {
            suggestions.push(json!({ "tool": tool, "arguments": arguments, "why": why }));
        }
    };
    let mut details = Vec::new();
    let mut blocked_now = 0;
    let mut profile_id: Option<String> = None;
    let mut filtering_off = false;

    for (domain, why) in order.iter().zip(&explained) {
        let u = &names[domain];
        let view = device
            .as_ref()
            .and_then(|d| crate::blocklist::client_view(&s, domain, d.client()).ok());
        if let Some(v) = &view {
            filtering_off |= v["filtering_off"] == true;
            if profile_id.is_none() {
                profile_id = v["profile"].as_str().map(str::to_string);
            }
        }
        let blocked_for_device = view
            .as_ref()
            .map(|v| v["blocked"] == true)
            .unwrap_or(why.blocked);
        if blocked_for_device {
            blocked_now += 1;
        }
        let sources: Vec<Value> = why
            .sources
            .iter()
            .map(|src| json!({ "kind": src.kind, "name": src.name, "matched": src.matched }))
            .collect();
        let route = proxy.route_egress(domain).map(|(egress, _)| {
            let healthy = proxy.is_egress_healthy(&egress);
            json!({ "egress": egress, "healthy": healthy })
        });

        // What each blocked name comes to.
        if blocked_for_device {
            let breakage = suspects.iter().any(|x| x.domain == *domain);
            let lists: Vec<&str> = why
                .sources
                .iter()
                .filter(|x| x.kind == "list")
                .map(|x| x.name.as_str())
                .collect();
            let manual = why
                .sources
                .iter()
                .find(|x| matches!(x.kind.as_str(), "blacklist" | "wildcard" | "regex"));
            let service = why.sources.iter().find(|x| x.kind == "service");
            if let Some(svc) = service {
                findings.push(format!(
                    "{domain} is blocked because the {} service is blocked for every device.",
                    svc.name
                ));
                if let Some(t) = target.service {
                    suggest(
                        "set_service_blocked",
                        json!({ "service": t.id, "blocked": false }),
                        format!("unblock {} for every device", t.name),
                    );
                }
            } else if let Some(rule) = manual {
                // An exact entry is reported by the key it matched at; a
                // wildcard or regex by its own pattern.
                let entry = if rule.kind == "blacklist" {
                    &rule.matched
                } else {
                    &rule.name
                };
                findings.push(format!("{domain} is blocked by your own rule `{entry}`."));
                suggest(
                    "remove_domain_rule",
                    json!({ "domain": entry, "list": "block" }),
                    format!("remove the rule that blocks {domain}"),
                );
            } else if !lists.is_empty() {
                findings.push(format!(
                    "{domain} is blocked by the list{} {}{}.",
                    if lists.len() > 1 { "s" } else { "" },
                    lists.join(", "),
                    if breakage {
                        " — the device keeps asking for it, which is how an app looks when a block broke it"
                    } else {
                        ""
                    }
                ));
                suggest(
                    "allow_domain",
                    json!({ "domain": domain }),
                    format!("allow {domain} for every device"),
                );
            } else if let Some(p) = view.as_ref().and_then(|v| v["profile"].as_str()) {
                let blocks_service = target.service.is_some_and(|t| {
                    bl.get_profiles()
                        .iter()
                        .any(|pr| pr.id == p && pr.services.contains(&t.id))
                });
                if blocks_service && let Some(t) = target.service {
                    findings.push(format!(
                        "{domain} is blocked on this device because its profile `{p}` blocks {}.",
                        t.name
                    ));
                    suggest(
                        "set_service_blocked",
                        json!({ "service": t.id, "blocked": false, "profile": p }),
                        format!("let profile {p} use {}", t.name),
                    );
                } else {
                    findings.push(format!(
                        "{domain} is blocked on this device by its profile `{p}` (its own lists or entries)."
                    ));
                }
            }
        }
        if u.servfail > 0 {
            findings.push(format!(
                "The upstream resolver failed (SERVFAIL) for {domain} {} time(s): an upstream problem, not a block.",
                u.servfail
            ));
        }
        if u.nxdomain > 0 && u.answered == u.nxdomain && !blocked_for_device {
            findings.push(format!(
                "{domain} doesn't exist upstream (NXDOMAIN): nothing ferrite blocks."
            ));
        }
        if let Some(r) = &route
            && r["healthy"] == false
        {
            findings.push(format!(
                "{domain} is routed through the tunnel `{}`, which is down right now.",
                r["egress"].as_str().unwrap_or_default()
            ));
            suggest(
                "tunnel_status",
                json!({}),
                "see which tunnel is down and why".to_string(),
            );
        }
        details.push(json!({
            "domain": domain,
            "asked": u.asked,
            "blocked": u.blocked,
            "answered": u.answered,
            "routed": u.routed,
            "nxdomain": u.nxdomain,
            "servfail": u.servfail,
            "devices": u.devices,
            "blocked_now": blocked_for_device,
            "blocked_by": sources,
            "whitelisted": why.whitelisted,
            "route": route,
        }));
    }

    // ── The device and the box ──
    if !bl.blocking_enabled() {
        findings.insert(
            0,
            "Filtering is paused or switched off for the whole network, so a block isn't the cause."
                .into(),
        );
    } else if filtering_off {
        findings.insert(
            0,
            "Filtering is off for this device right now (paused or set to bypass), so a block isn't the cause."
                .into(),
        );
    }
    if !log_on {
        findings.push(
            "The query log is switched off, so what the device actually asked can't be seen; the names were judged as they would go now."
                .into(),
        );
    } else if !seen {
        findings.push(match &device {
            Some(_) => format!(
                "This device asked for no {} name in the last {minutes} minutes. Either the app wasn't opened, or the device doesn't ask ferrite (its own Private DNS or DNS over HTTPS, a VPN, mobile data).",
                target.label
            ),
            None => format!(
                "No device asked for a {} name in the last {minutes} minutes.",
                target.label
            ),
        });
    }
    let verdict = if !bl.blocking_enabled() || filtering_off {
        "not_filtered"
    } else if blocked_now > 0 {
        "blocked"
    } else if details.iter().any(|d| d["route"]["healthy"] == false) {
        "tunnel_down"
    } else if details.iter().any(|d| d["servfail"].as_u64() > Some(0)) {
        "upstream_errors"
    } else if log_on && !seen {
        "no_queries"
    } else {
        "fine"
    };
    if verdict == "fine" {
        findings.push(format!(
            "DNS looks fine for {}: nothing it asked is blocked. If it still doesn't work, the cause is elsewhere (the connection, the app's servers, a VPN).",
            target.label
        ));
    }
    let breakage: Vec<Value> = suspects
        .iter()
        .filter(|x| target.covers(&x.domain))
        .filter(|x| device.as_ref().is_none_or(|d| x.device == d.token))
        .map(
            |x| json!({ "domain": x.domain, "device": x.device, "tries": x.tries, "last": x.last }),
        )
        .collect();

    Ok(json!({
        "site": target.label,
        "service": target.service.map(|t| t.id.clone()),
        "device": device.as_ref().map(Device::json),
        "profile": profile_id,
        "window_minutes": minutes,
        "verdict": verdict,
        "findings": findings,
        "suggestions": suggestions,
        "names": details,
        "breakage": breakage,
    }))
}
