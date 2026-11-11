//! MCP prompts: the two things people come to the box for, as ready-made
//! requests a client can offer (Claude shows them as commands). Each only
//! words the request; the tools do the work.

use serde_json::{Value, json};

pub(super) fn list() -> Value {
    json!({
        "prompts": [
            {
                "name": "why_not_working",
                "title": "Why doesn't it work?",
                "description": "A site or app doesn't work, on one device or everywhere: find out whether the DNS filter is the cause and what would fix it.",
                "arguments": [
                    { "name": "site", "description": "The site or app: instagram, youtube, bbc.co.uk…", "required": true },
                    { "name": "device", "description": "The device it fails on: its name, IP or MAC (optional).", "required": false }
                ]
            },
            {
                "name": "network_report",
                "title": "Home network report",
                "description": "A short report on the home network: what was blocked, the devices, anything that looks broken or unusual.",
                "arguments": [
                    { "name": "hours", "description": "How far back, in hours (24 by default, at most 168).", "required": false }
                ]
            }
        ]
    })
}

/// The prompt's messages, or what's wrong with the request.
pub(super) fn get(name: &str, args: &Value) -> Result<Value, String> {
    let arg = |key: &str| {
        args.get(key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|v| !v.is_empty())
    };
    let text = match name {
        "why_not_working" => {
            let site = arg("site").ok_or("`site` is required")?;
            let on = arg("device")
                .map(|d| format!(" on the device {d}"))
                .unwrap_or_default();
            format!(
                "{site} doesn't work{on} on my home network. Use ferrite's diagnose tool \
                 (site: {site}{client}) to find out whether the DNS filter is the cause. \
                 Tell me in plain words what you found and what you'd change, and why. \
                 Don't change anything until I say so; if I agree, make the change with \
                 the tool diagnose suggested and check again with diagnose.",
                client = arg("device")
                    .map(|d| format!(", client: {d}"))
                    .unwrap_or_default(),
            )
        }
        "network_report" => {
            let hours = arg("hours")
                .and_then(|h| h.parse::<u32>().ok())
                .unwrap_or(24)
                .clamp(1, 168);
            format!(
                "Give me a short report on my home network for the last {hours} hours, \
                 from ferrite: get_status, top_domains (blocked) for {hours} hours, \
                 list_clients for {hours} hours, likely_breakage, tunnel_status, and \
                 recent_logs at warn. Start with anything that needs me: devices seen for \
                 the first time, a device blocked far more than the others, names that seem \
                 broken by a block, tunnels down, errors. Then the numbers in a few lines. \
                 Keep it short and don't change anything."
            )
        }
        other => return Err(format!("unknown prompt: {other}")),
    };
    let description = list()["prompts"]
        .as_array()
        .and_then(|p| p.iter().find(|p| p["name"] == name))
        .map(|p| p["description"].clone())
        .unwrap_or(Value::Null);
    Ok(json!({
        "description": description,
        "messages": [{ "role": "user", "content": { "type": "text", "text": text } }]
    }))
}
