use super::*;
use axum::http::HeaderValue;
use ferrite_app::test_support;

async fn send(state: &AppState, headers: HeaderMap, body: Value) -> (StatusCode, Value) {
    let resp = post(State(state.clone()), headers, Bytes::from(body.to_string())).await;
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    let json = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    (status, json)
}

fn call(id: u64, name: &str, args: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "method": "tools/call", "params": { "name": name, "arguments": args } })
}

async fn enabled_state(name: &str, allow_changes: bool) -> (AppState, std::path::PathBuf) {
    let (state, db) = test_support::app_state(name).await;
    {
        let mut cfg = state.live_config.write();
        cfg.mcp.enabled = true;
        cfg.mcp.allow_changes = allow_changes;
    }
    (state, db)
}

#[tokio::test]
async fn off_by_default_and_hidden_behind_a_404() {
    let (state, db) = test_support::app_state("mcp-off").await;
    let (status, _) = send(
        &state,
        HeaderMap::new(),
        json!({"jsonrpc":"2.0","id":1,"method":"ping"}),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    drop(state);
    test_support::cleanup_sqlite(&db);
}

#[tokio::test]
async fn initialize_negotiates_and_notifications_are_accepted() {
    let (state, db) = enabled_state("mcp-init", false).await;
    let (status, v) = send(
        &state,
        HeaderMap::new(),
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
            "protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["id"], 1);
    assert_eq!(v["result"]["protocolVersion"], "2025-06-18");
    assert_eq!(v["result"]["serverInfo"]["name"], "ferrite");
    assert!(v["result"]["capabilities"]["tools"].is_object());

    // An unknown version is answered with ours.
    let (_, v) = send(
        &state,
        HeaderMap::new(),
        json!({"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"1999-01-01"}}),
    )
    .await;
    assert_eq!(v["result"]["protocolVersion"], SUPPORTED_VERSIONS[0]);

    let (status, v) = send(
        &state,
        HeaderMap::new(),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert!(v.is_null());

    let (_, v) = send(
        &state,
        HeaderMap::new(),
        json!({"jsonrpc":"2.0","id":3,"method":"nope"}),
    )
    .await;
    assert_eq!(v["error"]["code"], METHOD_NOT_FOUND);
    drop(state);
    test_support::cleanup_sqlite(&db);
}

#[tokio::test]
async fn foreign_origins_and_unknown_versions_are_refused() {
    let (state, db) = enabled_state("mcp-origin", false).await;
    let ping = json!({"jsonrpc":"2.0","id":1,"method":"ping"});

    let mut h = HeaderMap::new();
    h.insert(header::HOST, HeaderValue::from_static("192.168.1.10"));
    h.insert(
        header::ORIGIN,
        HeaderValue::from_static("http://evil.example"),
    );
    assert_eq!(send(&state, h, ping.clone()).await.0, StatusCode::FORBIDDEN);

    // The panel's own origin is fine.
    let mut h = HeaderMap::new();
    h.insert(header::HOST, HeaderValue::from_static("192.168.1.10"));
    h.insert(
        header::ORIGIN,
        HeaderValue::from_static("http://192.168.1.10"),
    );
    assert_eq!(send(&state, h, ping.clone()).await.0, StatusCode::OK);

    let mut h = HeaderMap::new();
    h.insert(
        "mcp-protocol-version",
        HeaderValue::from_static("2020-01-01"),
    );
    assert_eq!(send(&state, h, ping).await.0, StatusCode::BAD_REQUEST);
    drop(state);
    test_support::cleanup_sqlite(&db);
}

#[tokio::test]
async fn read_tools_answer_and_change_tools_need_permission() {
    let (state, db) = enabled_state("mcp-tools", false).await;

    let (_, v) = send(
        &state,
        HeaderMap::new(),
        json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}),
    )
    .await;
    let names: Vec<&str> = v["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"check_domain") && names.contains(&"search_queries"));
    assert!(
        !names.contains(&"block_domain"),
        "changes are off: {names:?}"
    );

    let (_, v) = send(
        &state,
        HeaderMap::new(),
        call(2, "check_domain", json!({"domain": "Example.COM"})),
    )
    .await;
    assert_eq!(v["result"]["isError"], false);
    assert_eq!(v["result"]["structuredContent"]["domain"], "example.com");
    assert_eq!(v["result"]["structuredContent"]["blocked"], false);

    let (_, v) = send(&state, HeaderMap::new(), call(3, "get_status", json!({}))).await;
    assert_eq!(
        v["result"]["structuredContent"]["filtering"]["enabled"],
        true
    );

    // A change tool is refused while changes are off — as a tool error the
    // assistant can read, not a protocol failure.
    let (_, v) = send(
        &state,
        HeaderMap::new(),
        call(4, "block_domain", json!({"domain": "ads.test"})),
    )
    .await;
    assert_eq!(v["result"]["isError"], true);
    assert!(!state.inner.blocklist.should_block_for("ads.test", None));

    let (_, v) = send(&state, HeaderMap::new(), call(5, "no_such_tool", json!({}))).await;
    assert_eq!(v["error"]["code"], INVALID_PARAMS);
    drop(state);
    test_support::cleanup_sqlite(&db);
}

#[tokio::test]
async fn change_tools_act_like_the_panel_when_allowed() {
    let (state, db) = enabled_state("mcp-changes", true).await;

    let (_, v) = send(
        &state,
        HeaderMap::new(),
        call(1, "block_domain", json!({"domain": "ads.test"})),
    )
    .await;
    assert_eq!(v["result"]["isError"], false, "{v}");
    assert!(state.inner.blocklist.should_block_for("www.ads.test", None));
    assert!(
        state
            .live_config
            .read()
            .blocklist
            .domains
            .contains(&"ads.test".to_string())
    );

    let (_, v) = send(
        &state,
        HeaderMap::new(),
        call(
            2,
            "set_service_blocked",
            json!({"service": "tiktok", "blocked": true}),
        ),
    )
    .await;
    assert_eq!(v["result"]["isError"], false, "{v}");
    assert_eq!(state.inner.blocklist.blocked_services(), vec!["tiktok"]);

    // A device's own decision: the check names the client's view.
    let (_, v) = send(
        &state,
        HeaderMap::new(),
        call(
            3,
            "check_domain",
            json!({"domain": "www.tiktok.com", "client": "10.0.0.7"}),
        ),
    )
    .await;
    let r = &v["result"]["structuredContent"];
    assert_eq!(r["blocked"], true);
    assert_eq!(r["for_client"]["blocked"], true);
    assert_eq!(r["sources"][0]["kind"], "service");

    let (_, v) = send(
        &state,
        HeaderMap::new(),
        call(
            4,
            "set_service_blocked",
            json!({"service": "tiktok", "blocked": true, "profile": "ghost"}),
        ),
    )
    .await;
    assert_eq!(v["result"]["isError"], true);
    drop(state);
    test_support::cleanup_sqlite(&db);
}

fn structured(v: &Value) -> &Value {
    assert_eq!(v["result"]["isError"], false, "{v}");
    &v["result"]["structuredContent"]
}

fn entry(
    id: u64,
    secs_ago: i64,
    domain: &str,
    status: ferrite_core::types::QueryStatus,
    rcode: u8,
) -> ferrite_core::types::QueryEntry {
    ferrite_core::types::QueryEntry {
        id,
        timestamp: chrono::Utc::now() - chrono::Duration::seconds(secs_ago),
        domain: domain.into(),
        query_type: 1,
        client_ip: "192.168.1.20".into(),
        device: "192.168.1.20".into(),
        status,
        latency_ms: 1,
        upstream: None,
        rcode,
    }
}

#[tokio::test]
async fn the_listing_tells_reads_from_changes_and_what_each_change_does() {
    let (state, db) = enabled_state("mcp-annotations", true).await;
    let (_, v) = send(
        &state,
        HeaderMap::new(),
        json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}),
    )
    .await;
    let tools = v["result"]["tools"].as_array().unwrap();
    let hints = |name: &str| {
        tools
            .iter()
            .find(|t| t["name"] == name)
            .unwrap_or_else(|| panic!("{name} listed"))["annotations"]
            .clone()
    };
    for read in [
        "diagnose",
        "likely_breakage",
        "device_report",
        "encrypted_dns_status",
    ] {
        assert_eq!(hints(read)["readOnlyHint"], true, "{read}");
    }
    assert_eq!(hints("remove_domain_rule")["destructiveHint"], true);
    assert_eq!(hints("remove_tunnel_route")["destructiveHint"], true);
    assert_eq!(hints("block_domain")["destructiveHint"], false);
    assert_eq!(hints("pause_filtering")["idempotentHint"], false);
    assert_eq!(hints("refresh_lists")["openWorldHint"], true);
    assert_eq!(hints("set_device_profile")["readOnlyHint"], false);
    drop(state);
    test_support::cleanup_sqlite(&db);
}

#[tokio::test]
async fn prompts_word_the_two_usual_requests() {
    let (state, db) = enabled_state("mcp-prompts", false).await;
    let (_, v) = send(
        &state,
        HeaderMap::new(),
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}),
    )
    .await;
    assert!(v["result"]["capabilities"]["prompts"].is_object());

    let (_, v) = send(
        &state,
        HeaderMap::new(),
        json!({"jsonrpc":"2.0","id":2,"method":"prompts/list"}),
    )
    .await;
    let names: Vec<&str> = v["result"]["prompts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["why_not_working", "network_report"]);

    let (_, v) = send(
        &state,
        HeaderMap::new(),
        json!({"jsonrpc":"2.0","id":3,"method":"prompts/get","params":{
            "name":"why_not_working","arguments":{"site":"instagram","device":"pixel"}}}),
    )
    .await;
    let text = v["result"]["messages"][0]["content"]["text"]
        .as_str()
        .unwrap();
    assert!(
        text.contains("diagnose") && text.contains("client: pixel"),
        "{text}"
    );

    // The site is needed; an unknown prompt is a protocol error.
    let (_, v) = send(
        &state,
        HeaderMap::new(),
        json!({"jsonrpc":"2.0","id":4,"method":"prompts/get","params":{"name":"why_not_working"}}),
    )
    .await;
    assert_eq!(v["error"]["code"], INVALID_PARAMS);
    let (_, v) = send(
        &state,
        HeaderMap::new(),
        json!({"jsonrpc":"2.0","id":5,"method":"prompts/get","params":{"name":"nope"}}),
    )
    .await;
    assert_eq!(v["error"]["code"], INVALID_PARAMS);
    drop(state);
    test_support::cleanup_sqlite(&db);
}

#[tokio::test]
async fn diagnose_reads_the_log_and_names_the_fix() {
    use ferrite_core::recording::RecordScope;
    use ferrite_core::types::QueryStatus::{Blocked, Upstream};
    let (state, db) = enabled_state("mcp-diagnose-log", false).await;
    state
        .inner
        .blocklist
        .add_blacklist("api.example.com")
        .unwrap();
    let rows = vec![
        entry(1, 300, "www.example.com", Upstream, 0),
        entry(2, 240, "api.example.com", Blocked, 3),
        entry(3, 180, "api.example.com", Blocked, 3),
        entry(4, 120, "cdn.example.com", Upstream, 2),
        entry(5, 60, "other.test", Upstream, 0),
        // Long before the window.
        entry(6, 7200, "old.example.com", Blocked, 3),
    ];
    state
        .inner
        .storage
        .write_batch(rows, RecordScope::ALL)
        .await
        .unwrap();

    // A link is as good as a domain.
    let (_, v) = send(
        &state,
        HeaderMap::new(),
        call(
            1,
            "diagnose",
            json!({"site": "https://www.example.com/news?x=1", "client": "192.168.1.20"}),
        ),
    )
    .await;
    let r = structured(&v);
    assert_eq!(r["site"], "example.com");
    assert_eq!(r["verdict"], "blocked", "{r}");
    let names: Vec<&str> = r["names"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n["domain"].as_str().unwrap())
        .collect();
    assert_eq!(
        names[0], "api.example.com",
        "blocked names first: {names:?}"
    );
    assert!(names.contains(&"cdn.example.com"));
    assert!(!names.contains(&"other.test") && !names.contains(&"old.example.com"));
    assert_eq!(r["names"][0]["blocked"], 2);
    assert_eq!(r["names"][0]["blocked_by"][0]["kind"], "blacklist");
    assert_eq!(
        r["suggestions"][0],
        json!({
            "tool": "remove_domain_rule",
            "arguments": { "domain": "api.example.com", "list": "block" },
            "why": "remove the rule that blocks api.example.com",
        })
    );
    let findings = r["findings"].to_string();
    assert!(findings.contains("SERVFAIL"), "{findings}");

    // Nothing asked of another site: the device may not use ferrite.
    let (_, v) = send(
        &state,
        HeaderMap::new(),
        call(
            2,
            "diagnose",
            json!({"site": "wikipedia.org", "client": "192.168.1.20"}),
        ),
    )
    .await;
    let r = structured(&v);
    assert_eq!(r["verdict"], "no_queries", "{r}");
    assert!(r["findings"].to_string().contains("doesn't ask ferrite"));

    // Not a site at all.
    let (_, v) = send(
        &state,
        HeaderMap::new(),
        call(3, "diagnose", json!({"site": "printer"})),
    )
    .await;
    assert_eq!(v["result"]["isError"], true);

    // A device by its name, or by a part of it that names only it.
    let _ = crate::clients::add_alias(
        State(state.clone()),
        Json(crate::clients::AliasPayload {
            ip: Some("192.168.1.20".into()),
            mac: None,
            name: "Kitchen tablet".into(),
        }),
    )
    .await
    .unwrap();
    let (_, v) = send(
        &state,
        HeaderMap::new(),
        call(
            4,
            "diagnose",
            json!({"site": "example.com", "client": "kitchen"}),
        ),
    )
    .await;
    let r = structured(&v);
    assert_eq!(r["device"]["name"], "Kitchen tablet", "{r}");
    assert_eq!(r["device"]["key"], "192.168.1.20");
    assert_eq!(r["verdict"], "blocked");
    let (_, v) = send(
        &state,
        HeaderMap::new(),
        call(5, "device_report", json!({"client": "nobody-by-that-name"})),
    )
    .await;
    assert_eq!(v["result"]["isError"], true);
    drop(state);
    test_support::cleanup_sqlite(&db);
}

#[tokio::test]
async fn diagnose_finds_services_profiles_and_pauses() {
    let (state, db) = enabled_state("mcp-diagnose-rules", true).await;
    let kids: ferrite_core::config::BlocklistProfileConfig = serde_json::from_value(json!({
        "id": "kids", "name": "Kids", "clients": ["10.0.0.9"], "services": ["youtube"]
    }))
    .unwrap();
    let _ = crate::profiles::put_profiles(State(state.clone()), Json(vec![kids]))
        .await
        .unwrap();
    let _ = send(
        &state,
        HeaderMap::new(),
        call(
            1,
            "set_service_blocked",
            json!({"service": "instagram", "blocked": true}),
        ),
    )
    .await;

    // Blocked for everyone as a service: unblock the service.
    let (_, v) = send(
        &state,
        HeaderMap::new(),
        call(2, "diagnose", json!({"site": "Instagram"})),
    )
    .await;
    let r = structured(&v);
    assert_eq!(r["service"], "instagram");
    assert_eq!(r["verdict"], "blocked", "{r}");
    assert_eq!(r["suggestions"][0]["tool"], "set_service_blocked");
    assert_eq!(
        r["suggestions"][0]["arguments"],
        json!({"service": "instagram", "blocked": false})
    );

    // Blocked by the device's profile: unblock it for that profile only.
    let (_, v) = send(
        &state,
        HeaderMap::new(),
        call(
            3,
            "diagnose",
            json!({"site": "youtube", "client": "10.0.0.9"}),
        ),
    )
    .await;
    let r = structured(&v);
    assert_eq!(r["profile"], "kids", "{r}");
    assert_eq!(
        r["suggestions"][0]["arguments"],
        json!({"service": "youtube", "blocked": false, "profile": "kids"})
    );
    // Another device isn't in that profile: YouTube is fine for it.
    let (_, v) = send(
        &state,
        HeaderMap::new(),
        call(
            4,
            "diagnose",
            json!({"site": "youtube", "client": "10.0.0.8"}),
        ),
    )
    .await;
    assert_ne!(structured(&v)["verdict"], "blocked");

    // Paused: the filter isn't the cause, whatever it would block.
    let _ = send(
        &state,
        HeaderMap::new(),
        call(
            5,
            "pause_filtering",
            json!({"minutes": 5, "clients": ["10.0.0.9"]}),
        ),
    )
    .await;
    let (_, v) = send(
        &state,
        HeaderMap::new(),
        call(
            6,
            "diagnose",
            json!({"site": "youtube", "client": "10.0.0.9"}),
        ),
    )
    .await;
    assert_eq!(structured(&v)["verdict"], "not_filtered");
    drop(state);
    test_support::cleanup_sqlite(&db);
}

#[tokio::test]
async fn devices_profiles_and_tunnels_change_like_in_the_panel() {
    let (state, db) = enabled_state("mcp-device-tunnel", true).await;
    let kids: ferrite_core::config::BlocklistProfileConfig =
        serde_json::from_value(json!({ "id": "kids", "name": "Kids" })).unwrap();
    let _ = crate::profiles::put_profiles(State(state.clone()), Json(vec![kids]))
        .await
        .unwrap();

    // Into a profile and out again.
    let (_, v) = send(
        &state,
        HeaderMap::new(),
        call(
            1,
            "set_device_profile",
            json!({"client": "10.0.0.9", "profile": "kids"}),
        ),
    )
    .await;
    structured(&v);
    assert_eq!(
        state.inner.blocklist.get_profiles()[0].clients,
        vec!["10.0.0.9"]
    );
    let (_, v) = send(
        &state,
        HeaderMap::new(),
        call(2, "device_report", json!({"client": "10.0.0.9"})),
    )
    .await;
    assert_eq!(structured(&v)["profile"], "kids");
    let (_, v) = send(
        &state,
        HeaderMap::new(),
        call(3, "set_device_profile", json!({"client": "10.0.0.9"})),
    )
    .await;
    structured(&v);
    assert!(state.inner.blocklist.get_profiles()[0].clients.is_empty());
    let (_, v) = send(
        &state,
        HeaderMap::new(),
        call(
            4,
            "set_device_profile",
            json!({"client": "10.0.0.9", "profile": "ghost"}),
        ),
    )
    .await;
    assert_eq!(v["result"]["isError"], true);

    // A tunnel to route through.
    let mut proxy = state.live_config.read().proxy.clone();
    proxy.egresses = vec![
        serde_json::from_value(json!({"id": "nl", "kind": "direct"})).unwrap(),
        serde_json::from_value(json!({"id": "de", "kind": "direct"})).unwrap(),
    ];
    let _ = crate::proxy::put_proxy(State(state.clone()), Json(proxy))
        .await
        .unwrap();

    let (_, v) = send(
        &state,
        HeaderMap::new(),
        call(
            5,
            "route_through_tunnel",
            json!({"domain": "Reddit.com.", "egress": "nl"}),
        ),
    )
    .await;
    let r = structured(&v);
    assert_eq!(r["tunnels_enabled"], false);
    assert!(r["note"].is_string());
    // The same name again moves it, rather than adding a second rule.
    let (_, v) = send(
        &state,
        HeaderMap::new(),
        call(
            6,
            "route_through_tunnel",
            json!({"domain": "reddit.com", "egress": "de"}),
        ),
    )
    .await;
    structured(&v);
    let rules = state.live_config.read().proxy.rules.clone();
    assert_eq!(rules.len(), 1);
    assert_eq!(
        (rules[0].pattern.as_str(), rules[0].egress.as_str()),
        ("reddit.com", "de")
    );
    assert!(rules[0].fail_closed);

    let (_, v) = send(
        &state,
        HeaderMap::new(),
        call(
            7,
            "route_through_tunnel",
            json!({"domain": "x.test", "egress": "nowhere"}),
        ),
    )
    .await;
    assert_eq!(v["result"]["isError"], true);
    let (_, v) = send(
        &state,
        HeaderMap::new(),
        call(8, "remove_tunnel_route", json!({"domain": "reddit.com"})),
    )
    .await;
    assert_eq!(structured(&v)["removed"], 1);
    let (_, v) = send(
        &state,
        HeaderMap::new(),
        call(9, "remove_tunnel_route", json!({"domain": "reddit.com"})),
    )
    .await;
    assert_eq!(v["result"]["isError"], true);

    // Keeping a name blocked lands in the config.
    let (_, v) = send(
        &state,
        HeaderMap::new(),
        call(
            10,
            "keep_blocked",
            json!({"domain": "telemetry.example.com"}),
        ),
    )
    .await;
    structured(&v);
    assert_eq!(
        state.live_config.read().blocklist.breakage_ignore,
        vec!["telemetry.example.com"]
    );
    drop(state);
    test_support::cleanup_sqlite(&db);
}
