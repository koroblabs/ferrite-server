//! Likely breakage: blocked names devices keep asking for while they use the
//! site the name belongs to (see `ferrite_stats::breakage`). Only what a
//! subscription list blocks is shown — a manual rule or a blocked service is
//! the user's own choice — and allowing one is the ordinary whitelist.

use std::collections::BTreeMap;

use axum::{
    Json,
    extract::{Path, State},
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::ApiError;
use ferrite_app::AppState;
use ferrite_core::error::FeriteError;

/// Names shown at most.
const SHOWN: usize = 20;

#[derive(Deserialize)]
pub struct IgnorePayload {
    pub domain: String,
}

/// Whether `domain` is `entry` or under it.
fn covered(domain: &str, entry: &str) -> bool {
    domain == entry
        || domain
            .strip_suffix(entry)
            .is_some_and(|rest| rest.ends_with('.'))
}

/// GET /api/breakage — one row per name, with the devices asking for it,
/// latest first; and the names set aside.
pub async fn get_breakage(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    let ignored = state.live_config.read().blocklist.breakage_ignore.clone();
    let suspects: Vec<_> = state
        .inner
        .live_stats
        .breakage
        .suspects()
        .into_iter()
        .filter(|s| !ignored.iter().any(|i| covered(&s.domain, i)))
        .collect();

    // One row per name; `suspects` is latest first, so the first device seen
    // for a name carries its latest try.
    let mut order: Vec<String> = Vec::new();
    let mut rows: BTreeMap<String, (String, u32, i64, i64, Vec<String>)> = BTreeMap::new();
    for s in suspects {
        let row = rows.entry(s.domain.clone()).or_insert_with(|| {
            order.push(s.domain.clone());
            (s.site.clone(), 0, s.first, s.last, Vec::new())
        });
        row.1 = row.1.max(s.tries);
        row.2 = row.2.min(s.first);
        row.3 = row.3.max(s.last);
        if !row.4.contains(&s.device) {
            row.4.push(s.device);
        }
    }

    // What blocks each name, off the DNS path: the explanation reads every
    // list's own file.
    let blocklist = std::sync::Arc::clone(&state.inner.blocklist);
    let names = order.clone();
    let explained = tokio::task::spawn_blocking(move || {
        names
            .into_iter()
            .map(|d| blocklist.explain(&d))
            .collect::<Vec<_>>()
    })
    .await
    .map_err(|e| ApiError(FeriteError::Internal(format!("explain task failed: {e}"))))?;

    let registry = &state.inner.client_registry;
    let mut out = Vec::new();
    for (domain, why) in order.iter().zip(explained) {
        // Not blocked for everyone any more (allowed since, or a profile's
        // own block), or blocked by something other than a list: not ours
        // to suggest.
        if !why.blocked || why.sources.iter().any(|s| s.kind != "list") {
            continue;
        }
        let (site, tries, first, last, devices) = &rows[domain];
        let devices: Vec<Value> = devices
            .iter()
            .map(|device| {
                let info = registry.describe_device(device);
                json!({ "device": device, "name": info.name, "ips": info.ips })
            })
            .collect();
        let mut lists: Vec<String> = why.sources.iter().map(|s| s.name.clone()).collect();
        lists.dedup();
        out.push(json!({
            "domain": domain,
            "site": site,
            "tries": tries,
            "first": first,
            "last": last,
            "lists": lists,
            "devices": devices,
        }));
        if out.len() == SHOWN {
            break;
        }
    }
    Ok(Json(json!({ "suspects": out, "ignored": ignored })))
}

/// POST /api/breakage/ignore — this block is fine: stop suggesting it.
pub async fn ignore(
    State(state): State<AppState>,
    Json(payload): Json<IgnorePayload>,
) -> Result<Json<Value>, ApiError> {
    let domain = ferrite_blocklist::normalise_domain(&payload.domain);
    if domain.is_empty() {
        return Err(ApiError(FeriteError::Config("a domain is needed".into())));
    }
    {
        let mut cfg = state.live_config.write();
        let list = &mut cfg.blocklist.breakage_ignore;
        if !list.contains(&domain) {
            list.push(domain.clone());
            list.sort();
        }
    }
    state.inner.live_stats.breakage.drop_domain(&domain);
    let persisted = state.persist_config().await.is_some();
    Ok(Json(json!({ "domain": domain, "persisted": persisted })))
}

/// DELETE /api/breakage/ignore/{domain} — suggest it again if it breaks.
pub async fn unignore(
    State(state): State<AppState>,
    Path(domain): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let domain = ferrite_blocklist::normalise_domain(&domain);
    state
        .live_config
        .write()
        .blocklist
        .breakage_ignore
        .retain(|d| *d != domain);
    let persisted = state.persist_config().await.is_some();
    Ok(Json(json!({ "domain": domain, "persisted": persisted })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use ferrite_core::types::{QueryEntry, QueryStatus};

    fn q(domain: &str, status: QueryStatus, secs: i64) -> QueryEntry {
        QueryEntry {
            id: 0,
            timestamp: Utc::now() + chrono::Duration::seconds(secs),
            domain: domain.into(),
            query_type: 1,
            client_ip: "192.168.1.20".into(),
            device: "192.168.1.20".into(),
            status,
            latency_ms: 0,
            upstream: None,
            rcode: 0,
        }
    }

    #[test]
    fn an_entry_covers_itself_and_what_is_under_it() {
        assert!(covered("graph.example.com", "graph.example.com"));
        assert!(covered("a.graph.example.com", "graph.example.com"));
        assert!(!covered("xgraph.example.com", "graph.example.com"));
        assert!(!covered("example.com", "graph.example.com"));
    }

    #[tokio::test]
    async fn a_name_a_list_blocks_is_suggested_until_it_is_allowed() {
        let (state, db, config_path) =
            ferrite_app::test_support::app_state_with_config_path("breakage-list").await;
        let dir = std::env::temp_dir().join(format!("ferrite-breakage-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let list = dir.join("list.txt");
        std::fs::write(&list, "graph.example.com\n").unwrap();
        let bl = &state.inner.blocklist;
        bl.subscriptions(ferrite_blocklist::ListPolarity::Block)
            .add(ferrite_core::config::ListConfig {
                name: "Test list".into(),
                url: format!("file://{}", list.display()),
                enabled: true,
            })
            .unwrap();
        bl.refresh(true).await.unwrap();
        assert!(bl.should_block_for("graph.example.com", None));

        let live = &state.inner.live_stats;
        live.breakage.push(
            &q("www.example.com", QueryStatus::Upstream, 0),
            "192.168.1.20",
        );
        for minute in 0..4 {
            live.breakage.push(
                &q("graph.example.com", QueryStatus::Blocked, minute * 60),
                "192.168.1.20",
            );
        }
        let Json(v) = get_breakage(State(state.clone())).await.unwrap();
        let rows = v["suspects"].as_array().unwrap();
        assert_eq!(rows.len(), 1, "{v}");
        assert_eq!(rows[0]["domain"], "graph.example.com");
        assert_eq!(rows[0]["site"], "example.com");
        assert_eq!(rows[0]["tries"], 4);
        assert_eq!(rows[0]["lists"], json!(["Test list"]));
        assert_eq!(rows[0]["devices"][0]["device"], "192.168.1.20");

        // Allowed (the whitelist): no longer a suggestion.
        bl.add_whitelist("graph.example.com").unwrap();
        let Json(v) = get_breakage(State(state.clone())).await.unwrap();
        assert_eq!(v["suspects"], json!([]), "{v}");

        let _ = std::fs::remove_dir_all(&dir);
        ferrite_app::test_support::cleanup_sqlite(&db);
        let _ = std::fs::remove_file(&config_path);
    }

    #[tokio::test]
    async fn only_what_a_list_blocks_is_suggested_and_ignoring_it_sticks() {
        let (state, db, config_path) =
            ferrite_app::test_support::app_state_with_config_path("breakage").await;
        let live = &state.inner.live_stats;
        // A manual rule: the user's own choice, never suggested.
        state
            .inner
            .blocklist
            .add_blacklist("api.example.com")
            .unwrap();
        live.breakage
            .push(&q("example.com", QueryStatus::Upstream, 0), "192.168.1.20");
        for minute in 0..3 {
            live.breakage.push(
                &q("api.example.com", QueryStatus::Blocked, minute * 60),
                "192.168.1.20",
            );
        }
        assert_eq!(live.breakage.suspects().len(), 1, "the watch saw it");
        let Json(v) = get_breakage(State(state.clone())).await.unwrap();
        assert_eq!(v["suspects"], json!([]), "{v}");

        // Ignoring a name drops it and is kept in the config.
        let Json(v) = ignore(
            State(state.clone()),
            Json(IgnorePayload {
                domain: "API.example.com.".into(),
            }),
        )
        .await
        .unwrap();
        assert_eq!(v["domain"], "api.example.com");
        assert!(live.breakage.suspects().is_empty());
        let Json(v) = get_breakage(State(state.clone())).await.unwrap();
        assert_eq!(v["ignored"], json!(["api.example.com"]));
        let saved = std::fs::read_to_string(&config_path).unwrap();
        assert!(saved.contains("breakage_ignore"), "{saved}");

        let _ = unignore(State(state.clone()), Path("api.example.com".into()))
            .await
            .unwrap();
        let Json(v) = get_breakage(State(state.clone())).await.unwrap();
        assert_eq!(v["ignored"], json!([]));

        ferrite_app::test_support::cleanup_sqlite(&db);
        let _ = std::fs::remove_file(&config_path);
    }
}
