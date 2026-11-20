//! How the upstreams are doing, and a try of one: what the panel shows next
//! to each, and what its Test button asks.

use std::time::Duration;

use axum::{Json, extract::State};

use ferrite_app::AppState;
use ferrite_core::config::UpstreamConfig;
use ferrite_upstream::{ProbeResult, UpstreamStatus};

/// A try from the panel's Test button may take this long.
const TEST_WITHIN: Duration = Duration::from_secs(10);
/// The tries after a save, all at once, hold the answer at most this long.
const SAVE_WITHIN: Duration = Duration::from_secs(5);

/// GET /api/upstreams/status — each configured upstream, in order: answering,
/// failing (and why), or not asked yet.
pub async fn status(State(state): State<AppState>) -> Json<Vec<UpstreamStatus>> {
    Json(state.inner.upstream_pool.default_pool().status())
}

/// POST /api/upstreams/test — try one upstream as the form has it, saved or
/// not: checked as a save would, then asked over a connection of its own.
pub async fn test(
    State(state): State<AppState>,
    Json(cfg): Json<UpstreamConfig>,
) -> Json<ProbeResult> {
    if let Err(why) = ferrite_upstream::check_one(&cfg) {
        return Json(ProbeResult {
            label: String::new(),
            ok: false,
            ms: None,
            error: Some(why),
        });
    }
    Json(ferrite_upstream::probe(&cfg, &state.inner.upstream_proxy, TEST_WITHIN).await)
}

/// Every upstream tried at once, for the answer to a save; in their order.
pub(crate) async fn check_all(state: &AppState, upstream: &[UpstreamConfig]) -> Vec<ProbeResult> {
    let mut tries = tokio::task::JoinSet::new();
    for (i, cfg) in upstream.iter().cloned().enumerate() {
        let proxy = std::sync::Arc::clone(&state.inner.upstream_proxy);
        tries.spawn(async move { (i, ferrite_upstream::probe(&cfg, &proxy, SAVE_WITHIN).await) });
    }
    let mut results: Vec<(usize, ProbeResult)> = tries.join_all().await;
    results.sort_by_key(|(i, _)| *i);
    results.into_iter().map(|(_, r)| r).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::{SettingsPatch, update_settings};
    use ferrite_app::test_support;

    /// A UDP resolver on localhost that answers every query.
    async fn answering() -> u16 {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            while let Ok((n, from)) = socket.recv_from(&mut buf).await {
                buf[2] |= 0x80;
                let _ = socket.send_to(&buf[..n], from).await;
            }
        });
        port
    }

    fn plain(port: u16) -> UpstreamConfig {
        UpstreamConfig::Plain {
            address: "127.0.0.1".into(),
            port,
            egress: None,
        }
    }

    #[tokio::test]
    async fn a_save_with_a_scheme_in_tls_name_is_refused_and_names_the_fix() {
        let (state, db_path, config_path) =
            test_support::app_state_with_config_path("upstreams-bad-name").await;
        let before = state.live_config.read().upstream.len();
        let err = update_settings(
            State(state.clone()),
            axum::http::HeaderMap::new(),
            Json(SettingsPatch {
                upstream: Some(vec![UpstreamConfig::Quic {
                    address: "138.199.149.249".into(),
                    port: 853,
                    tls_name: "quic://blank.dnsforge.de".into(),
                }]),
                ..Default::default()
            }),
        )
        .await
        .unwrap_err();
        let e = err.0.to_string();
        assert!(e.contains("upstream 1 (doq://138.199.149.249:853)"), "{e}");
        assert!(e.contains("'blank.dnsforge.de'"), "{e}");
        assert_eq!(state.live_config.read().upstream.len(), before);
        assert!(!config_path.exists());

        drop(state);
        test_support::cleanup_sqlite(&db_path);
    }

    #[tokio::test]
    async fn a_save_says_which_upstreams_answer_and_the_status_follows() {
        let (state, db_path, config_path) =
            test_support::app_state_with_config_path("upstreams-checks").await;
        let good = answering().await;
        let dead = std::net::UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();

        let Json(v) = update_settings(
            State(state.clone()),
            axum::http::HeaderMap::new(),
            Json(SettingsPatch {
                upstream: Some(vec![plain(dead), plain(good)]),
                ..Default::default()
            }),
        )
        .await
        .unwrap();
        assert_eq!(v["status"], "ok");
        let checks = v["upstream_checks"].as_array().unwrap();
        assert_eq!(checks.len(), 2);
        assert_eq!(checks[0]["ok"], false, "{v}");
        assert!(checks[0]["error"].is_string());
        assert_eq!(checks[1]["ok"], true, "{v}");

        // The tries after the save are the pool's first word on each.
        let Json(before) = status(State(state.clone())).await;
        assert_eq!(before[0].state, "failing");
        assert!(before[0].last_error.is_some());
        assert_eq!(before[1].state, "ok");
        let mut query = vec![0x12, 0x34, 0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        query.extend_from_slice(&[0, 0, 2, 0, 1]);
        state.inner.upstream_pool.resolve_raw(query).await.unwrap();
        let Json(after) = status(State(state.clone())).await;
        assert_eq!(after.len(), 2);
        assert!(after.iter().any(|s| s.state == "ok"));

        // The Test button: as the form has it, checked first.
        let Json(r) = test(State(state.clone()), Json(plain(good))).await;
        assert!(r.ok, "{r:?}");
        let Json(r) = test(
            State(state.clone()),
            Json(UpstreamConfig::Tls {
                address: "9.9.9.9".into(),
                port: 853,
                tls_name: "dns.quad9.net:853".into(),
                egress: None,
            }),
        )
        .await;
        assert!(!r.ok);
        assert!(r.error.unwrap().contains("has a port"));

        drop(state);
        test_support::cleanup_sqlite(&db_path);
        let _ = std::fs::remove_file(config_path);
    }
}
