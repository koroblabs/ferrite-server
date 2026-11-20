use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use tokio_rustls::rustls::ClientConfig;
use tokio_rustls::rustls::pki_types::ServerName;

use crate::egress::ProxyHandle;
use crate::tunneled::{TunneledResolver, client_config};
use crate::{doh::DohResolver, doq::DoqResolver, plain::PlainResolver, stream::StreamResolver};
use ferrite_core::config::UpstreamConfig;
use ferrite_core::error::{FeriteError, Result};

/// A single upstream entry, wrapping one of the protocol variants.
pub enum UpstreamEntry {
    Plain(PlainResolver),
    /// Direct DoT (no egress), raw-forwarding over a pooled TLS connection.
    Tls(Box<StreamResolver>),
    Https(DohResolver),
    Quic(Box<DoqResolver>),
    /// Plain DNS-over-TCP or DoT routed through an egress (tunnel).
    Tunneled(TunneledResolver),
}

impl UpstreamEntry {
    pub async fn resolve_raw(&self, raw: Vec<u8>) -> Result<(Vec<u8>, String)> {
        match self {
            UpstreamEntry::Plain(r) => r.resolve_raw(raw).await,
            UpstreamEntry::Tls(r) => r.resolve_raw(raw).await,
            UpstreamEntry::Https(r) => r.resolve_raw(raw).await,
            UpstreamEntry::Quic(r) => r.resolve_raw(raw).await,
            UpstreamEntry::Tunneled(r) => r.resolve_raw(raw).await,
        }
    }

    pub fn label(&self) -> &str {
        match self {
            UpstreamEntry::Plain(r) => r.label(),
            UpstreamEntry::Tls(r) => r.label(),
            UpstreamEntry::Https(r) => r.label(),
            UpstreamEntry::Quic(r) => r.label(),
            UpstreamEntry::Tunneled(r) => r.label(),
        }
    }
}

/// Round-robin pool of upstream resolvers, keeping track of which answer.
///
/// An upstream that fails is tried after the others for a while — 10 s, then
/// doubling up to 5 min while it keeps failing — instead of costing every
/// query that lands on it a failed try first. Once that while is over, one
/// query tries it again; one that answers puts it back in the round. Each
/// change is logged once: failing (with the reason), the reason changing,
/// answering again.
pub struct UpstreamPool {
    upstreams: Vec<Member>,
    counter: AtomicUsize,
}

struct Member {
    entry: UpstreamEntry,
    health: Mutex<Health>,
}

#[derive(Default)]
struct Health {
    /// Failures in a row; 0 while it answers.
    failures: u32,
    /// Tried after the others until then.
    rest_until: Option<Instant>,
    last_error: Option<String>,
    failing_since: Option<SystemTime>,
    last_ok: Option<SystemTime>,
    last_ms: Option<u32>,
}

const FIRST_REST: Duration = Duration::from_secs(10);
const LONGEST_REST: Duration = Duration::from_secs(300);
/// Held for the one query trying a resting upstream again, so the others
/// don't all pile onto it at once.
const TRIAL: Duration = Duration::from_secs(10);

fn rest_for(failures: u32) -> Duration {
    FIRST_REST
        .saturating_mul(1 << failures.saturating_sub(1).min(8))
        .min(LONGEST_REST)
}

impl Member {
    /// Whether it goes in the first round. Past its rest, the caller is the
    /// one query that tries it again.
    fn ready(&self, now: Instant) -> bool {
        let mut h = self.health.lock().unwrap();
        match h.rest_until {
            _ if h.failures == 0 => true,
            Some(until) if until > now => false,
            _ => {
                h.rest_until = Some(now + TRIAL);
                true
            }
        }
    }

    fn answered(&self, took: Duration) {
        let mut h = self.health.lock().unwrap();
        if h.failures > 0 {
            tracing::info!(
                "upstream {} answers again, after {} failed {}",
                self.entry.label(),
                h.failures,
                if h.failures == 1 { "try" } else { "tries" }
            );
        }
        *h = Health {
            last_ok: Some(SystemTime::now()),
            last_ms: Some(took.as_millis().min(u32::MAX as u128) as u32),
            ..Health::default()
        };
    }

    fn failed(&self, e: &FeriteError) {
        let why = reason(e);
        let mut h = self.health.lock().unwrap();
        h.failures += 1;
        let rest = rest_for(h.failures);
        h.rest_until = Some(Instant::now() + rest);
        h.failing_since.get_or_insert_with(SystemTime::now);
        let label = self.entry.label();
        if h.failures == 1 {
            tracing::warn!(
                "upstream {label} failed: {why} — the others answer first, it's tried again in {}s",
                rest.as_secs()
            );
        } else if h.last_error.as_deref() != Some(why.as_str()) {
            tracing::warn!("upstream {label} still fails, now: {why}");
        } else {
            tracing::debug!("upstream {label} failed again: {why}");
        }
        h.last_error = Some(why);
    }

    fn status(&self, now: Instant) -> UpstreamStatus {
        let h = self.health.lock().unwrap();
        UpstreamStatus {
            label: self.entry.label().to_string(),
            state: match (h.failures, h.last_ok) {
                (0, Some(_)) => "ok",
                (0, None) => "unknown",
                _ => "failing",
            },
            last_error: h.last_error.clone(),
            failing_since: h.failing_since.map(unix),
            last_ok: h.last_ok.map(unix),
            latency_ms: h.last_ms,
            retry_in: h
                .rest_until
                .filter(|_| h.failures > 0)
                .map(|until| until.saturating_duration_since(now).as_secs()),
        }
    }
}

/// How an upstream is doing, as the panel shows it.
#[derive(Debug, Clone, Serialize)]
pub struct UpstreamStatus {
    pub label: String,
    /// `ok`, `failing`, or `unknown` — not asked yet.
    pub state: &'static str,
    pub last_error: Option<String>,
    /// Unix seconds.
    pub failing_since: Option<i64>,
    pub last_ok: Option<i64>,
    /// The last answer's round trip.
    pub latency_ms: Option<u32>,
    /// Seconds until it's tried again, while failing.
    pub retry_in: Option<u64>,
}

fn unix(t: SystemTime) -> i64 {
    t.duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// The error without the "DNS error: " its type puts in front.
fn reason(e: &FeriteError) -> String {
    match e {
        FeriteError::Dns(why) | FeriteError::Config(why) => why.clone(),
        other => other.to_string(),
    }
}

impl UpstreamPool {
    /// Build a pool from a list of `UpstreamConfig` entries.
    pub fn from_config(configs: &[UpstreamConfig], proxy: ProxyHandle) -> Result<Arc<Self>> {
        if configs.is_empty() {
            return Err(FeriteError::Config("no upstreams configured".to_string()));
        }

        // Shared TLS client config, built lazily only if a tunneled DoT upstream
        // is configured (most setups have none).
        let mut tls_config: Option<Arc<ClientConfig>> = None;

        let mut upstreams = Vec::with_capacity(configs.len());
        for cfg in configs {
            upstreams.push(Member {
                entry: build(cfg, &proxy, &mut tls_config)?,
                health: Mutex::default(),
            });
        }

        Ok(Arc::new(Self {
            upstreams,
            counter: AtomicUsize::new(0),
        }))
    }

    /// Forward the raw query to the next upstream in the round; on failure,
    /// to the others. Resting upstreams come last, so they still answer when
    /// nothing else does.
    pub async fn resolve_raw(&self, raw: Vec<u8>) -> Result<(Vec<u8>, String)> {
        let n = self.upstreams.len();
        let start = self.counter.fetch_add(1, Ordering::Relaxed) % n;
        let now = Instant::now();
        let (ready, resting): (Vec<usize>, Vec<usize>) = (0..n)
            .map(|i| (start + i) % n)
            .partition(|&idx| self.upstreams[idx].ready(now));

        let mut last_err = FeriteError::Dns("no upstreams available".to_string());
        for idx in ready.into_iter().chain(resting) {
            let member = &self.upstreams[idx];
            let began = Instant::now();
            match member.entry.resolve_raw(raw.clone()).await {
                Ok(result) => {
                    member.answered(began.elapsed());
                    return Ok(result);
                }
                Err(e) => {
                    member.failed(&e);
                    last_err = e;
                }
            }
        }

        Err(last_err)
    }

    /// Take what tries of these upstreams found (in the configured order) as
    /// their state: one that didn't answer rests from now on, instead of the
    /// next query finding out again.
    pub fn note(&self, found: &[ProbeResult]) {
        for (member, probe) in self.upstreams.iter().zip(found) {
            match (&probe.error, probe.ms) {
                (None, Some(ms)) => member.answered(Duration::from_millis(ms)),
                (Some(why), _) => member.failed(&FeriteError::Dns(why.clone())),
                (None, None) => {}
            }
        }
    }

    /// Each upstream's state, in the configured order.
    pub fn status(&self) -> Vec<UpstreamStatus> {
        let now = Instant::now();
        self.upstreams.iter().map(|m| m.status(now)).collect()
    }
}

fn build(
    cfg: &UpstreamConfig,
    proxy: &ProxyHandle,
    tls_config: &mut Option<Arc<ClientConfig>>,
) -> Result<UpstreamEntry> {
    Ok(match cfg {
        // Tunneled (egress set) variants first — most-specific match wins.
        UpstreamConfig::Plain {
            address,
            port,
            egress: Some(id),
        } => UpstreamEntry::Tunneled(TunneledResolver::plain(proxy.clone(), id, address, *port)?),
        UpstreamConfig::Tls {
            address,
            port,
            tls_name,
            egress: Some(id),
        } => {
            let tls = match tls_config {
                Some(c) => c.clone(),
                None => tls_config.insert(client_config()?).clone(),
            };
            UpstreamEntry::Tunneled(TunneledResolver::dot(
                proxy.clone(),
                id,
                address,
                *port,
                tls_name,
                tls,
            )?)
        }
        // Direct (no egress) variants.
        UpstreamConfig::Plain { address, port, .. } => {
            UpstreamEntry::Plain(PlainResolver::new(address, *port)?)
        }
        UpstreamConfig::Tls {
            address,
            port,
            tls_name,
            ..
        } => UpstreamEntry::Tls(Box::new(StreamResolver::dot(address, *port, tls_name)?)),
        UpstreamConfig::Https { url, bootstrap_ip } => {
            UpstreamEntry::Https(DohResolver::new(url, bootstrap_ip.as_deref())?)
        }
        UpstreamConfig::Quic {
            address,
            port,
            tls_name,
        } => UpstreamEntry::Quic(Box::new(DoqResolver::new(address, *port, tls_name)?)),
    })
}

// ── Checks ────────────────────────────────────────────────────────────────────

/// What a single try of an upstream found.
#[derive(Debug, Clone, Serialize)]
pub struct ProbeResult {
    pub label: String,
    pub ok: bool,
    /// The round trip, when it answered.
    pub ms: Option<u64>,
    /// What went wrong, in the transport's own words.
    pub error: Option<String>,
}

/// Ask `cfg` for the root's name servers over a connection of its own (no
/// pool, nothing shared) and say how that went within `within`: an answer, or
/// why there was none — the address, the handshake, the certificate, the
/// answer itself.
pub async fn probe(cfg: &UpstreamConfig, proxy: &ProxyHandle, within: Duration) -> ProbeResult {
    let entry = match build(cfg, proxy, &mut None) {
        Ok(entry) => entry,
        Err(e) => {
            return ProbeResult {
                label: describe(cfg),
                ok: false,
                ms: None,
                error: Some(reason(&e)),
            };
        }
    };
    let label = entry.label().to_string();
    let id = probe_id();
    let mut query = id.to_be_bytes().to_vec();
    // RD, one question: `. IN NS`.
    query.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1]);

    let began = Instant::now();
    let outcome = tokio::time::timeout(within, entry.resolve_raw(query)).await;
    let ms = began.elapsed().as_millis() as u64;
    let error = match outcome {
        Err(_) => Some(format!("no answer in {} s", within.as_secs())),
        Ok(Err(e)) => Some(reason(&e)),
        Ok(Ok((answer, _))) if answer.len() < 12 || answer[..2] != id.to_be_bytes() => {
            Some("the answer isn't one to our question".to_string())
        }
        Ok(Ok((answer, _))) => match answer[3] & 0x0f {
            0 | 3 => None,
            rcode => Some(format!("it answered {}", rcode_name(rcode))),
        },
    };
    ProbeResult {
        label,
        ok: error.is_none(),
        ms: error.is_none().then_some(ms),
        error,
    }
}

fn probe_id() -> u16 {
    use ring::rand::SecureRandom;
    let mut id = [0u8; 2];
    let _ = ring::rand::SystemRandom::new().fill(&mut id);
    u16::from_be_bytes(id)
}

fn rcode_name(rcode: u8) -> String {
    match rcode {
        1 => "FORMERR".into(),
        2 => "SERVFAIL".into(),
        4 => "NOTIMP".into(),
        5 => "REFUSED (it doesn't serve this box)".into(),
        other => format!("rcode {other}"),
    }
}

/// An upstream as people name it, for messages about one that didn't build.
fn describe(cfg: &UpstreamConfig) -> String {
    match cfg {
        UpstreamConfig::Plain { address, port, .. } => format!("{address}:{port}"),
        UpstreamConfig::Tls { address, port, .. } => format!("dot://{address}:{port}"),
        UpstreamConfig::Https { url, .. } => url.clone(),
        UpstreamConfig::Quic { address, port, .. } => format!("doq://{address}:{port}"),
    }
}

/// Every upstream as it will be saved: addresses that are IPs, a `tls_name`
/// that is a host name (or an IP the certificate carries), an `https` URL.
/// Stricter than [`UpstreamPool::from_config`], which takes what an existing
/// config holds rather than stop a box at start.
pub fn check(configs: &[UpstreamConfig]) -> Result<()> {
    for (i, cfg) in configs.iter().enumerate() {
        check_one(cfg).map_err(|why| {
            FeriteError::Config(format!("upstream {} ({}): {why}", i + 1, describe(cfg)))
        })?;
    }
    Ok(())
}

/// [`check`] for one upstream, the reason alone.
pub fn check_one(cfg: &UpstreamConfig) -> std::result::Result<(), String> {
    let ip = |address: &str| {
        address
            .parse::<IpAddr>()
            .map(|_| ())
            .map_err(|_| format!("address '{address}' isn't an IP address"))
    };
    match cfg {
        UpstreamConfig::Plain { address, .. } => ip(address),
        UpstreamConfig::Tls {
            address, tls_name, ..
        }
        | UpstreamConfig::Quic {
            address, tls_name, ..
        } => {
            ip(address)?;
            check_tls_name(tls_name)
        }
        UpstreamConfig::Https { url, bootstrap_ip } => {
            let parsed =
                reqwest::Url::parse(url).map_err(|e| format!("URL '{url}' doesn't parse: {e}"))?;
            if parsed.scheme() != "https" {
                return Err(format!("URL '{url}' must start with https://"));
            }
            match bootstrap_ip.as_deref().map(str::trim) {
                Some(b) if !b.is_empty() => ip(b),
                _ => Ok(()),
            }
        }
    }
}

/// The name the certificate is checked against, and the SNI: a host name, or
/// an IP address when the certificate carries that IP.
pub fn check_tls_name(name: &str) -> std::result::Result<(), String> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err("tls_name is empty: give the server's host name, e.g. dns.quad9.net".into());
    }
    if trimmed != name {
        return Err(format!("tls_name '{name}' has spaces around it"));
    }
    if let Some((_, rest)) = name.split_once("://") {
        let host = rest.split(['/', ':']).next().unwrap_or(rest);
        return Err(format!(
            "tls_name '{name}' has a scheme: give just the host name, '{host}'"
        ));
    }
    if name.contains('/') {
        return Err(format!(
            "tls_name '{name}' has a path: give just the host name"
        ));
    }
    if name.parse::<IpAddr>().is_err() && name.contains(':') {
        return Err(format!(
            "tls_name '{name}' has a port: give just the host name; the port has its own field"
        ));
    }
    ServerName::try_from(name)
        .map(|_| ())
        .map_err(|_| format!("tls_name '{name}' isn't a host name"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::egress::no_proxy;

    fn quic(tls_name: &str) -> UpstreamConfig {
        UpstreamConfig::Quic {
            address: "138.199.149.249".into(),
            port: 853,
            tls_name: tls_name.into(),
        }
    }

    #[test]
    fn a_tls_name_is_a_host_name_or_an_ip() {
        for good in [
            "blank.dnsforge.de",
            "dot.sb",
            "45.11.45.11",
            "2606:4700:4700::1111",
        ] {
            assert_eq!(check_tls_name(good), Ok(()), "{good}");
        }
        for (bad, says) in [
            (
                "quic://blank.dnsforge.de",
                "give just the host name, 'blank.dnsforge.de'",
            ),
            (
                "tls://dns.quad9.net:853/",
                "give just the host name, 'dns.quad9.net'",
            ),
            ("dns.quad9.net:853", "has a port"),
            ("dns.quad9.net/dns-query", "has a path"),
            (" dot.sb", "spaces"),
            ("", "is empty"),
            ("not a name", "isn't a host name"),
        ] {
            let e = check_tls_name(bad).unwrap_err();
            assert!(e.contains(says), "{bad}: {e}");
        }
    }

    #[test]
    fn the_check_names_the_upstream_that_is_wrong() {
        let configs = vec![
            UpstreamConfig::Plain {
                address: "9.9.9.9".into(),
                port: 53,
                egress: None,
            },
            quic("quic://blank.dnsforge.de"),
        ];
        let e = check(&configs).unwrap_err().to_string();
        assert!(e.contains("upstream 2 (doq://138.199.149.249:853)"), "{e}");
        assert!(e.contains("'blank.dnsforge.de'"), "{e}");

        let https = |url: &str| UpstreamConfig::Https {
            url: url.into(),
            bootstrap_ip: None,
        };
        assert!(check(&[https("https://dns.quad9.net/dns-query")]).is_ok());
        assert!(check(&[https("http://dns.quad9.net/dns-query")]).is_err());
        let plain_name = UpstreamConfig::Plain {
            address: "dns.quad9.net".into(),
            port: 53,
            egress: None,
        };
        assert!(
            check(&[plain_name])
                .unwrap_err()
                .to_string()
                .contains("isn't an IP")
        );
    }

    #[test]
    fn a_failing_upstream_rests_longer_each_time() {
        assert_eq!(rest_for(1), Duration::from_secs(10));
        assert_eq!(rest_for(2), Duration::from_secs(20));
        assert_eq!(rest_for(5), Duration::from_secs(160));
        assert_eq!(rest_for(6), LONGEST_REST);
        assert_eq!(rest_for(60), LONGEST_REST);
    }

    /// A UDP "resolver" on localhost answering every query (QR set), counting
    /// them.
    async fn answering() -> (u16, Arc<AtomicUsize>) {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();
        let count = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&count);
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            while let Ok((n, from)) = socket.recv_from(&mut buf).await {
                seen.fetch_add(1, Ordering::SeqCst);
                buf[2] |= 0x80;
                let _ = socket.send_to(&buf[..n], from).await;
            }
        });
        (port, count)
    }

    /// A port nothing answers on: a bound socket that never replies.
    async fn silent() -> (u16, tokio::net::UdpSocket) {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        (socket.local_addr().unwrap().port(), socket)
    }

    fn plain(port: u16) -> UpstreamConfig {
        UpstreamConfig::Plain {
            address: "127.0.0.1".into(),
            port,
            egress: None,
        }
    }

    fn query() -> Vec<u8> {
        vec![0x12, 0x34, 0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1]
    }

    #[tokio::test]
    async fn a_failed_upstream_is_asked_after_the_others_until_its_rest_is_over() {
        crate::install_default_crypto();
        let (good, answers) = answering().await;
        // A refused port fails at once over UDP: nothing listens there.
        let refused = {
            let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            s.local_addr().unwrap().port()
        };
        let pool = UpstreamPool::from_config(&[plain(refused), plain(good)], no_proxy()).unwrap();
        assert_eq!(pool.status()[0].state, "unknown");

        for _ in 0..6 {
            pool.resolve_raw(query()).await.unwrap();
        }
        assert_eq!(answers.load(Ordering::SeqCst), 6);
        let status = pool.status();
        assert_eq!(status[0].state, "failing");
        assert!(status[0].last_error.is_some());
        assert!(status[0].retry_in.is_some_and(|s| s <= 10));
        assert_eq!(status[1].state, "ok");
        assert!(status[1].latency_ms.is_some());

        // Resting: every query goes to the one that answers first. The failed
        // one was tried only once, on its first turn.
        let failures = pool.upstreams[0].health.lock().unwrap().failures;
        assert_eq!(failures, 1);

        // Its rest over, one query tries it again.
        pool.upstreams[0].health.lock().unwrap().rest_until = Some(Instant::now());
        pool.resolve_raw(query()).await.unwrap();
        pool.resolve_raw(query()).await.unwrap();
        let h = pool.upstreams[0].health.lock().unwrap();
        assert_eq!(h.failures, 2, "tried once more, not by every query");
        assert!(h.rest_until.unwrap() > Instant::now() + Duration::from_secs(15));
    }

    #[tokio::test]
    async fn a_probe_says_it_answered_or_why_not() {
        crate::install_default_crypto();
        let (good, _) = answering().await;
        let r = probe(&plain(good), &no_proxy(), Duration::from_secs(10)).await;
        assert!(r.ok, "{r:?}");
        assert!(r.ms.is_some());
        assert_eq!(r.label, format!("127.0.0.1:{good}"));

        let (quiet, _socket) = silent().await;
        let r = tokio::time::timeout(
            Duration::from_secs(20),
            probe(&plain(quiet), &no_proxy(), Duration::from_secs(2)),
        )
        .await
        .unwrap();
        assert!(!r.ok);
        assert!(r.error.is_some(), "{r:?}");

        let r = probe(&quic("quic://x.test"), &no_proxy(), Duration::from_secs(10)).await;
        assert!(!r.ok);
        assert!(r.error.unwrap().contains("invalid server name"));
    }
}
