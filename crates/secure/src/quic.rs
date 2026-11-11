//! QUIC for encrypted DNS: one endpoint per UDP port, speaking HTTP/3 (DNS
//! over HTTPS, [`crate::doh3`]) or DNS over QUIC ([`crate::doq`]), whichever
//! the device asks for by ALPN and the port offers. HTTP/3 is on the UDP side
//! of the DNS over HTTPS port, DNS over QUIC on that of the DNS over TLS one;
//! where the two are the same port, its one endpoint takes both. QUIC doesn't
//! pass through a reverse proxy: away from home, the router sends the UDP
//! port straight to this box.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio_rustls::rustls;
use tokio_rustls::rustls::server::{ClientHello, ResolvesServerCert};
use tokio_rustls::rustls::sign::CertifiedKey;

use crate::{Serving, client_id_from_sni, is_ours};

pub(crate) const ALPN_H3: &[u8] = b"h3";
pub(crate) const ALPN_DOQ: &[u8] = b"doq";

/// A connection with nothing to say this long is closed; the device opens
/// another when it next asks.
const IDLE: Duration = Duration::from_secs(30);
/// The handshake has this long.
const HANDSHAKE: Duration = Duration::from_secs(10);

/// The certificate, but only for our own name: a device sent to this
/// address for another site (a routed name, away from home) is turned down
/// in the handshake instead of shown a certificate that isn't that site's.
#[derive(Debug)]
struct OnlyOurs {
    certs: Arc<dyn ResolvesServerCert>,
    hostname: String,
}

impl ResolvesServerCert for OnlyOurs {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        if hello
            .server_name()
            .is_some_and(|sni| !is_ours(sni, &self.hostname))
        {
            return None;
        }
        self.certs.resolve(hello)
    }
}

/// QUIC with TLS 1.3 for `hostname`, offering the protocols in `alpn`.
pub(crate) fn server_config(
    certs: Arc<dyn ResolvesServerCert>,
    hostname: &str,
    alpn: &[&[u8]],
) -> Result<quinn::ServerConfig, String> {
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|e| format!("TLS setup failed: {e}"))?
    .with_no_client_auth()
    .with_cert_resolver(Arc::new(OnlyOurs {
        certs,
        hostname: hostname.to_string(),
    }));
    tls.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
        .map_err(|e| format!("QUIC setup failed: {e}"))?;
    let mut cfg = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(IDLE.try_into().ok());
    // HTTP/3 takes a stream per request, DNS over QUIC one per query: this
    // many of either in flight on one connection.
    transport.max_concurrent_bidi_streams(64u32.into());
    cfg.transport_config(Arc::new(transport));
    Ok(cfg)
}

/// UDP `port` on every address, both families where the box has IPv6.
pub(crate) fn bind(port: u16, cfg: quinn::ServerConfig) -> std::io::Result<quinn::Endpoint> {
    match quinn::Endpoint::server(cfg.clone(), SocketAddr::from((Ipv6Addr::UNSPECIFIED, port))) {
        Err(e) if e.kind() != std::io::ErrorKind::AddrInUse => {
            quinn::Endpoint::server(cfg, SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)))
        }
        other => other,
    }
}

pub(crate) async fn accept_loop(endpoint: quinn::Endpoint, serving: Arc<Serving>) {
    while let Some(incoming) = endpoint.accept().await {
        let Ok(slot) = Arc::clone(&serving.connections).try_acquire_owned() else {
            incoming.refuse(); // full
            continue;
        };
        let serving = Arc::clone(&serving);
        tokio::spawn(async move {
            connection(incoming, &serving).await;
            drop(slot);
        });
    }
}

async fn connection(incoming: quinn::Incoming, serving: &Serving) {
    let conn = match tokio::time::timeout(HANDSHAKE, incoming).await {
        Ok(Ok(conn)) => conn,
        _ => return,
    };
    let peer = conn.remote_address();
    let peer = SocketAddr::new(ferrite_core::net::unmap_v4(peer.ip()), peer.port());
    let handshake = conn
        .handshake_data()
        .and_then(|d| d.downcast::<quinn::crypto::rustls::HandshakeData>().ok());
    let sni_id = handshake
        .as_ref()
        .and_then(|d| d.server_name.as_deref())
        .and_then(|sni| client_id_from_sni(sni, &serving.hostname));
    // The handshake only completes on a protocol both sides named.
    match handshake.and_then(|d| d.protocol) {
        Some(p) if p == ALPN_DOQ => crate::doq::serve(conn, peer, sni_id, serving).await,
        _ => crate::doh3::serve(conn, peer, sni_id, serving).await,
    }
}
