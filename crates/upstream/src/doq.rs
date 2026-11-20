//! DNS-over-QUIC upstream (RFC 9250), on quinn directly.
//!
//! Like [`crate::stream`] for DoT, this forwards the **raw wire query** and
//! hands back the **raw wire answer**, so DNSSEC records ride through as they
//! came — and a failure says what failed. The hickory resolver this replaces
//! reported every QUIC or TLS failure as "no connections available": its
//! name-server pool kept that placeholder over the I/O error that carried the
//! cause (an invalid name, a certificate for another name, a refused
//! handshake).
//!
//! One QUIC connection per upstream, opened on the first query and reused:
//! each query is a stream of its own on it. A connection that died while idle
//! (closed by the server, or by our own idle timeout) is replaced on the next
//! query; a query that fails on a reused connection is tried once more on a
//! fresh one.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use tokio::sync::Mutex;
use tokio::time::timeout;
use tokio_rustls::rustls::ClientConfig;

use crate::tunneled::client_config;
use ferrite_core::error::{FeriteError, Result};

const ALPN_DOQ: &[u8] = b"doq";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
const QUERY_TIMEOUT: Duration = Duration::from_secs(8);
/// We let a connection go after this long unused, so a reused one is rarely a
/// connection the server or a NAT already forgot.
const IDLE_TIMEOUT: Duration = Duration::from_secs(20);
/// The largest DNS message, and its two-byte length.
const MAX_MESSAGE: usize = u16::MAX as usize;

pub struct DoqResolver {
    addr: SocketAddr,
    /// SNI and the name the certificate must carry: as configured, checked
    /// only when connecting (so a bad one fails queries with the reason
    /// instead of stopping the box at start).
    tls_name: String,
    config: quinn::ClientConfig,
    endpoint: OnceLock<quinn::Endpoint>,
    conn: Mutex<Option<quinn::Connection>>,
    label: String,
}

impl DoqResolver {
    /// DoQ to `address:port` (a literal IP) with the certificate name `tls_name`.
    pub fn new(address: &str, port: u16, tls_name: &str) -> Result<Self> {
        Self::with_tls(address, port, tls_name, client_config()?)
    }

    pub(crate) fn with_tls(
        address: &str,
        port: u16,
        tls_name: &str,
        tls: Arc<ClientConfig>,
    ) -> Result<Self> {
        let addr: SocketAddr = format!("{address}:{port}")
            .parse()
            .or_else(|_| format!("[{address}]:{port}").parse())
            .map_err(|e| FeriteError::Config(format!("invalid DoQ address: {e}")))?;

        let mut tls = (*tls).clone();
        tls.alpn_protocols = vec![ALPN_DOQ.to_vec()];
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
            .map_err(|e| FeriteError::Config(format!("DoQ TLS setup: {e}")))?;
        let mut config = quinn::ClientConfig::new(Arc::new(crypto));
        let mut transport = quinn::TransportConfig::default();
        transport.max_idle_timeout(IDLE_TIMEOUT.try_into().ok());
        config.transport_config(Arc::new(transport));

        Ok(Self {
            addr,
            tls_name: tls_name.to_string(),
            config,
            endpoint: OnceLock::new(),
            conn: Mutex::new(None),
            label: format!("doq://{address}:{port}#{tls_name}"),
        })
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    pub async fn resolve_raw(&self, raw: Vec<u8>) -> Result<(Vec<u8>, String)> {
        if raw.len() < 12 || raw.len() > MAX_MESSAGE {
            return Err(FeriteError::Dns("not a DNS query".into()));
        }
        // RFC 9250 §4.2.1: the message ID is 0 on the wire — the stream tells
        // the answers apart. The client's goes back on the answer.
        let id = [raw[0], raw[1]];
        let mut query = raw;
        query[0] = 0;
        query[1] = 0;

        let (conn, reused) = self.connection().await?;
        let answer = match exchange(&conn, &query).await {
            Ok(answer) => answer,
            Err(_) if reused => {
                // Most likely a connection that went away while idle: once
                // more, on a fresh one.
                self.forget(&conn).await;
                let (conn, _) = self.connection().await?;
                exchange(&conn, &query).await.map_err(|e| self.error(e))?
            }
            Err(e) => return Err(self.error(e)),
        };
        let mut answer = answer;
        if answer.len() < 12 {
            return Err(self.error("the answer is too short to be DNS".into()));
        }
        answer[0] = id[0];
        answer[1] = id[1];
        Ok((answer, self.label.clone()))
    }

    /// The live connection, or a new one; `true` with one that was open already.
    async fn connection(&self) -> Result<(quinn::Connection, bool)> {
        let mut slot = self.conn.lock().await;
        if let Some(conn) = slot.as_ref()
            && conn.close_reason().is_none()
        {
            return Ok((conn.clone(), true));
        }
        let endpoint = self.endpoint()?;
        let connecting = endpoint
            .connect_with(self.config.clone(), self.addr, &self.tls_name)
            .map_err(|e| self.error(e.to_string()))?;
        let conn = timeout(CONNECT_TIMEOUT, connecting)
            .await
            .map_err(|_| self.error("QUIC handshake timed out".into()))?
            .map_err(|e| {
                let why = crate::tidy_tls(&e.to_string());
                self.error(format!("QUIC handshake: {why}{}", turned_down(&e)))
            })?;
        *slot = Some(conn.clone());
        Ok((conn, false))
    }

    async fn forget(&self, conn: &quinn::Connection) {
        let mut slot = self.conn.lock().await;
        if slot
            .as_ref()
            .is_some_and(|c| c.stable_id() == conn.stable_id())
        {
            *slot = None;
        }
    }

    /// The client socket, bound on the first connection (inside the runtime)
    /// in the upstream's address family.
    fn endpoint(&self) -> Result<&quinn::Endpoint> {
        if let Some(endpoint) = self.endpoint.get() {
            return Ok(endpoint);
        }
        let local: SocketAddr = if self.addr.is_ipv4() {
            (Ipv4Addr::UNSPECIFIED, 0).into()
        } else {
            (Ipv6Addr::UNSPECIFIED, 0).into()
        };
        let endpoint = quinn::Endpoint::client(local)
            .map_err(|e| self.error(format!("can't open a UDP socket: {e}")))?;
        Ok(self.endpoint.get_or_init(|| endpoint))
    }

    fn error(&self, what: String) -> FeriteError {
        FeriteError::Dns(format!("{}: {what}", self.label))
    }
}

/// What a handshake the server ended most likely means: its TLS alert alone
/// ("error 80") says little to whoever reads the log.
fn turned_down(e: &quinn::ConnectionError) -> &'static str {
    let text = e.to_string();
    if !(text.contains("aborted by peer") && text.contains("handshake failed")) {
        return "";
    }
    match text.rsplit("error ").next().map(str::trim) {
        Some("120") => " (the server doesn't offer DNS over QUIC here)",
        Some("112") => " (the server doesn't know this tls_name)",
        _ => " (the server turned the handshake down; often it doesn't serve this tls_name)",
    }
}

/// One query on a stream of its own: `[u16 length][message]`, the stream
/// finished, and the answer framed the same way back.
async fn exchange(conn: &quinn::Connection, query: &[u8]) -> std::result::Result<Vec<u8>, String> {
    let fut = async {
        let (mut send, mut recv) = conn.open_bi().await.map_err(|e| e.to_string())?;
        let mut framed = Vec::with_capacity(query.len() + 2);
        framed.extend_from_slice(&(query.len() as u16).to_be_bytes());
        framed.extend_from_slice(query);
        send.write_all(&framed).await.map_err(|e| e.to_string())?;
        send.finish().map_err(|e| e.to_string())?;
        let raw = recv
            .read_to_end(MAX_MESSAGE + 2)
            .await
            .map_err(|e| e.to_string())?;
        let (len, message) = raw
            .split_first_chunk::<2>()
            .ok_or("the answer stream ended empty")?;
        if message.len() != u16::from_be_bytes(*len) as usize {
            return Err("the answer's length doesn't match its framing".to_string());
        }
        Ok(message.to_vec())
    };
    timeout(QUERY_TIMEOUT, fut)
        .await
        .map_err(|_| "no answer in time".to_string())?
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio_rustls::rustls::{self, RootCertStore, pki_types::PrivatePkcs8KeyDer};

    /// A DoQ server for `name` on localhost that answers each query with its
    /// own bytes and the QR bit set, noting the IDs it saw. `close_after`
    /// closes each connection after that many answers.
    struct Server {
        addr: SocketAddr,
        roots: Arc<ClientConfig>,
        ids: Arc<std::sync::Mutex<Vec<u16>>>,
        connections: Arc<AtomicUsize>,
    }

    fn server(name: &str, close_after: Option<usize>) -> Server {
        crate::install_default_crypto();
        let cert = rcgen::generate_simple_self_signed(vec![name.to_string()]).unwrap();
        let key = PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
        let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert.cert.der().clone()], key.into())
        .unwrap();
        tls.alpn_protocols = vec![ALPN_DOQ.to_vec()];
        let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
        let endpoint = quinn::Endpoint::server(
            quinn::ServerConfig::with_crypto(Arc::new(crypto)),
            (Ipv4Addr::LOCALHOST, 0).into(),
        )
        .unwrap();
        let addr = endpoint.local_addr().unwrap();

        let ids = Arc::new(std::sync::Mutex::new(Vec::new()));
        let connections = Arc::new(AtomicUsize::new(0));
        let (seen, count) = (Arc::clone(&ids), Arc::clone(&connections));
        tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                let Ok(conn) = incoming.await else { continue };
                count.fetch_add(1, Ordering::SeqCst);
                let seen = Arc::clone(&seen);
                tokio::spawn(async move {
                    let mut answered = 0;
                    while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                        let raw = recv.read_to_end(MAX_MESSAGE + 2).await.unwrap();
                        let mut message = raw[2..].to_vec();
                        seen.lock()
                            .unwrap()
                            .push(u16::from_be_bytes([message[0], message[1]]));
                        message[2] |= 0x80;
                        let mut framed = (message.len() as u16).to_be_bytes().to_vec();
                        framed.extend_from_slice(&message);
                        send.write_all(&framed).await.unwrap();
                        send.finish().unwrap();
                        answered += 1;
                        if close_after == Some(answered) {
                            // Let the answer leave before the connection does.
                            let _ = send.stopped().await;
                            conn.close(0u32.into(), b"bye");
                            break;
                        }
                    }
                });
            }
        });

        let mut roots = RootCertStore::empty();
        roots.add(cert.cert.der().clone()).unwrap();
        let client =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth();
        Server {
            addr,
            roots: Arc::new(client),
            ids,
            connections,
        }
    }

    fn query(id: u16) -> Vec<u8> {
        let mut q = id.to_be_bytes().to_vec();
        // RD, one question: `. IN NS`.
        q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1]);
        q
    }

    fn resolver(s: &Server, name: &str) -> DoqResolver {
        DoqResolver::with_tls("127.0.0.1", s.addr.port(), name, Arc::clone(&s.roots)).unwrap()
    }

    #[tokio::test]
    async fn a_query_goes_out_with_id_zero_and_comes_back_with_its_own() {
        let s = server("doq.test", None);
        let r = resolver(&s, "doq.test");
        for id in [0x1234, 0xbeef] {
            let (answer, label) = r.resolve_raw(query(id)).await.unwrap();
            assert_eq!(u16::from_be_bytes([answer[0], answer[1]]), id);
            assert_eq!(answer[2] & 0x80, 0x80, "the server's answer");
            assert_eq!(label, format!("doq://127.0.0.1:{}#doq.test", s.addr.port()));
        }
        assert_eq!(*s.ids.lock().unwrap(), vec![0, 0]);
        assert_eq!(
            s.connections.load(Ordering::SeqCst),
            1,
            "one connection, reused"
        );
    }

    #[tokio::test]
    async fn a_connection_the_server_closed_is_replaced() {
        let s = server("doq.test", Some(1));
        let r = resolver(&s, "doq.test");
        for id in 1..=3 {
            r.resolve_raw(query(id)).await.unwrap();
        }
        assert_eq!(s.connections.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn a_certificate_for_another_name_says_so() {
        let s = server("doq.test", None);
        let r = resolver(&s, "other.test");
        let e = r.resolve_raw(query(7)).await.unwrap_err().to_string();
        assert!(e.contains("QUIC handshake"), "{e}");
        assert!(e.contains("certificate"), "{e}");
        assert!(e.contains("doq://127.0.0.1"), "{e}");
    }

    #[tokio::test]
    async fn a_name_with_a_scheme_says_it_is_invalid() {
        let s = server("doq.test", None);
        let r = resolver(&s, "quic://doq.test");
        let e = r.resolve_raw(query(7)).await.unwrap_err().to_string();
        assert!(e.contains("invalid server name"), "{e}");
    }

    #[test]
    fn a_bad_address_is_refused_at_once() {
        crate::install_default_crypto();
        assert!(DoqResolver::new("dns.example", 853, "dns.example").is_err());
        assert!(DoqResolver::new("2001:db8::1", 853, "dns.example").is_ok());
    }
}
