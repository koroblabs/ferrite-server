//! DNS over QUIC (RFC 9250): each query on a QUIC stream of its own — the
//! message with a two-byte length in front, then the end of the stream — and
//! its answer back on the same stream the same way. As with HTTP/3, a lost
//! packet holds up only its own query; unlike it, there's no HTTP around the
//! message. The device names itself in the TLS name, as over TLS
//! (`kid.dns.example.com`). On the UDP side of the DNS over TLS port.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::time::timeout;

use ferrite_dns::ctx::DnsCtx;

use crate::Serving;
use crate::gate::Gate;

/// The query has this long to arrive whole once its stream opened.
const BODY: Duration = Duration::from_secs(10);
const MAX_MESSAGE: usize = 65_535;

/// RFC 9250 §4.3 error codes.
const DOQ_INTERNAL_ERROR: u32 = 0x1;
const DOQ_PROTOCOL_ERROR: u32 = 0x2;
const DOQ_EXCESSIVE_LOAD: u32 = 0x4;

/// DNS over QUIC on a connection the handshake settled on `doq` for.
pub(crate) async fn serve(
    conn: quinn::Connection,
    peer: SocketAddr,
    client_id: Option<String>,
    serving: &Serving,
) {
    // As over TLS: a proxy passing QUIC on can't say whose it is.
    if serving.gate.trusts(peer.ip()) {
        tracing::warn!(
            "doq: {peer} is a proxy, which can't say who it forwards for over DNS over QUIC; \
             forward the UDP port to this box directly"
        );
        conn.close(DOQ_PROTOCOL_ERROR.into(), b"proxy");
        return;
    }
    // Until the device goes quiet (the idle timeout) or closes it.
    while let Ok((send, recv)) = conn.accept_bi().await {
        let (ctx, gate, id) = (
            Arc::clone(&serving.ctx),
            Arc::clone(&serving.gate),
            client_id.clone(),
        );
        tokio::spawn(stream(send, recv, peer, id, ctx, gate));
    }
}

/// One query and its answer.
async fn stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    peer: SocketAddr,
    client_id: Option<String>,
    ctx: Arc<DnsCtx>,
    gate: Arc<Gate>,
) {
    let raw = match timeout(BODY, recv.read_to_end(MAX_MESSAGE + 2)).await {
        Ok(Ok(raw)) => raw,
        _ => {
            let _ = send.reset(DOQ_PROTOCOL_ERROR.into());
            return;
        }
    };
    let Some(query) = unframe(&raw) else {
        let _ = send.reset(DOQ_PROTOCOL_ERROR.into());
        return;
    };
    let answer = if gate.allows(peer.ip(), client_id.as_deref()) {
        // The box-wide cap on queries waiting for upstream, as over TCP.
        let Ok(permit) = Arc::clone(&ctx.query_semaphore).try_acquire_owned() else {
            tracing::warn!("query concurrency limit reached, turning a DoQ query from {peer} away");
            let _ = send.reset(DOQ_EXCESSIVE_LOAD.into());
            return;
        };
        let answer =
            ferrite_dns::handler::handle_query_as(query, peer, client_id.as_deref(), ctx).await;
        drop(permit);
        answer.unwrap_or_default()
    } else {
        ferrite_dns::handler::refused(&query)
    };
    if answer.is_empty() || answer.len() > MAX_MESSAGE {
        let _ = send.reset(DOQ_INTERNAL_ERROR.into());
        return;
    }
    let mut framed = Vec::with_capacity(answer.len() + 2);
    framed.extend_from_slice(&(answer.len() as u16).to_be_bytes());
    framed.extend_from_slice(&answer);
    // A finished stream still delivers what it holds once dropped, for as
    // long as the connection lasts.
    if send.write_all(&framed).await.is_ok() {
        let _ = send.finish();
    }
}

/// The message out of a stream's whole content: its length, then exactly
/// that many bytes.
fn unframe(raw: &[u8]) -> Option<Vec<u8>> {
    let (len, message) = raw.split_first_chunk::<2>()?;
    let len = u16::from_be_bytes(*len) as usize;
    (len != 0 && message.len() == len).then(|| message.to_vec())
}

#[cfg(test)]
mod tests {
    use super::unframe;

    #[test]
    fn a_stream_holds_one_whole_message() {
        assert_eq!(unframe(&[0, 3, 1, 2, 3]), Some(vec![1, 2, 3]));
        // Short, long, empty, or no length at all: not a query.
        assert_eq!(unframe(&[0, 4, 1, 2, 3]), None);
        assert_eq!(unframe(&[0, 2, 1, 2, 3]), None);
        assert_eq!(unframe(&[0, 0]), None);
        assert_eq!(unframe(&[7]), None);
        assert_eq!(unframe(&[]), None);
    }
}
