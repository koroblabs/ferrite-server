//! DNS over HTTPS over HTTP/3: QUIC, on the UDP side of the DNS over HTTPS
//! port. A device that has asked over HTTP/1.1 or HTTP/2 learns of it from
//! the `Alt-Svc` header and moves over: one UDP flow where a lost packet
//! holds up only its own query, and a reconnect that costs less — what a
//! phone on a poor mobile network notices. The requests are the ones of
//! [`crate::doh`]; the QUIC side (endpoint, certificate, handshake) is
//! [`crate::quic`]'s.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use http::StatusCode;

use crate::Serving;
use crate::doh::{self, Query, Reply};

type Stream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

/// HTTP/3 on a connection the handshake settled on `h3` for.
pub(crate) async fn serve(
    conn: quinn::Connection,
    peer: SocketAddr,
    sni_id: Option<String>,
    serving: &Serving,
) {
    let Ok(mut h3) = h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(conn)).await
    else {
        return;
    };
    loop {
        match h3.accept().await {
            Ok(Some(resolver)) => {
                let (ctx, gate, sni_id) = (
                    Arc::clone(&serving.ctx),
                    Arc::clone(&serving.gate),
                    sni_id.clone(),
                );
                tokio::spawn(async move {
                    let Ok((req, mut stream)) = resolver.resolve_request().await else {
                        return;
                    };
                    let reply = request(&req, &mut stream, peer, sni_id, ctx, &gate).await;
                    send(&mut stream, reply).await;
                });
            }
            Ok(None) => break,
            Err(e) => {
                tracing::debug!("doh3: connection from {peer} ended: {e}");
                break;
            }
        }
    }
}

async fn request(
    req: &http::Request<()>,
    stream: &mut Stream,
    peer: SocketAddr,
    sni_id: Option<String>,
    ctx: Arc<ferrite_dns::ctx::DnsCtx>,
    gate: &crate::gate::Gate,
) -> Reply {
    let (client_id, query) = match doh::read_head(req.method(), req.uri(), req.headers(), sni_id) {
        Ok(asked) => asked,
        Err(reply) => return reply,
    };
    let raw = match query {
        Query::InUrl(raw) => raw,
        Query::InBody => {
            let mut body = BytesMut::new();
            loop {
                match stream.recv_data().await {
                    Ok(Some(chunk)) => {
                        if body.len() + chunk.remaining() > doh::MAX_MESSAGE {
                            return doh::too_large();
                        }
                        body.put(chunk);
                    }
                    Ok(None) => break,
                    Err(_) => {
                        return Reply {
                            status: StatusCode::BAD_REQUEST,
                            content_type: "text/plain; charset=utf-8",
                            body: Bytes::from_static(b"the body didn't arrive\n"),
                        };
                    }
                }
            }
            body.to_vec()
        }
    };
    doh::resolve(raw, client_id.as_deref(), peer, ctx, gate).await
}

async fn send(stream: &mut Stream, reply: Reply) {
    let Ok(head) = reply.head().body(()) else {
        return;
    };
    if stream.send_response(head).await.is_err() {
        return;
    }
    let _ = stream.send_data(reply.body).await;
    let _ = stream.finish().await;
}
