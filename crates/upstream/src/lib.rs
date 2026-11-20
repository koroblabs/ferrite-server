pub mod doh;
pub mod doq;
pub mod egress;
pub mod plain;
pub mod pool;
pub mod stream;
pub mod tunneled;
pub mod zone_router;

pub use egress::{
    EgressConn, EgressConnectError, EgressConnectFuture, EgressConnector, ProxyHandle, no_proxy,
};
pub use pool::{
    ProbeResult, UpstreamPool, UpstreamStatus, check, check_one, check_tls_name, probe,
};
pub use zone_router::ZoneRouter;

/// Install *ring* as the process-wide rustls crypto provider. Must run before
/// the first TLS connection is built.
///
/// Every rustls user in the tree is compiled without a built-in provider, so
/// that only one crypto stack (ring, already required by hickory's `*-ring`
/// features) ends up in the binary instead of aws-lc alongside it. The cost of
/// that is exactly this call: `reqwest` resolves its provider from the process
/// default, and would fail to build a client if nothing installed one.
///
/// Idempotent — a second call (or a provider installed by someone else) is
/// ignored rather than treated as an error.
pub fn install_default_crypto() {
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
}

/// A TLS error as people read it: rustls lists every name a certificate is
/// good for (Quad9's has 60), as `DnsName("…")` and `IpAddress(…)`. The
/// first few, plainly, are enough to see the right one.
pub(crate) fn tidy_tls(why: &str) -> String {
    const SHOWN: usize = 3;
    let marker = "certificate is only valid for ";
    let Some(at) = why.find(marker) else {
        return why.to_string();
    };
    let (head, list) = why.split_at(at + marker.len());
    let names: Vec<String> = list
        .split(", ")
        .flat_map(|part| part.split(" or "))
        .map(|name| {
            let name = name
                .trim()
                .trim_start_matches("DnsName(")
                .trim_start_matches("IpAddress(")
                .trim_end_matches(')');
            name.trim_matches('"').to_string()
        })
        .collect();
    let more = names.len().saturating_sub(SHOWN);
    let shown = names.into_iter().take(SHOWN).collect::<Vec<_>>().join(", ");
    if more > 0 {
        format!("{head}{shown} and {more} more")
    } else {
        format!("{head}{shown}")
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_long_certificate_name_list_is_cut_short() {
        let quad9 = r#"invalid peer certificate: certificate not valid for name "dns.google"; certificate is only valid for DnsName("dns.quad9.net"), DnsName("dns-nosec.quad9.net"), DnsName("doh-brave.quad9.net"), IpAddress(9.9.9.9), IpAddress(2620:fe::fe:15) or IpAddress(2620:fe::fe:64)"#;
        assert_eq!(
            super::tidy_tls(quad9),
            r#"invalid peer certificate: certificate not valid for name "dns.google"; certificate is only valid for dns.quad9.net, dns-nosec.quad9.net, doh-brave.quad9.net and 3 more"#
        );
        let one = r#"certificate not valid for name "x"; certificate is only valid for DnsName("doq.test")"#;
        assert_eq!(
            super::tidy_tls(one),
            r#"certificate not valid for name "x"; certificate is only valid for doq.test"#
        );
        assert_eq!(super::tidy_tls("connection reset"), "connection reset");
    }
}
