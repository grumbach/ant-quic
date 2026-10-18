//! Basic NAT traversal tests

#![allow(clippy::unwrap_used, clippy::expect_used)]

// Re-export common test utilities
pub use crate::utils::*;

#[cfg(test)]
mod tests {
    use ant_quic::{
        CandidateSource,
        nat_traversal_api::{CandidateAddress, CandidateValidationError},
    };
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    // Integration tests link ant_quic without cfg(test), so these exercise the
    // production privileged-port check that library unit tests bypass. The
    // strict constructor is also used by the CoordinationAccepted handler.
    fn candidate_ips() -> [IpAddr; 3] {
        let ipv4 = Ipv4Addr::new(8, 8, 8, 8);
        [
            IpAddr::V4(ipv4),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888)),
            IpAddr::V6(ipv4.to_ipv6_mapped()),
        ]
    }

    #[test]
    fn candidate_address_accepts_allowed_privileged_ports() {
        for ip in candidate_ips() {
            for port in [443, 80, 853] {
                let addr = SocketAddr::new(ip, port);
                let candidate =
                    CandidateAddress::new_with_options(addr, 0, CandidateSource::Peer, true);
                assert!(candidate.is_ok(), "{addr}: {candidate:?}");
                assert_eq!(candidate.unwrap().address, addr);

                if !matches!(ip, IpAddr::V6(ipv6) if ipv6.to_ipv4_mapped().is_some()) {
                    let candidate = CandidateAddress::new(addr, 0, CandidateSource::Peer);
                    assert!(candidate.is_ok(), "{addr}: {candidate:?}");
                    assert_eq!(candidate.unwrap().address, addr);
                }
            }
        }
    }

    #[test]
    fn candidate_address_rejects_other_privileged_ports() {
        for ip in candidate_ips() {
            for port in 1..1024 {
                if matches!(port, 443 | 80 | 853) {
                    continue;
                }
                let addr = SocketAddr::new(ip, port);
                let result =
                    CandidateAddress::new_with_options(addr, 0, CandidateSource::Peer, true);
                assert!(
                    matches!(result, Err(CandidateValidationError::PrivilegedPort(p)) if p == port),
                    "{addr}: {result:?}"
                );
            }
        }
    }

    #[test]
    fn candidate_address_port_boundaries() {
        for ip in candidate_ips() {
            let zero = SocketAddr::new(ip, 0);
            assert!(matches!(
                CandidateAddress::new_with_options(zero, 0, CandidateSource::Peer, true),
                Err(CandidateValidationError::InvalidPort(0))
            ));
            for port in [1024, 8080, u16::MAX] {
                let addr = SocketAddr::new(ip, port);
                let candidate =
                    CandidateAddress::new_with_options(addr, 0, CandidateSource::Peer, true);
                assert!(candidate.is_ok(), "{addr}: {candidate:?}");
            }
        }
    }

    #[test]
    fn candidate_address_allowed_privileged_ports_keep_address_checks() {
        use CandidateValidationError::*;

        for port in [443, 80, 853] {
            for (ip, expected) in [
                ("0.0.0.0", UnspecifiedAddress),
                ("::", UnspecifiedAddress),
                ("255.255.255.255", BroadcastAddress),
                ("224.0.0.1", MulticastAddress),
                ("ff02::1", MulticastAddress),
                ("0.1.2.3", ReservedAddress),
                ("240.0.0.1", ReservedAddress),
                ("2001:db8::1", DocumentationAddress),
                ("::ffff:8.8.8.8", IPv4MappedAddress),
            ] {
                let addr = SocketAddr::new(ip.parse().unwrap(), port);
                assert_eq!(CandidateAddress::validate_address(&addr), Err(expected));
            }
        }
    }
}
