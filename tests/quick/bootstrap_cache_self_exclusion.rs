//! #269 wiring: a node restarted on a persistent bootstrap cache must not
//! load, store or select its own entry, and must not keep IPv4-mapped
//! addresses. Loopback only; the cached addresses are data and are never
//! dialled.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use ant_quic::bootstrap_cache::{BootstrapCache, BootstrapCacheConfig, CachedPeer, PeerSource};
use ant_quic::{Node, NodeConfig, PeerId, derive_peer_id_from_public_key, generate_ml_dsa_keypair};
use std::net::SocketAddr;
use tempfile::TempDir;

fn cache_config(dir: &TempDir) -> BootstrapCacheConfig {
    BootstrapCacheConfig::builder()
        .cache_dir(dir.path())
        .min_peers_to_save(1)
        .build()
}

fn addr(s: &str) -> SocketAddr {
    s.parse().expect("socket addr")
}

#[tokio::test]
async fn restarted_node_never_loads_stores_or_selects_its_own_cache_entry() {
    let dir = TempDir::new().expect("tempdir");
    let (public_key, secret_key) = generate_ml_dsa_keypair().expect("keypair");
    let own = derive_peer_id_from_public_key(&public_key);
    let other = PeerId([0x42; 32]);

    // A previous run of this node ingested its own announcement and wrote it
    // to disk, together with a v4-mapped address for another peer.
    {
        let cache = BootstrapCache::open(cache_config(&dir))
            .await
            .expect("seed cache");
        cache
            .upsert(CachedPeer::new(
                own,
                vec![addr("127.0.0.1:9269")],
                PeerSource::Connection,
            ))
            .await;
        cache
            .upsert(CachedPeer::new(
                other,
                vec![addr("[::ffff:127.0.0.1]:9270")],
                PeerSource::Connection,
            ))
            .await;
        cache.save().await.expect("save seed cache");
    }

    let node = Node::with_config(
        NodeConfig::builder()
            .bind_addr(addr("127.0.0.1:0"))
            .mdns_enabled(false)
            .keypair(public_key, secret_key)
            .bootstrap_cache(cache_config(&dir))
            .build(),
    )
    .await
    .expect("node");
    assert_eq!(node.peer_id(), own);
    let cache = node.bootstrap_cache();

    assert!(
        !cache.contains(&own).await,
        "the restarted node loaded its own cache entry"
    );
    let reloaded = cache.get(&other).await.expect("other peer reloads");
    assert_eq!(
        reloaded.addresses,
        vec![addr("127.0.0.1:9270")],
        "a v4-mapped cached address must load as plain IPv4"
    );

    // Live ingestion of the node's own announcement is refused.
    cache
        .upsert(CachedPeer::new(
            own,
            vec![addr("127.0.0.1:9269")],
            PeerSource::Connection,
        ))
        .await;
    assert!(
        !cache.contains(&own).await,
        "the node stored its own announcement"
    );
    assert!(
        cache
            .all_peers()
            .await
            .iter()
            .all(|peer| peer.peer_id != own),
        "the node's own entry is a dial candidate"
    );

    node.shutdown().await;
}
