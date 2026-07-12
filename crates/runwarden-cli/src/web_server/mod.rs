mod api;
mod reviewer_nonce;
mod sse;

use std::net::SocketAddr;

use anyhow::{Context, ensure};
use axum::Router;
use runwarden_state::StateStore;

use reviewer_nonce::ReviewerNonce;

pub const REVIEWER_NONCE_HEADER: &str = "X-Runwarden-Reviewer-Nonce";
pub(crate) const REVIEWER_NONCE_HEADER_LOWER: &str = "x-runwarden-reviewer-nonce";

#[derive(Clone)]
pub struct ReviewerApiState {
    pub(crate) store: StateStore,
    pub(crate) nonce: ReviewerNonce,
    pub(crate) accepted_origin: String,
}

impl ReviewerApiState {
    pub fn new(store: StateStore, listen_addr: SocketAddr) -> anyhow::Result<Self> {
        ensure!(
            listen_addr.ip().is_loopback(),
            "reviewer API must listen on a loopback address"
        );
        let nonce = ReviewerNonce::generate()
            .map_err(|error| anyhow::anyhow!("generate reviewer nonce: {error}"))?;
        let accepted_origin = loopback_origin(listen_addr);
        ensure!(
            accepted_origin.is_ascii(),
            "reviewer accepted origin must be ASCII"
        );
        Ok(Self {
            store,
            nonce,
            accepted_origin,
        })
    }

    pub fn accepted_origin(&self) -> &str {
        &self.accepted_origin
    }

    pub fn encoded_nonce(&self) -> String {
        self.nonce.encoded()
    }
}

fn loopback_origin(listen_addr: SocketAddr) -> String {
    let host = match listen_addr.ip() {
        std::net::IpAddr::V4(address) => address.to_string(),
        std::net::IpAddr::V6(address) => format!("[{address}]"),
    };
    if listen_addr.port() == 80 {
        format!("http://{host}")
    } else {
        format!("http://{host}:{}", listen_addr.port())
    }
}

pub fn reviewer_router(state: ReviewerApiState) -> Router {
    api::routes()
        .merge(sse::routes())
        .with_state(state)
        .layer(axum::extract::DefaultBodyLimit::max(16 * 1_024))
}

pub fn reviewer_state_for_listener(
    state_dir: impl AsRef<std::path::Path>,
    listen_addr: SocketAddr,
) -> anyhow::Result<ReviewerApiState> {
    let store = StateStore::open(state_dir).context("open native reviewer state")?;
    ReviewerApiState::new(store, listen_addr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reviewer_state_rejects_non_loopback_listeners() {
        let temp = tempfile::tempdir().unwrap();
        let store = StateStore::open(temp.path().join("state")).unwrap();
        let address = "0.0.0.0:8088".parse().unwrap();

        assert!(ReviewerApiState::new(store, address).is_err());
    }

    #[test]
    fn accepted_origin_uses_browser_origin_serialization() {
        assert_eq!(
            loopback_origin("127.0.0.1:80".parse().unwrap()),
            "http://127.0.0.1"
        );
        assert_eq!(
            loopback_origin("[::1]:8088".parse().unwrap()),
            "http://[::1]:8088"
        );
    }
}
