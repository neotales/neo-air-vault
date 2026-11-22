//! Loopback health listener for neo-air-vault.
//!
//! This crate does not store, encrypt, wrap, or return secrets. A successful
//! health response means the process is running. It does not mean a vault exists.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;

/// Address the process binds. Loopback only. `NAV_LISTEN` is not read.
pub const LISTEN_ADDR: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8787);

/// Health body. `vault` is always false. There is no constructor that says otherwise.
#[derive(Debug, Serialize)]
pub struct Health {
    status: &'static str,
    vault: bool,
}

impl Health {
    /// The only health report this process is allowed to make.
    #[must_use]
    pub const fn not_a_vault() -> Self {
        Self {
            status: "ok",
            vault: false,
        }
    }
}

/// Routes this process serves. `/health` is the only route.
pub fn router() -> Router {
    Router::new().route("/health", get(health))
}

async fn health() -> Json<Health> {
    Json(Health::not_a_vault())
}

/// Bind [`LISTEN_ADDR`] and serve [`router`]. This does not open a store.
///
/// # Errors
///
/// Returns the listener error. The error is an address or I/O failure, not a secret.
pub async fn serve() -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(LISTEN_ADDR).await?;
    axum::serve(listener, router()).await
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use super::{Health, LISTEN_ADDR, router};

    #[test]
    fn listen_addr_is_loopback() {
        assert!(LISTEN_ADDR.ip().is_loopback());
        assert_eq!(LISTEN_ADDR.port(), 8787);
    }

    #[test]
    fn health_cannot_claim_a_vault() {
        let health = Health::not_a_vault();
        assert!(!health.vault);
        let body = serde_json::to_string(&health).expect("health serializes");
        assert_eq!(body, r#"{"status":"ok","vault":false}"#);
    }

    #[tokio::test]
    async fn health_route_is_not_a_vault() {
        let response = router()
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let text = String::from_utf8(bytes.to_vec()).expect("utf-8");
        assert_eq!(text, r#"{"status":"ok","vault":false}"#);
        let lower = text.to_ascii_lowercase();
        assert!(!lower.contains("password"));
        assert!(!lower.contains("secret"));
    }

    #[tokio::test]
    async fn other_routes_are_not_a_vault() {
        let response = router()
            .oneshot(
                Request::builder()
                    .uri("/secrets")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
