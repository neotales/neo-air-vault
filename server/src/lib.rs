//! Loopback health listener for neo-air-vault.
//!
//! This crate does not store, encrypt, wrap, or return secrets. A successful
//! health response means the process is running. It does not mean a vault exists.
//!
//! [`app`] adds the authenticated application: accounts, groups, permissions,
//! and memberships kept in SQLite through `neotales-x-auth-store-sqlite`. That
//! is identity data, not secret material; the store is not a vault either.

mod auth;

pub use auth::{
    ADMIN_FILE, DEFAULT_DATABASE, KEY_FILE, KEY_LEN, Settings, StartupError, app, app_with,
};
// The two header parsers are public so the fuzz target can call them; nothing
// else in this module is exported.
pub use auth::{cookie, origin_matches};

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

/// Routes this process serves without a store. `/health` is always present.
///
/// The `embed-ui` feature also serves the built web client. That client is
/// not a vault. The page is one route: `/` and an empty path serve
/// `index.html`. Any other missing path, including `/secrets`, is 404.
/// [`app`] mounts this health route together with the auth routes and sets
/// the file handler last, so a matched route still wins.
pub fn router() -> Router {
    let router = Router::new().route("/health", get(health));
    #[cfg(feature = "embed-ui")]
    let router = router.fallback(ui::file);
    router
}

#[cfg(feature = "embed-ui")]
mod ui {
    use axum::body::Body;
    use axum::http::{HeaderValue, StatusCode, Uri, header};
    use axum::response::Response;
    use include_dir::{Dir, include_dir};

    static UI: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/../web/build");

    /// Serve one built file.
    ///
    /// `/` and an empty path are the page (`index.html`). An existing file in
    /// the build is served as itself. Any other path is 404. This is not a
    /// client-side router: `/secrets` is not the page.
    pub async fn file(uri: Uri) -> Response {
        let path = uri.path().trim_start_matches('/');
        let path = if path.is_empty() { "index.html" } else { path };
        if let Some(file) = UI.get_file(path) {
            return response(StatusCode::OK, path, file.contents());
        }
        Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::empty())
            .expect("empty response")
    }

    fn response(status: StatusCode, path: &str, bytes: &[u8]) -> Response {
        let mut response = Response::builder().status(status);
        if let Some(kind) = content_type(path) {
            response = response.header(header::CONTENT_TYPE, HeaderValue::from_static(kind));
        }
        response.body(Body::from(bytes.to_vec())).expect("body")
    }

    fn content_type(path: &str) -> Option<&'static str> {
        match path.rsplit('.').next() {
            Some("html") => Some("text/html; charset=utf-8"),
            Some("css") => Some("text/css; charset=utf-8"),
            Some("js") => Some("text/javascript; charset=utf-8"),
            Some("svg") => Some("image/svg+xml"),
            Some("json") => Some("application/json"),
            Some("txt") => Some("text/plain; charset=utf-8"),
            _ => None,
        }
    }
}

pub(crate) async fn health() -> Json<Health> {
    Json(Health::not_a_vault())
}

/// Open the store, bootstrap the tenant and administrator, bind [`LISTEN_ADDR`],
/// and serve [`app`].
///
/// # Errors
///
/// Returns [`StartupError`] when the store, key, bootstrap, or listener fails.
/// No error message contains a password or a digest key.
pub async fn serve() -> Result<(), StartupError> {
    let listener = tokio::net::TcpListener::bind(LISTEN_ADDR)
        .await
        .map_err(StartupError::Listen)?;
    axum::serve(listener, app().await?)
        .await
        .map_err(StartupError::Listen)
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use super::{Health, LISTEN_ADDR, router};

    #[test]
    fn version_is_alpha() {
        assert_eq!(env!("CARGO_PKG_VERSION"), "0.0.0-alpha.0");
    }

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

    #[cfg(feature = "embed-ui")]
    #[tokio::test]
    async fn root_serves_the_page() {
        for uri in ["/", "/index.html"] {
            let response = router()
                .oneshot(
                    Request::builder()
                        .uri(uri)
                        .body(Body::empty())
                        .expect("request"),
                )
                .await
                .expect("response");

            assert_eq!(response.status(), StatusCode::OK, "{uri}");
            let kind = response
                .headers()
                .get(axum::http::header::CONTENT_TYPE)
                .expect("content type");
            assert_eq!(kind, "text/html; charset=utf-8");
        }
    }
}
