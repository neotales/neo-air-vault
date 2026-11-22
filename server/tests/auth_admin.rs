//! The auth routes over a temporary store: bootstrap, session, and lists.

use axum::Router;
use axum::body::Body;
use axum::http::request::Builder;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

use navault_server::{KEY_LEN, Settings, app_with};

/// A fresh 32-byte digest key for one temporary database.
fn random_key() -> [u8; KEY_LEN] {
    let mut key = [0u8; KEY_LEN];
    getrandom::fill(&mut key).expect("random key");
    key
}

/// A fresh password for one temporary account.
fn random_password() -> String {
    use std::fmt::Write as _;

    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).expect("random password");
    let mut password = String::with_capacity(32);
    for byte in bytes {
        write!(&mut password, "{byte:02x}").expect("write to a string");
    }
    password
}

/// A store in `directory` with a bootstrapped administrator.
async fn boot(directory: &tempfile::TempDir, email: &str, password: &str) -> Router {
    app_with(
        Settings::new(directory.path().join("nav.sqlite"))
            .with_key(random_key())
            .with_admin(email, password),
    )
    .await
    .expect("the application starts")
}

/// One caller with a cookie jar and the response body as text.
struct Client {
    router: Router,
    session: Option<String>,
    csrf: Option<String>,
}

impl Client {
    fn new(router: Router) -> Self {
        Self {
            router,
            session: None,
            csrf: None,
        }
    }

    /// Keep a session or CSRF value the response set.
    fn remember(&mut self, response: &axum::response::Response) {
        for value in response.headers().get_all(header::SET_COOKIE) {
            let Ok(text) = value.to_str() else {
                continue;
            };
            let pair = text.split(';').next().unwrap_or("");
            let Some((name, value)) = pair.split_once('=') else {
                continue;
            };
            if value.is_empty() {
                continue;
            }
            if name == "neotales.session" {
                self.session = Some(value.to_owned());
            } else if name == "neotales.csrf" {
                self.csrf = Some(value.to_owned());
            }
        }
    }

    fn cookie_header(&self) -> Option<String> {
        let mut pairs = Vec::new();
        if let Some(session) = &self.session {
            pairs.push(format!("neotales.session={session}"));
        }
        if let Some(csrf) = &self.csrf {
            pairs.push(format!("neotales.csrf={csrf}"));
        }
        if pairs.is_empty() {
            return None;
        }
        Some(pairs.join("; "))
    }

    async fn send(&mut self, builder: Builder, body: &str) -> (StatusCode, String) {
        let request = builder.body(Body::from(body.to_owned())).expect("request");
        let response = self
            .router
            .clone()
            .oneshot(request)
            .await
            .expect("response");
        let status = response.status();
        self.remember(&response);
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        (status, String::from_utf8(bytes.to_vec()).expect("utf-8"))
    }

    async fn get(&mut self, uri: &str) -> (StatusCode, String) {
        let mut builder = Request::builder().method("GET").uri(uri);
        if let Some(cookie) = self.cookie_header() {
            builder = builder.header(header::COOKIE, cookie);
        }
        self.send(builder, "").await
    }

    /// A state-changing request with an allowed origin and the double-submit pair.
    async fn post(&mut self, uri: &str, body: &str) -> (StatusCode, String) {
        let csrf = self.csrf.clone().unwrap_or_default();
        let mut builder = Request::builder()
            .method("POST")
            .uri(uri)
            .header(header::ORIGIN, "http://127.0.0.1:5173")
            .header(header::CONTENT_TYPE, "application/json")
            .header("x-csrf-token", csrf);
        if let Some(cookie) = self.cookie_header() {
            builder = builder.header(header::COOKIE, cookie);
        }
        self.send(builder, body).await
    }

    /// Sign in, returning the status and body.
    async fn sign_in(&mut self, email: &str, password: &str) -> (StatusCode, String) {
        self.post(
            "/sign-in",
            &format!(r#"{{"email":"{email}","password":"{password}"}}"#),
        )
        .await
    }

    /// Visit the anonymous session route for a CSRF cookie.
    async fn issue_csrf(&mut self) {
        let _ = self.get("/session").await;
    }
}

/// No secret column or derived value may appear in a list body.
fn assert_no_secret_columns(body: &str) {
    let lower = body.to_ascii_lowercase();
    for forbidden in ["password", "digest", "totp", "secret", "hash"] {
        assert!(!lower.contains(forbidden), "{forbidden} in {body}");
    }
}

fn users(body: &str) -> Vec<Value> {
    let value: Value = serde_json::from_str(body).expect("json");
    value
        .get("users")
        .and_then(Value::as_array)
        .expect("users array")
        .clone()
}

#[tokio::test]
async fn health_stays_the_only_vault_claim() {
    let directory = tempfile::tempdir().expect("temp dir");
    let router = boot(&directory, "admin@example.test", &random_password()).await;
    let mut client = Client::new(router);

    let (status, body) = client.get("/health").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, r#"{"status":"ok","vault":false}"#);
}

#[tokio::test]
async fn anonymous_writes_need_a_session_even_with_a_valid_csrf_pair() {
    let directory = tempfile::tempdir().expect("temp dir");
    let router = boot(&directory, "admin@example.test", &random_password()).await;
    let mut client = Client::new(router);
    client.issue_csrf().await;
    assert!(client.csrf.is_some(), "session route sets the CSRF cookie");

    for (route, body) in [
        (
            "/sign-up",
            r#"{"email":"anon@example.test","password":"placeholder"}"#,
        ),
        ("/roles", r#"{"name":"anon-role"}"#),
        ("/permissions", r#"{"name":"anon.permission"}"#),
        ("/groups", r#"{"name":"anon-group"}"#),
        (
            "/memberships",
            r#"{"user_id":"00000000-0000-0000-0000-000000000000"}"#,
        ),
    ] {
        let (status, text) = client.post(route, body).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{route}: {text}");
    }
}

#[tokio::test]
async fn a_signed_in_caller_creates_and_lists_users_groups_and_permissions() {
    let directory = tempfile::tempdir().expect("temp dir");
    let admin_password = random_password();
    let router = boot(&directory, "admin@example.test", &admin_password).await;
    let mut client = Client::new(router);
    client.issue_csrf().await;

    let (status, body) = client.sign_in("admin@example.test", &admin_password).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(client.session.is_some(), "sign-in sets the session cookie");

    let member_password = random_password();
    let (status, body) = client
        .post(
            "/sign-up",
            &format!(r#"{{"email":"member@example.test","password":"{member_password}"}}"#),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert!(body.contains("member@example.test"));

    let (status, body) = client.post("/groups", r#"{"name":"ops"}"#).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    let (status, body) = client
        .post("/permissions", r#"{"name":"vault.read"}"#)
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    let (status, body) = client.get("/users").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(users(&body).len(), 2);
    assert!(body.contains("member@example.test"));
    assert_no_secret_columns(&body);

    let (status, body) = client.get("/groups").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.contains("ops"));
    assert_no_secret_columns(&body);

    let (status, body) = client.get("/permissions").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.contains("vault.read"));
    assert_no_secret_columns(&body);

    let mut anonymous = Client::new(client.router.clone());
    for route in ["/users", "/groups", "/permissions"] {
        let (status, text) = anonymous.get(route).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{route}: {text}");
    }
}

#[tokio::test]
async fn a_store_with_a_user_ignores_the_administrator_settings() {
    let directory = tempfile::tempdir().expect("temp dir");
    let admin_password = random_password();
    let router = boot(&directory, "admin@example.test", &admin_password).await;
    let mut client = Client::new(router);
    client.issue_csrf().await;
    let (status, body) = client.sign_in("admin@example.test", &admin_password).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = client.get("/users").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(users(&body).len(), 1);
    drop(client);

    // Reopening with another administrator must not create or replace one.
    let other_password = random_password();
    let router = boot(&directory, "other@example.test", &other_password).await;
    let mut client = Client::new(router);
    client.issue_csrf().await;
    let (status, body) = client.sign_in("admin@example.test", &admin_password).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = client.get("/users").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(users(&body).len(), 1);

    let mut other = Client::new(client.router.clone());
    other.issue_csrf().await;
    let (status, _) = other.sign_in("other@example.test", &other_password).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_start_that_stopped_after_sign_up_finishes_the_administrator() {
    use neotales_x_auth::{Auth, Policy, hash_password};
    use neotales_x_auth_core::{AuthStore as _, Id, Timestamp};

    let directory = tempfile::tempdir().expect("temp dir");
    let database = directory.path().join("nav.sqlite");
    let key = random_key();
    let admin_password = random_password();

    // A first start that stopped after `sign_up`: the account exists, but the
    // membership and the admin role were never written.
    {
        let store = neotales_x_auth_store_sqlite::open(&database)
            .await
            .expect("store");
        let tenant = Id::now_v7();
        store
            .create_tenant(tenant, "navault", Timestamp::now_utc())
            .await
            .expect("tenant");
        let hash = hash_password(admin_password.as_bytes()).expect("hash");
        Auth::new(&store, key, Policy::default())
            .sign_up(tenant, "admin@example.test", &hash, Timestamp::now_utc())
            .await
            .expect("user");
    }

    // The next start finishes the membership and the role; it does not create a
    // second user, and it does not need the administrator password again.
    let router = app_with(
        Settings::new(&database)
            .with_key(key)
            .with_admin("second@example.test", random_password()),
    )
    .await
    .expect("the application starts");

    let mut client = Client::new(router);
    client.issue_csrf().await;
    let (status, body) = client.sign_in("admin@example.test", &admin_password).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, body) = client.get("/users").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let listed = users(&body);
    assert_eq!(listed.len(), 1, "no second user is created");

    // A second membership for the same user is a conflict, which proves the
    // start completed the missing membership and the caller may act.
    let user_id = listed[0]
        .get("id")
        .and_then(Value::as_str)
        .expect("user id");
    let (status, body) = client
        .post("/memberships", &format!(r#"{{"user_id":"{user_id}"}}"#))
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
}
