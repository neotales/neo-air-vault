//! The auth routes over a temporary store: bootstrap, session, and lists.

use axum::Router;
use axum::body::Body;
use axum::http::request::Builder;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use neotales_dbapi::{DbType, Parameter, Pool as _, QueryOptions, Value};
use neotales_x_auth::{Auth, Policy, hash_password};
use neotales_x_auth_core::{AuthError, AuthStore as _, Id, MembershipStatus, Timestamp};
use serde_json::Value as Json;
use tower::ServiceExt;

use navault_server::{ADMIN_FILE, KEY_LEN, Settings, app_with};

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

fn users(body: &str) -> Vec<Json> {
    let value: Json = serde_json::from_str(body).expect("json");
    value
        .get("users")
        .and_then(Json::as_array)
        .expect("users array")
        .clone()
}

/// The tenant and the first account, read directly from `database`.
async fn tenant_and_first_user(database: &std::path::Path) -> (Id, Id) {
    let store = neotales_x_auth_store_sqlite::open(database)
        .await
        .expect("store");
    let tenant = store
        .provider()
        .fetch_first_async(
            "SELECT id FROM auth_tenant ORDER BY created_at LIMIT 1",
            QueryOptions::new(),
        )
        .await
        .expect("tenant query")
        .expect("tenant");
    let tenant =
        Id::from_slice(&tenant.read::<Vec<u8>>("id").expect("tenant id")).expect("valid tenant id");
    let user = store
        .provider()
        .fetch_first_async(
            "SELECT id FROM auth_user ORDER BY created_at LIMIT 1",
            QueryOptions::new(),
        )
        .await
        .expect("user query")
        .expect("user");
    let user =
        Id::from_slice(&user.read::<Vec<u8>>("id").expect("user id")).expect("valid user id");
    (tenant, user)
}

/// The stored membership status for `user`, or `None` when there is no row.
async fn stored_membership(
    database: &std::path::Path,
    key: [u8; KEY_LEN],
    tenant: Id,
    user: Id,
) -> Option<MembershipStatus> {
    let store = neotales_x_auth_store_sqlite::open(database)
        .await
        .expect("store");
    let auth = Auth::new(&store, key, Policy::default());
    match auth.membership(tenant, user).await {
        Ok(membership) => Some(membership.status),
        Err(AuthError::NotFound) => None,
        Err(error) => panic!("membership query failed: {error:?}"),
    }
}

/// Mark `user` deleted, the way deleting the account leaves the row.
async fn soft_delete_user(database: &std::path::Path, user: Id) {
    let store = neotales_x_auth_store_sqlite::open(database)
        .await
        .expect("store");
    let deleted_at = Parameter::new(
        DbType::Text,
        Value::Text("2020-01-01T00:00:00.000000000Z".to_owned()),
    )
    .expect("text parameter");
    let id = Parameter::new(DbType::Bytes, Value::Bytes(user.as_bytes().to_vec()))
        .expect("id parameter");
    let affected = store
        .provider()
        .execute_async(
            "UPDATE auth_user SET deleted_at=? WHERE id=?",
            QueryOptions::new().bind(deleted_at).bind(id),
        )
        .await
        .expect("soft delete");
    assert_eq!(affected, 1, "one account is marked deleted");
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
    assert!(
        !directory.path().join(ADMIN_FILE).exists(),
        "the stopped start left no marker"
    );

    // The next start finishes the membership and the role; it does not create a
    // second user, and it does not need the administrator password again.
    let router = app_with(
        Settings::new(&database)
            .with_key(key)
            .with_admin("second@example.test", random_password()),
    )
    .await
    .expect("the application starts");
    assert!(
        directory.path().join(ADMIN_FILE).exists(),
        "finishing access writes the marker"
    );

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
    let user_id = listed[0].get("id").and_then(Json::as_str).expect("user id");
    let (status, body) = client
        .post("/memberships", &format!(r#"{{"user_id":"{user_id}"}}"#))
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");

    let marker = std::fs::read_to_string(directory.path().join(ADMIN_FILE)).expect("marker");
    assert_eq!(
        marker.trim(),
        user_id,
        "the marker records the administrator"
    );
}

#[tokio::test]
async fn a_revoked_membership_stays_revoked_on_the_next_open() {
    let directory = tempfile::tempdir().expect("temp dir");
    let database = directory.path().join("nav.sqlite");
    let key = random_key();
    let admin_password = random_password();

    let router = app_with(
        Settings::new(&database)
            .with_key(key)
            .with_admin("admin@example.test", &admin_password),
    )
    .await
    .expect("the first start");
    drop(router);
    assert!(
        directory.path().join(ADMIN_FILE).exists(),
        "the first start writes the marker"
    );

    let (tenant, user) = tenant_and_first_user(&database).await;
    {
        let store = neotales_x_auth_store_sqlite::open(&database)
            .await
            .expect("store");
        let auth = Auth::new(&store, key, Policy::default());
        let membership = auth.membership(tenant, user).await.expect("membership");
        auth.set_membership_status(
            membership.id,
            MembershipStatus::Suspended,
            Timestamp::now_utc(),
        )
        .await
        .expect("suspend");
    }

    // The marker makes the next start leave the suspension alone.
    let router = app_with(
        Settings::new(&database)
            .with_key(key)
            .with_admin("other@example.test", random_password()),
    )
    .await
    .expect("the next start");
    drop(router);

    assert_eq!(
        stored_membership(&database, key, tenant, user).await,
        Some(MembershipStatus::Suspended),
        "a revoked membership is not reactivated"
    );
}

#[tokio::test]
async fn a_store_with_memberships_adopts_the_existing_administrator() {
    let directory = tempfile::tempdir().expect("temp dir");
    let database = directory.path().join("nav.sqlite");
    let key = random_key();
    let admin_password = random_password();

    let router = app_with(
        Settings::new(&database)
            .with_key(key)
            .with_admin("admin@example.test", &admin_password),
    )
    .await
    .expect("the first start");
    drop(router);
    let (tenant, administrator) = tenant_and_first_user(&database).await;

    // A store that finished access before the marker existed has memberships
    // and no marker. The next start records the user who already holds admin.
    std::fs::remove_file(directory.path().join(ADMIN_FILE)).expect("remove marker");
    let router = app_with(
        Settings::new(&database)
            .with_key(key)
            .with_admin("other@example.test", random_password()),
    )
    .await
    .expect("the next start");
    drop(router);

    let marker = std::fs::read_to_string(directory.path().join(ADMIN_FILE)).expect("marker");
    assert_eq!(marker.trim(), administrator.to_string());
    assert_eq!(
        stored_membership(&database, key, tenant, administrator).await,
        Some(MembershipStatus::Active),
        "adoption changes no status"
    );
}

#[tokio::test]
async fn a_later_open_does_not_promote_a_second_user() {
    let directory = tempfile::tempdir().expect("temp dir");
    let database = directory.path().join("nav.sqlite");
    let key = random_key();
    let admin_password = random_password();

    let router = app_with(
        Settings::new(&database)
            .with_key(key)
            .with_admin("admin@example.test", &admin_password),
    )
    .await
    .expect("the first start");
    drop(router);
    let (tenant, administrator) = tenant_and_first_user(&database).await;

    // A second live account with no membership at all.
    let second = {
        let store = neotales_x_auth_store_sqlite::open(&database)
            .await
            .expect("store");
        let hash = hash_password(random_password().as_bytes()).expect("hash");
        Auth::new(&store, key, Policy::default())
            .sign_up(tenant, "second@example.test", &hash, Timestamp::now_utc())
            .await
            .expect("second user")
    };
    assert_eq!(
        stored_membership(&database, key, tenant, second.id).await,
        None,
        "the second user starts without a membership"
    );

    // Delete the original administrator; the marker still names it.
    soft_delete_user(&database, administrator).await;

    // The next start is the first live user's chance to be promoted, which the
    // marker must refuse: it names the deleted administrator, not this user.
    let router = app_with(
        Settings::new(&database)
            .with_key(key)
            .with_admin("third@example.test", random_password()),
    )
    .await
    .expect("the later start");
    drop(router);

    assert_eq!(
        stored_membership(&database, key, tenant, second.id).await,
        None,
        "a later start does not promote a different user"
    );
    let marker = std::fs::read_to_string(directory.path().join(ADMIN_FILE)).expect("marker");
    assert_eq!(
        marker.trim(),
        administrator.to_string(),
        "the marker still names the original administrator"
    );
}
