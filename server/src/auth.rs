//! The authenticated application: a SQLite-backed auth store, a bootstrap
//! administrator, and the signed-in write routes.
//!
//! The store is opened through `neotales-x-auth-store-sqlite`, which speaks
//! `neotales-dbapi`; this crate does not open a second `SQLx` pool. The session
//! cookie, the CSRF cookie, and the CSRF header keep the x-auth defaults:
//! `neotales.session`, `neotales.csrf`, and `x-csrf-token`.
//!
//! The accounts, groups, and permissions the routes create are not secrets. The
//! lists select identifiers and names only: no password hash, session token
//! digest, API-key secret digest, or TOTP column is read, and the digest key is
//! never logged or returned.

// `Response` is axum's standard return type; the fallible helpers below return it
// directly instead of boxing every error.
#![allow(clippy::result_large_err)]

use std::fmt;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::extract::{FromRequest, Path as AxumPath, Request, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use neotales_dbapi::{DbType, Parameter, Pool, QueryOptions, Row, Value};
use neotales_x_auth::{Auth, Policy, hash_password};
use neotales_x_auth_axum::{AuthRouter, AuthState};
use neotales_x_auth_core::{AuthError, AuthStore, Id, MembershipStatus, Timestamp};
use neotales_x_auth_store_sqlite::{OpenError, SqliteStore};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::json;
use zeroize::Zeroizing;

/// Database file the process opens when no other path is given.
pub const DEFAULT_DATABASE: &str = "nav.sqlite";

/// File beside the database that holds the 32-byte digest key when
/// `NAV_AUTH_KEY` is not set.
pub const KEY_FILE: &str = "auth.key";

/// Length in bytes of the session and proof digest key.
pub const KEY_LEN: usize = 32;

/// Environment variable holding the digest key as 64 hexadecimal characters.
const KEY_VARIABLE: &str = "NAV_AUTH_KEY";
/// Environment variable holding the first administrator's email.
const ADMIN_EMAIL_VARIABLE: &str = "NAV_ADMIN_EMAIL";
/// Environment variable holding the first administrator's password.
const ADMIN_PASSWORD_VARIABLE: &str = "NAV_ADMIN_PASSWORD";
/// The header a state-changing request echoes the CSRF cookie in.
const CSRF_HEADER: &str = "x-csrf-token";
/// The origin names the x-auth router accepts by default, on any port.
const LOCAL_ORIGINS: [&str; 3] = ["http://localhost", "http://127.0.0.1", "http://[::1]"];
/// Tenant name used when the store has no tenant yet. Not a secret.
const TENANT_NAME: &str = "navault";

/// How [`app`] and [`app_with`] find the database, the digest key, and the first
/// administrator.
///
/// A key or administrator supplied here wins over the environment. The
/// environment is read only for what is missing, and the administrator
/// variables are read only when the store has no user yet.
pub struct Settings {
    database: PathBuf,
    key: Option<[u8; KEY_LEN]>,
    admin: Option<Admin>,
}

/// The first administrator's credentials, held only long enough to hash them.
struct Admin {
    email: String,
    password: Zeroizing<String>,
}

impl Settings {
    /// Settings for the database at `database`, with the key and administrator
    /// taken from the environment when they are needed.
    #[must_use]
    pub fn new(database: impl Into<PathBuf>) -> Self {
        Self {
            database: database.into(),
            key: None,
            admin: None,
        }
    }

    /// Use `key` as the digest key instead of `NAV_AUTH_KEY` or `auth.key`.
    #[must_use]
    pub fn with_key(mut self, key: [u8; KEY_LEN]) -> Self {
        self.key = Some(key);
        self
    }

    /// Bootstrap this administrator when the store has no user yet.
    #[must_use]
    pub fn with_admin(mut self, email: impl Into<String>, password: impl Into<String>) -> Self {
        self.admin = Some(Admin {
            email: email.into(),
            password: Zeroizing::new(password.into()),
        });
        self
    }

    /// The database file these settings open.
    #[must_use]
    pub fn database(&self) -> &Path {
        &self.database
    }
}

/// Opening the store or preparing the first administrator failed.
///
/// The message names the failing step or variable. It never includes a
/// password, a digest key, or a submitted value.
#[derive(Debug)]
pub enum StartupError {
    /// The auth store could not be opened or migrated.
    Store(OpenError),
    /// An auth workflow failed while bootstrapping the tenant or administrator.
    Auth(AuthError),
    /// The digest key was missing, malformed, or unreadable.
    Key(&'static str),
    /// The store is empty and neither the settings nor the environment supplied
    /// both administrator variables.
    MissingAdmin,
    /// A bootstrap query failed.
    Query,
    /// The blocking password-hashing task failed.
    Task,
    /// Binding or serving the listener failed.
    Listen(std::io::Error),
    /// A key file operation failed.
    Io(std::io::Error),
}

impl fmt::Display for StartupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Store(_) => "the auth store could not be opened",
            Self::Auth(_) => "an auth workflow failed during startup",
            Self::Key(message) => message,
            Self::MissingAdmin => {
                "NAV_ADMIN_EMAIL and NAV_ADMIN_PASSWORD are required before the first user exists"
            }
            Self::Query => "a startup query failed",
            Self::Task => "the password hasher task failed",
            Self::Listen(_) => "the listener failed",
            Self::Io(_) => "a key file operation failed",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for StartupError {}

impl From<OpenError> for StartupError {
    fn from(error: OpenError) -> Self {
        Self::Store(error)
    }
}

impl From<AuthError> for StartupError {
    fn from(error: AuthError) -> Self {
        Self::Auth(error)
    }
}

/// Build the application: open the store at `NAV_AUTH_KEY`'s default location,
/// bootstrap the tenant and administrator, and mount the auth and list routes.
///
/// The database is [`DEFAULT_DATABASE`] (`./nav.sqlite`). The digest key comes
/// from `NAV_AUTH_KEY` (64 hexadecimal characters) or from `auth.key` beside the
/// database, created with 32 random bytes when absent. The administrator
/// variables are read only when the store has no user.
///
/// # Errors
///
/// Returns [`StartupError`] when the store cannot be opened, the key is
/// malformed, or a new store has no administrator variables. The error never
/// contains a password or the key.
pub async fn app() -> Result<Router, StartupError> {
    app_with(Settings::new(DEFAULT_DATABASE)).await
}

/// Build the application from explicit [`Settings`].
///
/// Routes: `GET /health`, the x-auth defaults (`POST /sign-in`, `POST /sign-out`,
/// `GET /session`, ...), `POST /sign-up`, `POST /roles`, `POST /permissions`,
/// `POST /groups`, `POST /groups/{id}/members`,
/// `DELETE /groups/{id}/members/{membership_id}`, `POST /memberships`,
/// `POST /invitations`, `POST /invitations/accept`, `POST /email/verify/request`,
/// `POST /email/verify`, `POST /password/reset/request`, `POST /password/reset`,
/// and `GET /users`, `GET /groups`, `GET /permissions`.
///
/// Every state-changing route requires a live session cookie, except
/// `POST /sign-in`. An anonymous call is refused with `401` before its body is
/// read, even when the origin and CSRF pair are valid. That covers the group
/// member add and remove, the invitation issue and accept, email verification,
/// password reset, and sign-out. The three lists require the same session.
/// `POST /sign-in` stays available to an anonymous caller that presents a valid
/// origin and CSRF pair.
///
/// `/health` remains the only vault claim, and it is always false. The
/// `embed-ui` fallback is set after these routes, so it answers only paths no
/// route matched.
///
/// # Errors
///
/// Returns [`StartupError`] when the store cannot be opened, the key is
/// malformed, or a new store has no administrator variables.
pub async fn app_with(settings: Settings) -> Result<Router, StartupError> {
    let key = match settings.key {
        Some(key) => key,
        None => match std::env::var(KEY_VARIABLE) {
            Ok(value) => decode_hex(&value).ok_or(StartupError::Key(
                "NAV_AUTH_KEY must be 64 hexadecimal characters",
            ))?,
            Err(std::env::VarError::NotPresent) => load_or_create_key(&settings.database)?,
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err(StartupError::Key("NAV_AUTH_KEY is not valid text"));
            }
        },
    };

    let store = neotales_x_auth_store_sqlite::open(&settings.database).await?;
    let tenant = bootstrap(&store, &settings, key).await?;
    let store = Arc::new(store);
    let shared = Arc::new(Shared {
        store: Arc::clone(&store),
        tenant,
        key: Zeroizing::new(key),
    });

    let auth = AuthRouter::new(Arc::clone(&store), tenant, key, false)
        .roles(true)
        // Tokens this application never issues are discarded. They are not logged.
        .on_proof(|_email, _kind, _token| {})
        .sign_up(create_user::<SqliteStore>)
        .sign_out(sign_out::<SqliteStore>)
        .role(create_role::<SqliteStore>)
        .permission(create_permission::<SqliteStore>)
        .group(create_group::<SqliteStore>)
        .group_member(add_group_member::<SqliteStore>)
        .group_member_remove(remove_group_member::<SqliteStore>)
        .memberships(create_membership::<SqliteStore>)
        .invitations(issue_invitation::<SqliteStore>)
        .accept_invitation(accept_invitation::<SqliteStore>)
        .email_verify_request(email_verify_request::<SqliteStore>)
        .email_verify(email_verify::<SqliteStore>)
        .password_reset_request(password_reset_request::<SqliteStore>)
        .password_reset(password_reset::<SqliteStore>)
        .into_router();

    let lists = Router::new()
        .route("/users", get(list_users))
        .route("/groups", get(list_groups))
        .route("/permissions", get(list_permissions))
        .with_state(shared);

    let router = Router::new()
        .route("/health", get(crate::health))
        .merge(auth)
        .merge(lists);
    #[cfg(feature = "embed-ui")]
    let router = router.fallback(crate::ui::file);
    Ok(router)
}

/// State the list routes need: the shared store, the tenant, and the digest key
/// the session check uses.
struct Shared {
    store: Arc<SqliteStore>,
    tenant: Id,
    key: Zeroizing<[u8; KEY_LEN]>,
}

/// Ensure the store has a tenant and a bootstrapped administrator with active
/// membership and the admin role.
///
/// The administrator variables are consulted only when `auth_user` is empty.
/// The password is hashed on a blocking executor; neither it nor the hash is
/// printed.
///
/// A store that already has a user skips the variables, but not the rest of the
/// setup: if the first live user exists without an active membership or without
/// the admin role, those steps are finished on this start. A failed start after
/// `sign_up` therefore recovers instead of leaving an administrator that cannot
/// act. No second user is created.
async fn bootstrap(
    store: &SqliteStore,
    settings: &Settings,
    key: [u8; KEY_LEN],
) -> Result<Id, StartupError> {
    let provider = store.provider();
    let tenant = provider
        .fetch_first_async(
            "SELECT id FROM auth_tenant ORDER BY created_at LIMIT 1",
            QueryOptions::new(),
        )
        .await
        .map_err(|_| StartupError::Query)?
        .map(|row| read_id(&row).map_err(|_| StartupError::Query))
        .transpose()?;
    let tenant = if let Some(tenant) = tenant {
        tenant
    } else {
        let tenant = Id::now_v7();
        store
            .create_tenant(tenant, TENANT_NAME, Timestamp::now_utc())
            .await?;
        tenant
    };

    let users = provider
        .fetch_first_async("SELECT COUNT(*) AS n FROM auth_user", QueryOptions::new())
        .await
        .map_err(|_| StartupError::Query)?
        .ok_or(StartupError::Query)?
        .read::<i64>("n")
        .map_err(|_| StartupError::Query)?;
    if users > 0 {
        // The bootstrap administrator is the first live user. If an earlier start
        // stopped after `sign_up`, this is the user it created; completing the
        // membership and role is idempotent on a store that finished setup.
        let user = provider
            .fetch_first_async(
                "SELECT id FROM auth_user WHERE deleted_at IS NULL ORDER BY created_at LIMIT 1",
                QueryOptions::new(),
            )
            .await
            .map_err(|_| StartupError::Query)?
            .map(|row| read_id(&row).map_err(|_| StartupError::Query))
            .transpose()?;
        if let Some(user) = user {
            ensure_administrator_access(store, tenant, user, key).await?;
        }
        return Ok(tenant);
    }

    let admin = match &settings.admin {
        Some(admin) => Admin {
            email: admin.email.clone(),
            password: admin.password.clone(),
        },
        None => admin_from_env()?,
    };
    let Admin { email, password } = admin;
    let hash = tokio::task::spawn_blocking(move || hash_password(password.as_bytes()))
        .await
        .map_err(|_| StartupError::Task)?
        .map_err(StartupError::Auth)?;

    let user = Auth::new(store, key, Policy::default())
        .sign_up(tenant, &email, &hash, Timestamp::now_utc())
        .await?;
    ensure_administrator_access(store, tenant, user.id, key).await?;
    Ok(tenant)
}

/// Give `user` an active membership in `tenant` and the tenant's `admin` role.
///
/// Repeating this is safe: an existing active membership is kept, an inactive
/// one is made active, and the role assignment ignores a duplicate. Neither the
/// password nor its hash is read here, and nothing is printed.
async fn ensure_administrator_access(
    store: &SqliteStore,
    tenant: Id,
    user: Id,
    key: [u8; KEY_LEN],
) -> Result<(), StartupError> {
    let auth = Auth::new(store, key, Policy::default());
    let now = Timestamp::now_utc();
    let membership = match auth.membership(tenant, user).await {
        Ok(membership) if membership.status.is_authority() => membership,
        Ok(membership) => {
            auth.set_membership_status(membership.id, MembershipStatus::Active, now)
                .await?
        }
        Err(AuthError::NotFound) => {
            auth.create_membership(tenant, user, MembershipStatus::Active, now)
                .await?
        }
        Err(error) => return Err(StartupError::Auth(error)),
    };
    let role = store
        .provider()
        .fetch_first_async(
            "SELECT id FROM auth_role WHERE tenant_id=? AND name='admin'",
            QueryOptions::new().bind(id_parameter(tenant)),
        )
        .await
        .map_err(|_| StartupError::Query)?
        .ok_or(StartupError::Query)
        .and_then(|row| read_id(&row).map_err(|_| StartupError::Query))?;
    auth.assign_role(membership.id, role, now).await?;
    Ok(())
}

/// Read the bootstrap administrator from the environment.
fn admin_from_env() -> Result<Admin, StartupError> {
    let email = std::env::var(ADMIN_EMAIL_VARIABLE).map_err(|_| StartupError::MissingAdmin)?;
    let password =
        std::env::var(ADMIN_PASSWORD_VARIABLE).map_err(|_| StartupError::MissingAdmin)?;
    if email.trim().is_empty() || password.is_empty() {
        return Err(StartupError::MissingAdmin);
    }
    Ok(Admin {
        email,
        password: Zeroizing::new(password),
    })
}

/// Decode 64 hexadecimal characters into the 32-byte digest key.
fn decode_hex(value: &str) -> Option<[u8; KEY_LEN]> {
    let bytes = value.as_bytes();
    if bytes.len() != KEY_LEN * 2 {
        return None;
    }
    let mut key = [0u8; KEY_LEN];
    for (pair, slot) in bytes.chunks(2).zip(key.iter_mut()) {
        let pair = std::str::from_utf8(pair).ok()?;
        *slot = u8::from_str_radix(pair, 16).ok()?;
    }
    Some(key)
}

/// The key file next to the database.
fn key_path(database: &Path) -> PathBuf {
    let parent = database
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    parent.join(KEY_FILE)
}

/// Read the key file, or create it with 32 random bytes.
fn load_or_create_key(database: &Path) -> Result<[u8; KEY_LEN], StartupError> {
    let path = key_path(database);
    match std::fs::metadata(&path) {
        Ok(_) => read_key(&path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => create_key(&path),
        Err(error) => Err(StartupError::Io(error)),
    }
}

/// Read an existing key file; it must be exactly 32 bytes.
fn read_key(path: &Path) -> Result<[u8; KEY_LEN], StartupError> {
    let bytes = std::fs::read(path).map_err(StartupError::Io)?;
    <[u8; KEY_LEN]>::try_from(bytes.as_slice())
        .map_err(|_| StartupError::Key("auth.key must contain exactly 32 bytes"))
}

/// Create the key file for this machine and return the key. Nothing is logged.
fn create_key(path: &Path) -> Result<[u8; KEY_LEN], StartupError> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).map_err(StartupError::Io)?;
    }
    let mut key = [0u8; KEY_LEN];
    getrandom::fill(&mut key).map_err(|_| StartupError::Key("the random source failed"))?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => return read_key(path),
        Err(error) => return Err(StartupError::Io(error)),
    };
    file.write_all(&key).map_err(StartupError::Io)?;
    file.sync_all().map_err(StartupError::Io)?;
    Ok(key)
}

/// A password from a request body, wiped when it drops and never printed.
#[derive(Deserialize)]
#[serde(from = "String")]
struct Password(Zeroizing<String>);

impl From<String> for Password {
    fn from(value: String) -> Self {
        Self(Zeroizing::new(value))
    }
}

impl fmt::Debug for Password {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Password([redacted])")
    }
}

impl Password {
    /// The bytes to hash, wiped when they drop.
    fn into_bytes(mut self) -> Zeroizing<Vec<u8>> {
        let value = std::mem::take(&mut *self.0);
        Zeroizing::new(value.into_bytes())
    }
}

/// A new account behind `POST /sign-up`.
#[derive(Deserialize)]
struct Credentials {
    email: String,
    password: Password,
}

/// The body the role, permission, and group routes accept.
#[derive(Deserialize)]
struct NameBody {
    name: String,
}

/// The body `POST /memberships` accepts.
#[derive(Deserialize)]
struct MembershipBody {
    user_id: String,
    #[serde(default)]
    status: Option<String>,
}

/// Build a JSON error body without echoing the input.
fn fail(status: StatusCode, message: &'static str) -> Response {
    (status, Json(json!({ "error": message }))).into_response()
}

/// Map an auth error to a status and a fixed message.
fn auth_error(error: AuthError) -> Response {
    let (status, message) = match error {
        AuthError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
        AuthError::NotFound => (StatusCode::NOT_FOUND, "not found"),
        AuthError::Invalid => (StatusCode::BAD_REQUEST, "invalid input"),
        AuthError::Conflict => (StatusCode::CONFLICT, "conflict"),
        AuthError::Store => (StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
        AuthError::Unsupported => (StatusCode::NOT_IMPLEMENTED, "unsupported"),
    };
    fail(status, message)
}

/// Read one named cookie from the request.
///
/// The cookie header is untrusted text. A missing or non-text header, a pair
/// without `=`, and a name that does not match all return `None`; nothing is
/// indexed past the end of the value.
#[must_use]
pub fn cookie<'a>(request: &'a Request, name: &str) -> Option<&'a str> {
    request
        .headers()
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|pair| {
            let (key, value) = pair.trim().split_once('=')?;
            (key == name).then_some(value)
        })
}

/// Whether `origin` is one of the loopback names on a valid port.
///
/// Both values are untrusted text. The comparison is a prefix match followed by
/// an optional numeric port, so an empty host, a non-numeric port, a port above
/// `u16::MAX`, or trailing text after the port is refused.
#[must_use]
pub fn origin_matches(host: &str, origin: &str) -> bool {
    origin.strip_prefix(host).is_some_and(|rest| {
        rest.is_empty()
            || rest.strip_prefix(':').is_some_and(|port| {
                !port.is_empty()
                    && port.bytes().all(|byte| byte.is_ascii_digit())
                    && port.parse::<u16>().is_ok()
            })
    })
}

/// The origin check the x-auth defaults use: loopback over plain HTTP, any port.
fn origin_permitted(request: &Request) -> bool {
    let Some(origin) = request
        .headers()
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    LOCAL_ORIGINS
        .iter()
        .any(|host| origin_matches(host, origin))
}

/// The double-submit check against the router's CSRF cookie and header.
fn csrf_permitted<S: AuthStore + 'static>(state: &AuthState<S>, request: &Request) -> bool {
    let Some(cookie) = cookie(request, state.csrf_cookie()) else {
        return false;
    };
    let Some(header) = request
        .headers()
        .get(CSRF_HEADER)
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    !cookie.is_empty() && cookie == header
}

/// Refuse an unlisted origin, then a mismatched CSRF pair.
fn guard<S: AuthStore + 'static>(state: &AuthState<S>, request: &Request) -> Result<(), Response> {
    if !origin_permitted(request) {
        return Err(fail(StatusCode::FORBIDDEN, "origin"));
    }
    if !csrf_permitted(state, request) {
        return Err(fail(StatusCode::FORBIDDEN, "csrf"));
    }
    Ok(())
}

/// The presented session bearer, when the request carries one.
fn session_token(request: &Request, name: &str) -> Option<String> {
    cookie(request, name).map(str::to_owned)
}

/// Refuse a request whose session token is absent, invalid, or expired.
///
/// The token is passed by value: holding `&Request` across an await would make the
/// handler future non-`Send`, because the request body is not `Sync`.
async fn require_session<S: AuthStore + 'static>(
    state: &AuthState<S>,
    token: Option<String>,
) -> Result<(), Response> {
    let Some(token) = token else {
        return Err(fail(StatusCode::UNAUTHORIZED, "unauthorized"));
    };
    state
        .auth()
        .resolve_session(&token, Timestamp::now_utc())
        .await
        .map(|_| ())
        .map_err(auth_error)
}

/// Read a JSON body, answering `400` when it does not parse.
async fn json_body<T, S>(request: Request, state: &AuthState<S>) -> Result<T, Response>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    match Json::<T>::from_request(request, state).await {
        Ok(Json(value)) => Ok(value),
        Err(_) => Err(fail(StatusCode::BAD_REQUEST, "invalid request")),
    }
}

/// Hash a request password away from the async worker.
async fn hash_on_blocking(password: Zeroizing<Vec<u8>>) -> Result<String, Response> {
    match tokio::task::spawn_blocking(move || hash_password(&password)).await {
        Ok(Ok(hash)) => Ok(hash),
        Ok(Err(error)) => Err(auth_error(error)),
        Err(_) => Err(fail(StatusCode::INTERNAL_SERVER_ERROR, "internal error")),
    }
}

/// `POST /sign-up` behind a live session.
async fn create_user<S: AuthStore + 'static>(
    State(state): State<AuthState<S>>,
    request: Request,
) -> Response {
    if let Err(response) = guard(&state, &request) {
        return response;
    }
    let token = session_token(&request, state.session_cookie());
    if let Err(response) = require_session(&state, token).await {
        return response;
    }
    let body: Credentials = match json_body(request, &state).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let hash = match hash_on_blocking(body.password.into_bytes()).await {
        Ok(hash) => hash,
        Err(response) => return response,
    };
    match state
        .auth()
        .sign_up(state.tenant(), &body.email, &hash, Timestamp::now_utc())
        .await
    {
        Ok(user) => (
            StatusCode::CREATED,
            Json(json!({ "user": { "id": user.id.to_string(), "email": user.email } })),
        )
            .into_response(),
        Err(error) => auth_error(error),
    }
}

/// `POST /roles` behind a live session.
async fn create_role<S: AuthStore + 'static>(
    State(state): State<AuthState<S>>,
    request: Request,
) -> Response {
    if let Err(response) = guard(&state, &request) {
        return response;
    }
    let token = session_token(&request, state.session_cookie());
    if let Err(response) = require_session(&state, token).await {
        return response;
    }
    let body: NameBody = match json_body(request, &state).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    match state.auth().create_role(state.tenant(), &body.name).await {
        Ok(id) => (StatusCode::CREATED, Json(json!({ "id": id.to_string() }))).into_response(),
        Err(error) => auth_error(error),
    }
}

/// `POST /permissions` behind a live session.
async fn create_permission<S: AuthStore + 'static>(
    State(state): State<AuthState<S>>,
    request: Request,
) -> Response {
    if let Err(response) = guard(&state, &request) {
        return response;
    }
    let token = session_token(&request, state.session_cookie());
    if let Err(response) = require_session(&state, token).await {
        return response;
    }
    let body: NameBody = match json_body(request, &state).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    match state
        .auth()
        .create_permission(state.tenant(), &body.name)
        .await
    {
        Ok(id) => (StatusCode::CREATED, Json(json!({ "id": id.to_string() }))).into_response(),
        Err(error) => auth_error(error),
    }
}

/// `POST /groups` behind a live session.
async fn create_group<S: AuthStore + 'static>(
    State(state): State<AuthState<S>>,
    request: Request,
) -> Response {
    if let Err(response) = guard(&state, &request) {
        return response;
    }
    let token = session_token(&request, state.session_cookie());
    if let Err(response) = require_session(&state, token).await {
        return response;
    }
    let body: NameBody = match json_body(request, &state).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    match state
        .auth()
        .create_group(state.tenant(), &body.name, Timestamp::now_utc())
        .await
    {
        Ok(id) => (StatusCode::CREATED, Json(json!({ "id": id.to_string() }))).into_response(),
        Err(error) => auth_error(error),
    }
}

/// `POST /memberships` behind a live session.
async fn create_membership<S: AuthStore + 'static>(
    State(state): State<AuthState<S>>,
    request: Request,
) -> Response {
    if let Err(response) = guard(&state, &request) {
        return response;
    }
    let token = session_token(&request, state.session_cookie());
    if let Err(response) = require_session(&state, token).await {
        return response;
    }
    let body: MembershipBody = match json_body(request, &state).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let Ok(user) = Id::parse_str(&body.user_id) else {
        return fail(StatusCode::BAD_REQUEST, "invalid identifier");
    };
    let status = match body.status.as_deref() {
        None => MembershipStatus::Active,
        Some(value) => match MembershipStatus::parse(value) {
            Ok(status) => status,
            Err(_) => return fail(StatusCode::BAD_REQUEST, "invalid status"),
        },
    };
    match state
        .auth()
        .create_membership(state.tenant(), user, status, Timestamp::now_utc())
        .await
    {
        Ok(membership) => (
            StatusCode::CREATED,
            Json(json!({
                "id": membership.id.to_string(),
                "user_id": membership.user_id.to_string(),
                "status": membership.status.as_str(),
            })),
        )
            .into_response(),
        Err(error) => auth_error(error),
    }
}

/// `POST /sign-out` behind a live session.
///
/// The x-auth default revokes a presented session and answers `204` even when
/// none is presented. This wrapper refuses the anonymous request with `401`
/// first, so no state-changing route but `POST /sign-in` is open to it.
async fn sign_out<S: AuthStore + 'static>(
    State(state): State<AuthState<S>>,
    request: Request,
) -> Response {
    if let Err(response) = guard(&state, &request) {
        return response;
    }
    let token = session_token(&request, state.session_cookie());
    if let Err(response) = require_session(&state, token).await {
        return response;
    }
    neotales_x_auth_axum::default::sign_out::<S>(State(state), request).await
}

/// `POST /groups/{id}/members` behind a live session.
///
/// The x-auth default checks the origin and CSRF pair only. This wrapper adds
/// the session check its sibling write routes already have.
async fn add_group_member<S: AuthStore + 'static>(
    State(state): State<AuthState<S>>,
    AxumPath(group): AxumPath<String>,
    request: Request,
) -> Response {
    if let Err(response) = guard(&state, &request) {
        return response;
    }
    let token = session_token(&request, state.session_cookie());
    if let Err(response) = require_session(&state, token).await {
        return response;
    }
    neotales_x_auth_axum::default::add_group_member::<S>(State(state), AxumPath(group), request)
        .await
}

/// `DELETE /groups/{id}/members/{membership_id}` behind a live session.
async fn remove_group_member<S: AuthStore + 'static>(
    State(state): State<AuthState<S>>,
    AxumPath(ids): AxumPath<(String, String)>,
    request: Request,
) -> Response {
    if let Err(response) = guard(&state, &request) {
        return response;
    }
    let token = session_token(&request, state.session_cookie());
    if let Err(response) = require_session(&state, token).await {
        return response;
    }
    neotales_x_auth_axum::default::remove_group_member::<S>(State(state), AxumPath(ids), request)
        .await
}

/// `POST /invitations` behind a live session.
async fn issue_invitation<S: AuthStore + 'static>(
    State(state): State<AuthState<S>>,
    request: Request,
) -> Response {
    if let Err(response) = guard(&state, &request) {
        return response;
    }
    let token = session_token(&request, state.session_cookie());
    if let Err(response) = require_session(&state, token).await {
        return response;
    }
    neotales_x_auth_axum::default::issue_invitation::<S>(State(state), request).await
}

/// `POST /invitations/accept` behind a live session.
async fn accept_invitation<S: AuthStore + 'static>(
    State(state): State<AuthState<S>>,
    request: Request,
) -> Response {
    if let Err(response) = guard(&state, &request) {
        return response;
    }
    let token = session_token(&request, state.session_cookie());
    if let Err(response) = require_session(&state, token).await {
        return response;
    }
    neotales_x_auth_axum::default::accept_invitation::<S>(State(state), request).await
}

/// `POST /email/verify/request` behind a live session.
async fn email_verify_request<S: AuthStore + 'static>(
    State(state): State<AuthState<S>>,
    request: Request,
) -> Response {
    if let Err(response) = guard(&state, &request) {
        return response;
    }
    let token = session_token(&request, state.session_cookie());
    if let Err(response) = require_session(&state, token).await {
        return response;
    }
    neotales_x_auth_axum::default::email_verify_request::<S>(State(state), request).await
}

/// `POST /email/verify` behind a live session.
async fn email_verify<S: AuthStore + 'static>(
    State(state): State<AuthState<S>>,
    request: Request,
) -> Response {
    if let Err(response) = guard(&state, &request) {
        return response;
    }
    let token = session_token(&request, state.session_cookie());
    if let Err(response) = require_session(&state, token).await {
        return response;
    }
    neotales_x_auth_axum::default::email_verify::<S>(State(state), request).await
}

/// `POST /password/reset/request` behind a live session.
async fn password_reset_request<S: AuthStore + 'static>(
    State(state): State<AuthState<S>>,
    request: Request,
) -> Response {
    if let Err(response) = guard(&state, &request) {
        return response;
    }
    let token = session_token(&request, state.session_cookie());
    if let Err(response) = require_session(&state, token).await {
        return response;
    }
    neotales_x_auth_axum::default::password_reset_request::<S>(State(state), request).await
}

/// `POST /password/reset` behind a live session.
async fn password_reset<S: AuthStore + 'static>(
    State(state): State<AuthState<S>>,
    request: Request,
) -> Response {
    if let Err(response) = guard(&state, &request) {
        return response;
    }
    let token = session_token(&request, state.session_cookie());
    if let Err(response) = require_session(&state, token).await {
        return response;
    }
    neotales_x_auth_axum::default::password_reset::<S>(State(state), request).await
}

/// A stored identifier as a SQLite parameter.
fn id_parameter(value: Id) -> Parameter {
    Parameter::new(DbType::Bytes, Value::Bytes(value.as_bytes().to_vec()))
        .expect("matching bytes parameter")
}

/// Read a 16-byte identifier column.
fn read_id(row: &Row) -> Result<Id, AuthError> {
    let raw: Vec<u8> = row.read("id").map_err(|_| AuthError::Store)?;
    Id::from_slice(&raw).map_err(|_| AuthError::Store)
}

/// Fetch the rows for one tenant-scoped, identifier-and-name-only query.
async fn tenant_rows(shared: &Shared, sql: &str) -> Result<Vec<Row>, AuthError> {
    shared
        .store
        .provider()
        .fetch_all_async(sql, QueryOptions::new().bind(id_parameter(shared.tenant)))
        .await
        .map_err(|_| AuthError::Store)
}

/// Refuse a list request without a live session.
async fn list_session(shared: &Shared, token: Option<String>) -> Result<(), Response> {
    let Some(token) = token else {
        return Err(fail(StatusCode::UNAUTHORIZED, "unauthorized"));
    };
    Auth::new(&*shared.store, *shared.key, Policy::default())
        .resolve_session(&token, Timestamp::now_utc())
        .await
        .map(|_| ())
        .map_err(auth_error)
}

/// `GET /users`: each account's identifier and email, nothing else.
async fn list_users(State(shared): State<Arc<Shared>>, request: Request) -> Response {
    let token = session_token(&request, neotales_x_auth_axum::DEFAULT_SESSION_COOKIE);
    if let Err(response) = list_session(&shared, token).await {
        return response;
    }
    let rows = match tenant_rows(
        &shared,
        "SELECT id,email FROM auth_user WHERE tenant_id=? AND deleted_at IS NULL ORDER BY created_at",
    )
    .await
    {
        Ok(rows) => rows,
        Err(error) => return auth_error(error),
    };
    let mut users = Vec::with_capacity(rows.len());
    for row in rows {
        let id = match read_id(&row) {
            Ok(id) => id,
            Err(error) => return auth_error(error),
        };
        let email: String = match row.read("email") {
            Ok(email) => email,
            Err(_) => return auth_error(AuthError::Store),
        };
        users.push(json!({ "id": id.to_string(), "email": email }));
    }
    (StatusCode::OK, Json(json!({ "users": users }))).into_response()
}

/// `GET /groups`: each group's identifier and name.
async fn list_groups(State(shared): State<Arc<Shared>>, request: Request) -> Response {
    let token = session_token(&request, neotales_x_auth_axum::DEFAULT_SESSION_COOKIE);
    if let Err(response) = list_session(&shared, token).await {
        return response;
    }
    let rows = match tenant_rows(
        &shared,
        "SELECT id,name FROM auth_group WHERE tenant_id=? ORDER BY name",
    )
    .await
    {
        Ok(rows) => rows,
        Err(error) => return auth_error(error),
    };
    let mut groups = Vec::with_capacity(rows.len());
    for row in rows {
        let id = match read_id(&row) {
            Ok(id) => id,
            Err(error) => return auth_error(error),
        };
        let name: String = match row.read("name") {
            Ok(name) => name,
            Err(_) => return auth_error(AuthError::Store),
        };
        groups.push(json!({ "id": id.to_string(), "name": name }));
    }
    (StatusCode::OK, Json(json!({ "groups": groups }))).into_response()
}

/// `GET /permissions`: each permission's identifier and name.
async fn list_permissions(State(shared): State<Arc<Shared>>, request: Request) -> Response {
    let token = session_token(&request, neotales_x_auth_axum::DEFAULT_SESSION_COOKIE);
    if let Err(response) = list_session(&shared, token).await {
        return response;
    }
    let rows = match tenant_rows(
        &shared,
        "SELECT id,name FROM auth_permission WHERE tenant_id=? ORDER BY name",
    )
    .await
    {
        Ok(rows) => rows,
        Err(error) => return auth_error(error),
    };
    let mut permissions = Vec::with_capacity(rows.len());
    for row in rows {
        let id = match read_id(&row) {
            Ok(id) => id,
            Err(error) => return auth_error(error),
        };
        let name: String = match row.read("name") {
            Ok(name) => name,
            Err(_) => return auth_error(AuthError::Store),
        };
        permissions.push(json!({ "id": id.to_string(), "name": name }));
    }
    (StatusCode::OK, Json(json!({ "permissions": permissions }))).into_response()
}

#[cfg(test)]
mod tests {
    use super::{KEY_LEN, Settings, app_with, decode_hex, load_or_create_key};

    #[test]
    fn a_sixty_four_character_hex_key_decodes() {
        let key = decode_hex(&"ab".repeat(32)).expect("valid hex");
        assert_eq!(key, [0xab; KEY_LEN]);
        assert_eq!(decode_hex(&"AB".repeat(32)).expect("uppercase"), [0xab; 32]);
    }

    #[test]
    fn a_key_that_is_not_sixty_four_hex_characters_is_refused() {
        assert!(decode_hex(&"ab".repeat(31)).is_none());
        assert!(decode_hex(&"ab".repeat(33)).is_none());
        assert!(decode_hex(&"zz".repeat(32)).is_none());
        assert!(decode_hex("").is_none());
    }

    #[test]
    fn the_key_file_is_created_once_and_reused() {
        let directory = tempfile::tempdir().expect("temp dir");
        let database = directory.path().join("nav.sqlite");
        let first = load_or_create_key(&database).expect("created key");
        let second = load_or_create_key(&database).expect("reused key");
        assert_eq!(first, second);
        let stored = std::fs::read(directory.path().join("auth.key")).expect("key file");
        assert_eq!(stored.len(), KEY_LEN);
    }

    /// An anonymous caller with a valid origin and CSRF pair still gets `401`
    /// from every state-changing route the task names, because a session is
    /// missing. `POST /sign-in` is the only state-changing route left open.
    #[tokio::test]
    async fn anonymous_state_changing_routes_are_unauthorized_with_a_csrf_pair() {
        use axum::body::Body;
        use axum::http::{Method, Request, StatusCode, header};
        use neotales_x_auth_core::Id;
        use tower::ServiceExt as _;

        let directory = tempfile::tempdir().expect("temp dir");
        let app = app_with(
            Settings::new(directory.path().join("nav.sqlite"))
                .with_key([0x11; KEY_LEN])
                .with_admin("admin@example.test", "correct horse battery staple"),
        )
        .await
        .expect("app");

        // A safe GET hands the page the CSRF cookie the POSTs must echo.
        let response = app
            .clone()
            .oneshot(
                Request::get("/session")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        let csrf = response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .find_map(|text| text.strip_prefix("neotales.csrf="))
            .and_then(|rest| rest.split(';').next())
            .expect("csrf cookie")
            .to_owned();
        assert_ne!(csrf, "");

        let group = Id::now_v7();
        let membership = Id::now_v7();
        let routes = [
            (Method::POST, format!("/groups/{group}/members")),
            (
                Method::DELETE,
                format!("/groups/{group}/members/{membership}"),
            ),
            (Method::POST, "/password/reset".to_owned()),
            (Method::POST, "/password/reset/request".to_owned()),
            (Method::POST, "/email/verify".to_owned()),
            (Method::POST, "/email/verify/request".to_owned()),
            (Method::POST, "/invitations".to_owned()),
            (Method::POST, "/invitations/accept".to_owned()),
            (Method::POST, "/sign-out".to_owned()),
        ];
        for (method, path) in routes {
            let request = Request::builder()
                .method(method.clone())
                .uri(&path)
                .header(header::ORIGIN, "http://localhost")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, format!("neotales.csrf={csrf}"))
                .header("x-csrf-token", &csrf)
                .body(Body::from("{}"))
                .expect("request");
            let response = app.clone().oneshot(request).await.expect("response");
            assert_eq!(
                response.status(),
                StatusCode::UNAUTHORIZED,
                "{method} {path} needs a session"
            );
        }
    }
}
