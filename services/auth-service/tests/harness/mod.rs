//! Test harness.
//!
//! Everything a test touches - the Postgres container, the pool and the HTTP
//! server - is built inside that test and dropped with it. Nothing lives in a
//! `static`, because statics are never dropped: a shared `ContainerAsync` held
//! there would leave a container running after the test binary exits, and they
//! would pile up one per run.
//!
//! The only thing shared is the signing keypair, via a directory on disk, since
//! regenerating a 2048-bit key for every test is needlessly slow.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use auth_service::config::Config;
use auth_service::http::router;
use auth_service::state::{AppState, TokenConfig};
use auth_service::{db, domain};
use testcontainers::ContainerAsync;
use testcontainers::core::ImageExt;
use testcontainers::runners::AsyncRunner;
use testcontainers_modules::postgres::Postgres;
use tokio::net::TcpListener;

pub const TEST_PASSWORD: &str = "correct horse battery staple";

/// Postgres major version used for tests. The module's own default is 11,
/// which is long past end of life, so pin something currently supported.
const POSTGRES_TAG: &str = "17-alpine";

/// Auth attempts per minute allowed in tests. The suite issues many requests
/// from a single IP, so the production limit would throttle it; throttling
/// itself is covered by `serve_with_rate_limit`.
const TEST_RATE_LIMIT: u32 = 100_000;

/// Directory holding the signing keypair, generated once for the whole run.
fn key_dir() -> &'static PathBuf {
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    DIR.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!("auth-service-it-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create key directory");
        dir
    })
}

/// A running server plus the state behind it, all owned by the calling test.
pub struct TestApp {
    pub address: SocketAddr,
    pub state: AppState,
    /// Held only so the container outlives the pool; dropping this stops it,
    /// which is what keeps repeated runs from accumulating containers.
    _container: ContainerAsync<Postgres>,
}

impl TestApp {
    pub fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.address)
    }
}

/// Builds a fully wired app on the caller's runtime: a fresh Postgres,
/// migrated, behind a real server.
pub async fn start() -> TestApp {
    start_with_bootstrapped_admins("").await
}

/// As [`start`], but grants the `admin` role to anyone registering with one of
/// the listed addresses. Used to test the bootstrap path itself.
pub async fn start_with_bootstrapped_admins(admin_emails: &str) -> TestApp {
    let _ = tracing_subscriber::fmt()
        .with_test_writer()
        .with_env_filter(tracing_subscriber::EnvFilter::new(
            "auth_service=debug,common=debug,warn",
        ))
        .try_init();

    let container = Postgres::default()
        .with_tag(POSTGRES_TAG)
        .start()
        .await
        .expect("Docker must be running to execute the integration tests");

    let host = container.get_host().await.expect("container host address");
    let port = container
        .get_host_port_ipv4(5432)
        .await
        .expect("postgres port");
    let url = format!("postgres://postgres:postgres@{host}:{port}/postgres");

    let pool = db::connect(&url, 5).await.expect("connect to postgres");

    // Run the migrator directly so a failure reports its real cause rather
    // than the generic message `db::migrate` logs.
    db::MIGRATOR
        .run(&pool)
        .await
        .unwrap_or_else(|e| panic!("migrations failed: {e}"));

    let keys = Arc::new(
        domain::keys::SigningKeys::load_or_generate(
            &key_dir().join("private.pem"),
            &key_dir().join("public.pem"),
        )
        .expect("load signing keys"),
    );

    let state = AppState {
        tokens: TokenConfig {
            issuer: "auth-service".into(),
            audience: "auth-service-clients".into(),
            access_ttl: std::time::Duration::from_secs(900),
        },
        config: Arc::new(
            Config::from_source_with(&|key| match key {
                "DATABASE_URL" => Some(url.clone()),
                "AUTH_RATE_LIMIT_PER_MINUTE" => Some(TEST_RATE_LIMIT.to_string()),
                // The admin tests promote their own account, so the default
                // list is empty.
                "ADMIN_BOOTSTRAP_EMAILS" => Some(admin_emails.to_owned()),
                _ => None,
            })
            .expect("test configuration"),
        ),
        pool,
        keys,
    };

    let address = serve(router(state.clone())).await;

    TestApp {
        address,
        state,
        _container: container,
    }
}

async fn serve(app: axum::Router) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let address = listener.local_addr().expect("local address");

    let app = app.into_make_service_with_connect_info::<SocketAddr>();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    address
}

/// Serves a second router over the same state with a deliberately tight
/// allowance, so throttling can be tested without disturbing the main app.
///
/// Compiled into every test binary but only exercised by the auth flow suite,
/// hence the allow.
#[allow(dead_code)]
pub async fn serve_with_rate_limit(state: &AppState, limit_per_minute: u32) -> SocketAddr {
    let app = auth_service::http::router_with_rate_limit(state.clone(), limit_per_minute);
    serve(app).await
}

/// An HTTP client that never follows redirects, so a 3xx cannot mask a 4xx.
pub fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("build http client")
}

/// A unique email per call, so tests never collide on the unique index.
pub fn unique_email(prefix: &str) -> String {
    format!("{prefix}-{}@example.com", uuid::Uuid::new_v4())
}
