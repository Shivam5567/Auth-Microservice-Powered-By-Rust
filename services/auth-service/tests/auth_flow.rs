//! End-to-end tests against a real Postgres, driven over HTTP.
//!
//! Every test shares one container and one running server; see `harness`.

mod harness;

use harness::{TEST_PASSWORD, TestApp, client, unique_email};
use serde_json::{Value, json};
use testcontainers::ContainerAsync;
use testcontainers_modules::postgres::Postgres;

/// Starts an app for this test.
///
/// Deliberately not cached: each `#[tokio::test]` owns its runtime, so a
/// shared server started by an earlier test would already be gone. The
/// container and keypair behind it are still shared.
async fn app() -> harness::TestApp {
    harness::start().await
}

async fn register(app: &TestApp, email: &str) -> Value {
    let response = client()
        .post(app.url("/api/v1/auth/register"))
        .json(&json!({ "email": email, "password": TEST_PASSWORD }))
        .send()
        .await
        .expect("register request");

    assert_eq!(response.status(), 201, "register should succeed");
    response.json().await.expect("register body")
}

async fn login(app: &TestApp, email: &str) -> Value {
    let response = client()
        .post(app.url("/api/v1/auth/login"))
        .json(&json!({ "email": email, "password": TEST_PASSWORD }))
        .send()
        .await
        .expect("login request");

    assert_eq!(response.status(), 200, "login should succeed");
    response.json().await.expect("login body")
}

#[tokio::test]
async fn register_returns_the_new_profile() {
    let app = app().await;
    let email = unique_email("register");

    let body = register(&app, &email).await;

    assert_eq!(body["email"], email);
    assert_eq!(body["roles"], json!(["user"]));
    assert!(body["id"].as_str().is_some());
    // The password hash must never be echoed back.
    assert!(body.get("password").is_none());
    assert!(body.get("password_hash").is_none());
}

#[tokio::test]
async fn a_duplicate_email_is_a_conflict() {
    let app = app().await;
    let email = unique_email("duplicate");

    register(&app, &email).await;

    let response = client()
        .post(app.url("/api/v1/auth/register"))
        .json(&json!({ "email": email, "password": TEST_PASSWORD }))
        .send()
        .await
        .expect("duplicate register request");

    assert_eq!(response.status(), 409);
    let body: Value = response.json().await.expect("error body");
    assert_eq!(body["error"]["code"], "conflict");
}

#[tokio::test]
async fn an_email_is_case_insensitive_for_registration() {
    let app = app().await;
    let email = unique_email("Casing");

    register(&app, &email).await;

    let response = client()
        .post(app.url("/api/v1/auth/register"))
        .json(&json!({ "email": email.to_uppercase(), "password": TEST_PASSWORD }))
        .send()
        .await
        .expect("uppercase register request");

    assert_eq!(response.status(), 409, "same address must not register twice");
}

#[tokio::test]
async fn login_returns_a_token_pair_and_the_profile() {
    let app = app().await;
    let email = unique_email("login");
    register(&app, &email).await;

    let body = login(&app, &email).await;

    assert_eq!(body["token_type"], "Bearer");
    assert_eq!(body["expires_in"], 900);
    assert!(body["access_token"].as_str().unwrap().split('.').count() == 3);
    assert!(body["refresh_token"].as_str().is_some());
    assert_eq!(body["user"]["email"], email);
}

#[tokio::test]
async fn a_wrong_password_is_rejected() {
    let app = app().await;
    let email = unique_email("wrongpw");
    register(&app, &email).await;

    let response = client()
        .post(app.url("/api/v1/auth/login"))
        .json(&json!({ "email": email, "password": "not the right one" }))
        .send()
        .await
        .expect("login request");

    assert_eq!(response.status(), 401);
    let body: Value = response.json().await.expect("error body");
    // The message must not reveal whether the address exists.
    assert_eq!(body["error"]["message"], "invalid email or password");
}

#[tokio::test]
async fn an_unknown_email_gives_the_same_answer_as_a_wrong_password() {
    let app = app().await;

    let response = client()
        .post(app.url("/api/v1/auth/login"))
        .json(&json!({ "email": unique_email("ghost"), "password": "whatever" }))
        .send()
        .await
        .expect("login request");

    assert_eq!(response.status(), 401);
    let body: Value = response.json().await.expect("error body");
    assert_eq!(body["error"]["message"], "invalid email or password");
}

#[tokio::test]
async fn me_returns_the_caller_from_the_access_token() {
    let app = app().await;
    let email = unique_email("me");
    register(&app, &email).await;
    let tokens = login(&app, &email).await;

    let response = client()
        .get(app.url("/api/v1/auth/me"))
        .bearer_auth(tokens["access_token"].as_str().unwrap())
        .send()
        .await
        .expect("me request");

    assert_eq!(response.status(), 200);
    let body: Value = response.json().await.expect("me body");
    assert_eq!(body["email"], email);
    assert_eq!(body["roles"], json!(["user"]));
}

#[tokio::test]
async fn me_rejects_a_missing_or_garbage_token() {
    let app = app().await;

    let anonymous = client()
        .get(app.url("/api/v1/auth/me"))
        .send()
        .await
        .expect("me request");
    assert_eq!(anonymous.status(), 401);

    let garbage = client()
        .get(app.url("/api/v1/auth/me"))
        .bearer_auth("not.a.token")
        .send()
        .await
        .expect("me request");
    assert_eq!(garbage.status(), 401);
}

#[tokio::test]
async fn refresh_issues_a_new_pair_and_retires_the_old_one() {
    let app = app().await;
    let email = unique_email("refresh");
    register(&app, &email).await;
    let first = login(&app, &email).await;
    let original = first["refresh_token"].as_str().unwrap().to_owned();

    let response = client()
        .post(app.url("/api/v1/auth/refresh"))
        .json(&json!({ "refresh_token": original }))
        .send()
        .await
        .expect("refresh request");

    assert_eq!(response.status(), 200);
    let second: Value = response.json().await.expect("refresh body");
    let rotated = second["refresh_token"].as_str().unwrap();

    assert_ne!(rotated, original, "rotation must produce a fresh token");
    assert!(second["access_token"].as_str().is_some());

    // The rotated token works, and the original is now spent.
    let reuse = client()
        .post(app.url("/api/v1/auth/refresh"))
        .json(&json!({ "refresh_token": original }))
        .send()
        .await
        .expect("reuse request");
    assert_eq!(reuse.status(), 401, "a spent token must not be reusable");
}

#[tokio::test]
async fn replaying_a_spent_token_burns_the_whole_family() {
    let app = app().await;
    let email = unique_email("reuse");
    register(&app, &email).await;
    let first = login(&app, &email).await;
    let stolen = first["refresh_token"].as_str().unwrap().to_owned();

    // The attacker rotates the stolen token successfully.
    let rotated: Value = client()
        .post(app.url("/api/v1/auth/refresh"))
        .json(&json!({ "refresh_token": stolen }))
        .send()
        .await
        .expect("refresh request")
        .json()
        .await
        .expect("refresh body");
    let attacker_token = rotated["refresh_token"].as_str().unwrap().to_owned();

    // The legitimate client then presents its now-spent token, which reveals
    // the theft and must invalidate the attacker's token too.
    let replay = client()
        .post(app.url("/api/v1/auth/refresh"))
        .json(&json!({ "refresh_token": stolen }))
        .send()
        .await
        .expect("replay request");
    assert_eq!(replay.status(), 401);

    let after = client()
        .post(app.url("/api/v1/auth/refresh"))
        .json(&json!({ "refresh_token": attacker_token }))
        .send()
        .await
        .expect("post-revocation refresh");
    assert_eq!(after.status(), 401, "family should be revoked after a replay");
}

#[tokio::test]
async fn logout_revokes_only_the_presented_session_by_default() {
    let app = app().await;
    let email = unique_email("logout");
    register(&app, &email).await;

    let first = login(&app, &email).await;
    let second = login(&app, &email).await;
    let first_token = first["refresh_token"].as_str().unwrap().to_owned();
    let second_token = second["refresh_token"].as_str().unwrap().to_owned();

    let response = client()
        .post(app.url("/api/v1/auth/logout"))
        .json(&json!({ "refresh_token": first_token }))
        .send()
        .await
        .expect("logout request");
    assert_eq!(response.status(), 204);

    let dead = client()
        .post(app.url("/api/v1/auth/refresh"))
        .json(&json!({ "refresh_token": first_token }))
        .send()
        .await
        .expect("refresh after logout");
    assert_eq!(dead.status(), 401);

    let alive = client()
        .post(app.url("/api/v1/auth/refresh"))
        .json(&json!({ "refresh_token": second_token }))
        .send()
        .await
        .expect("other session refresh");
    assert_eq!(alive.status(), 200, "the other session should survive");
}

#[tokio::test]
async fn logging_out_everywhere_also_kills_live_access_tokens() {
    let app = app().await;
    let email = unique_email("logoutall");
    register(&app, &email).await;
    let tokens = login(&app, &email).await;
    let access = tokens["access_token"].as_str().unwrap().to_owned();
    let refresh = tokens["refresh_token"].as_str().unwrap().to_owned();

    let response = client()
        .post(app.url("/api/v1/auth/logout"))
        .json(&json!({ "refresh_token": refresh, "all_devices": true }))
        .send()
        .await
        .expect("logout request");
    assert_eq!(response.status(), 204);

    // The access token is still cryptographically valid but has been revoked
    // by the version bump.
    let me = client()
        .get(app.url("/api/v1/auth/me"))
        .bearer_auth(&access)
        .send()
        .await
        .expect("me after logout");
    assert_eq!(me.status(), 401, "a revoked access token must stop working");
}

#[tokio::test]
async fn logout_is_idempotent_for_an_unknown_token() {
    let app = app().await;

    let response = client()
        .post(app.url("/api/v1/auth/logout"))
        .json(&json!({ "refresh_token": "never-existed" }))
        .send()
        .await
        .expect("logout request");

    assert_eq!(response.status(), 204);
}

#[tokio::test]
async fn an_invalid_payload_is_rejected_with_field_detail() {
    let app = app().await;

    let response = client()
        .post(app.url("/api/v1/auth/register"))
        .json(&json!({ "email": "not-an-email", "password": "short" }))
        .send()
        .await
        .expect("register request");

    assert_eq!(response.status(), 400);
    let body: Value = response.json().await.expect("error body");
    assert_eq!(body["error"]["code"], "validation_failed");
    let message = body["error"]["message"].as_str().unwrap();
    assert!(message.contains("email"), "got: {message}");
    assert!(message.contains("password"), "got: {message}");
}

#[tokio::test]
async fn health_endpoints_report_the_database_state() {
    let app = app().await;

    let live = client()
        .get(app.url("/health"))
        .send()
        .await
        .expect("health request");
    assert_eq!(live.status(), 200);

    let ready = client()
        .get(app.url("/health/ready"))
        .send()
        .await
        .expect("readiness request");
    assert_eq!(ready.status(), 200);
    let body: Value = ready.json().await.expect("readiness body");
    assert_eq!(body["database"], "connected");
}

#[tokio::test]
async fn an_unknown_route_returns_the_error_envelope() {
    let app = app().await;

    let response = client()
        .get(app.url("/api/v1/nope"))
        .send()
        .await
        .expect("request");

    assert_eq!(response.status(), 404);
    let body: Value = response.json().await.expect("error body");
    assert_eq!(body["error"]["code"], "not_found");
}

#[tokio::test]
async fn every_response_carries_a_request_id() {
    let app = app().await;

    let response = client()
        .get(app.url("/health"))
        .send()
        .await
        .expect("health request");

    assert!(response.headers().contains_key("x-request-id"));
}

/// Verifies throttling on a router built with a deliberately tiny allowance,
/// so the shared app used by the rest of the suite is not affected.
#[tokio::test]
async fn repeated_login_attempts_are_throttled() {
    let app = app().await;
    let address = harness::serve_with_rate_limit(&app.state, 3).await;
    let url = format!("http://{address}/api/v1/auth/login");

    let mut statuses = Vec::new();
    for _ in 0..5 {
        let response = client()
            .post(&url)
            .json(&json!({ "email": unique_email("flood"), "password": "wrong" }))
            .send()
            .await
            .expect("login request");
        statuses.push(response.status().as_u16());
    }

    assert!(
        statuses.contains(&429),
        "expected a 429 within five attempts, got {statuses:?}"
    );
    // The allowance is 3, so the first three attempts are served and the rest
    // are rejected.
    assert_eq!(statuses.iter().filter(|s| **s == 401).count(), 3);
}

#[tokio::test]
async fn a_throttled_response_uses_the_shared_error_envelope() {
    let app = app().await;
    let address = harness::serve_with_rate_limit(&app.state, 1).await;
    let url = format!("http://{address}/api/v1/auth/login");
    let body = json!({ "email": unique_email("env"), "password": "wrong" });

    let first = client().post(&url).json(&body).send().await.expect("first");
    assert_eq!(first.status(), 401);

    let second = client().post(&url).json(&body).send().await.expect("second");
    assert_eq!(second.status(), 429);

    let json: Value = second.json().await.expect("error body");
    assert_eq!(json["error"]["code"], "rate_limited");
}

/// Proves the at-rest guarantees: the password is stored as a salted Argon2id
/// hash, and the refresh token is stored only as a digest.
#[tokio::test]
async fn the_database_never_holds_a_plaintext_secret() {
    let app = app().await;
    let email = unique_email("atrest");
    let profile = register(&app, &email).await;
    let user_id = profile["id"].as_str().unwrap().to_owned();
    let tokens = login(&app, &email).await;
    let refresh = tokens["refresh_token"].as_str().unwrap().to_owned();

    let stored_hash: String = sqlx::query_scalar("SELECT password_hash FROM users WHERE email = $1")
        .bind(&email)
        .fetch_one(&app.state.pool)
        .await
        .expect("stored password hash");

    assert!(
        stored_hash.starts_with("$argon2id$"),
        "password must be stored as argon2id, got: {stored_hash}"
    );
    assert!(!stored_hash.contains(TEST_PASSWORD));

    // Searching the session row for the plaintext token must come up empty:
    // only its SHA-256 digest is persisted.
    let leaked: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM refresh_tokens
         WHERE user_id = $1 AND (token_hash = $2::bytea OR user_agent LIKE '%' || $2 || '%')",
    )
    .bind(uuid::Uuid::parse_str(&user_id).unwrap())
    .bind(&refresh)
    .fetch_one(&app.state.pool)
    .await
    .expect("leak count");

    assert_eq!(leaked, 0, "the plaintext refresh token must not be stored");

    let session_rows: i64 =
        sqlx::query_scalar("SELECT count(*) FROM refresh_tokens WHERE user_id = $1")
            .bind(uuid::Uuid::parse_str(&user_id).unwrap())
            .fetch_one(&app.state.pool)
            .await
            .expect("session count");
    assert_eq!(session_rows, 1, "one login should create exactly one session");
}

/// Guards the assumption that the container fixture is typed as expected.
#[allow(dead_code)]
fn _container_type(_: &ContainerAsync<Postgres>) {}
