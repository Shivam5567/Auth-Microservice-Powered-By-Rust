//! Integration tests for the downstream-service registry and the admin panel.
//!
//! The central claim under test is that removing a service actually stops its
//! tokens working, not just that a row changed status.

mod harness;

use harness::{TEST_PASSWORD, TestApp, client, unique_email};
use serde_json::{Value, json};

async fn app() -> harness::TestApp {
    harness::start().await
}

async fn register(app: &TestApp, email: &str) -> Value {
    client()
        .post(app.url("/api/v1/auth/register"))
        .json(&json!({ "email": email, "password": TEST_PASSWORD }))
        .send()
        .await
        .expect("register request")
        .json()
        .await
        .expect("register body")
}

async fn login(app: &TestApp, email: &str, service: Option<&str>) -> Value {
    let mut body = json!({ "email": email, "password": TEST_PASSWORD });
    if let Some(service) = service {
        body["service"] = json!(service);
    }
    let response = client()
        .post(app.url("/api/v1/auth/login"))
        .json(&body)
        .send()
        .await
        .expect("login request");
    response.json().await.expect("login body")
}

/// Every test needs an admin token, and creating one needs an admin, so this
/// promotes its own freshly registered account directly. That stands in for
/// the real bootstrap path, which is covered separately below.
async fn admin_token(app: &TestApp) -> String {
    let email = unique_email("root");
    let profile = register(app, &email).await;
    let id = uuid::Uuid::parse_str(profile["id"].as_str().unwrap()).expect("user id");

    sqlx::query(
        "INSERT INTO user_roles (user_id, role_id)
         SELECT $1, id FROM roles WHERE name = 'admin'
         ON CONFLICT DO NOTHING",
    )
    .bind(id)
    .execute(&app.state.pool)
    .await
    .expect("promote to admin");

    login(app, &email, None).await["access_token"]
        .as_str()
        .expect("access token")
        .to_owned()
}

/// Registers a service and asserts it worked, so a test never silently logs
/// in for a service that does not exist.
async fn register_service(app: &TestApp, admin: &str, name: &str) {
    let response = client()
        .post(app.url("/api/v1/admin/services"))
        .bearer_auth(admin)
        .json(&json!({ "name": name }))
        .send()
        .await
        .expect("create service");
    assert_eq!(response.status(), 201, "could not register {name}");
}

fn admin_request(app: &TestApp, token: &str) -> reqwest::RequestBuilder {
    client()
        .get(app.url("/api/v1/admin/services"))
        .bearer_auth(token)
}

#[tokio::test]
async fn an_admin_can_register_a_service() {
    let app = app().await;
    let token = admin_token(&app).await;

    let response = client()
        .post(app.url("/api/v1/admin/services"))
        .bearer_auth(&token)
        .json(&json!({
            "name": "Billing API",
            "description": "invoicing",
            "scopes": ["orders:read", "orders:write"]
        }))
        .send()
        .await
        .expect("create request");

    assert_eq!(response.status(), 201, "expected the service to be created");
    let body: Value = response.json().await.expect("create body");

    assert_eq!(body["name"], "billing-api", "name should be normalised");
    assert_eq!(body["status"], "active");
    assert_eq!(body["token_version"], 0);
    assert_eq!(body["scopes"], json!(["orders:read", "orders:write"]));
    assert_eq!(body["description"], "invoicing");
}

#[tokio::test]
async fn the_name_is_normalised_so_duplicates_are_caught() {
    let app = app().await;
    let token = admin_token(&app).await;

    let first = client()
        .post(app.url("/api/v1/admin/services"))
        .bearer_auth(&token)
        .json(&json!({ "name": "Billing API" }))
        .send()
        .await
        .expect("create");
    assert_eq!(first.status(), 201);

    // The same service spelled differently must not create a second row.
    let second = client()
        .post(app.url("/api/v1/admin/services"))
        .bearer_auth(&token)
        .json(&json!({ "name": "  billing_api " }))
        .send()
        .await
        .expect("duplicate create");
    assert_eq!(second.status(), 409);
}

#[tokio::test]
async fn a_non_admin_cannot_reach_the_admin_api() {
    let app = app().await;
    let email = unique_email("plain");
    register(&app, &email).await;
    let token = login(&app, &email, None).await["access_token"]
        .as_str()
        .unwrap()
        .to_owned();

    let response = admin_request(&app, &token).send().await.expect("list");
    assert_eq!(response.status(), 403, "an ordinary user must be refused");

    let anonymous = client()
        .get(app.url("/api/v1/admin/services"))
        .send()
        .await
        .expect("list");
    assert_eq!(anonymous.status(), 401, "no token must be refused");
}

#[tokio::test]
async fn listing_can_be_filtered_and_searched() {
    let app = app().await;
    let token = admin_token(&app).await;

    for name in ["search-alpha", "search-beta", "other-gamma"] {
        let created = client()
            .post(app.url("/api/v1/admin/services"))
            .bearer_auth(&token)
            .json(&json!({ "name": name }))
            .send()
            .await
            .expect("create");
        assert_eq!(created.status(), 201);
    }

    let listed: Value = client()
        .get(app.url("/api/v1/admin/services?search=search-"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("search")
        .json()
        .await
        .expect("search body");
    assert_eq!(listed["services"].as_array().unwrap().len(), 2);

    let all: Value = client()
        .get(app.url("/api/v1/admin/services"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list")
        .json()
        .await
        .expect("list body");
    assert_eq!(all["total"], 3);
    // Sorted by name, which is what the panel relies on for a stable view.
    let names: Vec<&str> = all["services"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["name"].as_str().unwrap())
        .collect();
    let mut sorted = names.clone();
    sorted.sort_unstable();
    assert_eq!(names, sorted);
}

#[tokio::test]
async fn an_unknown_status_filter_is_rejected() {
    let app = app().await;
    let token = admin_token(&app).await;

    let response = client()
        .get(app.url("/api/v1/admin/services?status=actve"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list");

    assert_eq!(response.status(), 400);
}

#[tokio::test]
async fn an_invalid_service_name_is_rejected() {
    let app = app().await;
    let token = admin_token(&app).await;

    let response = client()
        .post(app.url("/api/v1/admin/services"))
        .bearer_auth(&token)
        .json(&json!({ "name": "a" }))
        .send()
        .await
        .expect("create");

    assert_eq!(response.status(), 400);
    let body: Value = response.json().await.expect("error body");
    assert_eq!(body["error"]["code"], "validation_failed");
}

/// The point of the whole feature: removing a service must invalidate the
/// tokens already issued for it.
#[tokio::test]
async fn removing_a_service_stops_its_existing_tokens_working() {
    let app = app().await;
    let admin = admin_token(&app).await;
    register_service(&app, &admin, "doomed-service").await;

    let user = unique_email("consumer");
    register(&app, &user).await;
    let tokens = login(&app, &user, Some("doomed-service")).await;
    let access = tokens["access_token"].as_str().unwrap().to_owned();

    // The token works while the service is registered.
    let before = client()
        .get(app.url("/api/v1/auth/me"))
        .bearer_auth(&access)
        .send()
        .await
        .expect("me before");
    assert_eq!(before.status(), 200);

    let removed = client()
        .delete(app.url("/api/v1/admin/services/doomed-service"))
        .bearer_auth(&admin)
        .send()
        .await
        .expect("remove");
    assert_eq!(removed.status(), 200);
    let body: Value = removed.json().await.expect("remove body");
    assert_eq!(body["status"], "disabled");
    assert_eq!(
        body["token_version"], 1,
        "removal must bump the version to revoke live tokens"
    );

    // The very same token must now be refused.
    let after = client()
        .get(app.url("/api/v1/auth/me"))
        .bearer_auth(&access)
        .send()
        .await
        .expect("me after");
    assert_eq!(after.status(), 403, "a removed service's tokens must die");
}

#[tokio::test]
async fn a_removed_service_cannot_be_logged_into() {
    let app = app().await;
    let admin = admin_token(&app).await;

    client()
        .post(app.url("/api/v1/admin/services"))
        .bearer_auth(&admin)
        .json(&json!({ "name": "closed-service" }))
        .send()
        .await
        .expect("create");

    let user = unique_email("late");
    register(&app, &user).await;

    client()
        .delete(app.url("/api/v1/admin/services/closed-service"))
        .bearer_auth(&admin)
        .send()
        .await
        .expect("remove");

    let response = client()
        .post(app.url("/api/v1/auth/login"))
        .json(&json!({
            "email": user,
            "password": TEST_PASSWORD,
            "service": "closed-service"
        }))
        .send()
        .await
        .expect("login");
    assert_eq!(response.status(), 403);
}

/// Otherwise a decommissioned service's live session could be kept alive by
/// exchanging its refresh token.
#[tokio::test]
async fn a_removed_services_session_cannot_be_refreshed() {
    let app = app().await;
    let admin = admin_token(&app).await;
    register_service(&app, &admin, "ephemeral-service").await;

    let user = unique_email("refresher");
    register(&app, &user).await;
    let tokens = login(&app, &user, Some("ephemeral-service")).await;
    let refresh = tokens["refresh_token"].as_str().unwrap().to_owned();

    client()
        .delete(app.url("/api/v1/admin/services/ephemeral-service"))
        .bearer_auth(&admin)
        .send()
        .await
        .expect("remove");

    let response = client()
        .post(app.url("/api/v1/auth/refresh"))
        .json(&json!({ "refresh_token": refresh }))
        .send()
        .await
        .expect("refresh");
    assert_eq!(
        response.status(),
        403,
        "refresh must respect decommissioning"
    );
}

#[tokio::test]
async fn a_refreshed_token_stays_bound_to_its_service() {
    let app = app().await;
    let admin = admin_token(&app).await;
    register_service(&app, &admin, "sticky-service").await;

    let user = unique_email("bound");
    register(&app, &user).await;
    let first = login(&app, &user, Some("sticky-service")).await;

    let rotated: Value = client()
        .post(app.url("/api/v1/auth/refresh"))
        .json(&json!({ "refresh_token": first["refresh_token"] }))
        .send()
        .await
        .expect("refresh")
        .json()
        .await
        .expect("refresh body");

    // The successor must still be rejected after removal, which only holds if
    // the service binding was carried across the rotation.
    let access = rotated["access_token"].as_str().unwrap().to_owned();
    assert_eq!(
        client()
            .get(app.url("/api/v1/auth/me"))
            .bearer_auth(&access)
            .send()
            .await
            .expect("me")
            .status(),
        200
    );

    client()
        .delete(app.url("/api/v1/admin/services/sticky-service"))
        .bearer_auth(&admin)
        .send()
        .await
        .expect("remove");

    assert_eq!(
        client()
            .get(app.url("/api/v1/auth/me"))
            .bearer_auth(&access)
            .send()
            .await
            .expect("me after")
            .status(),
        403,
        "a rotated token must not escape its service's revocation"
    );
}

/// A token minted without naming a service belongs to nobody, so one service
/// being removed must not affect it.
#[tokio::test]
async fn removing_one_service_leaves_unbound_tokens_alone() {
    let app = app().await;
    let admin = admin_token(&app).await;

    let user = unique_email("generalist");
    register(&app, &user).await;
    let tokens = login(&app, &user, None).await;
    let access = tokens["access_token"].as_str().unwrap().to_owned();

    client()
        .post(app.url("/api/v1/admin/services"))
        .bearer_auth(&admin)
        .json(&json!({ "name": "unrelated" }))
        .send()
        .await
        .expect("create");
    client()
        .delete(app.url("/api/v1/admin/services/unrelated"))
        .bearer_auth(&admin)
        .send()
        .await
        .expect("remove");

    assert_eq!(
        client()
            .get(app.url("/api/v1/auth/me"))
            .bearer_auth(&access)
            .send()
            .await
            .expect("me")
            .status(),
        200,
        "an unbound token must survive another service being removed"
    );
}

#[tokio::test]
async fn removing_twice_is_not_an_error() {
    let app = app().await;
    let admin = admin_token(&app).await;

    client()
        .post(app.url("/api/v1/admin/services"))
        .bearer_auth(&admin)
        .json(&json!({ "name": "twice-removed" }))
        .send()
        .await
        .expect("create");

    let first: Value = client()
        .delete(app.url("/api/v1/admin/services/twice-removed"))
        .bearer_auth(&admin)
        .send()
        .await
        .expect("first remove")
        .json()
        .await
        .expect("first body");

    let second: Value = client()
        .delete(app.url("/api/v1/admin/services/twice-removed"))
        .bearer_auth(&admin)
        .send()
        .await
        .expect("second remove")
        .json()
        .await
        .expect("second body");

    assert_eq!(first["token_version"], 1);
    assert_eq!(
        second["token_version"], 1,
        "removing again must not bump the version and confuse the audit trail"
    );
}

#[tokio::test]
async fn a_restored_service_works_again_but_old_tokens_do_not() {
    let app = app().await;
    let admin = admin_token(&app).await;
    register_service(&app, &admin, "cycled-service").await;

    let user = unique_email("cycled");
    register(&app, &user).await;
    let stale = login(&app, &user, Some("cycled-service")).await["access_token"]
        .as_str()
        .unwrap()
        .to_owned();

    client()
        .delete(app.url("/api/v1/admin/services/cycled-service"))
        .bearer_auth(&admin)
        .send()
        .await
        .expect("remove");

    let restored: Value = client()
        .post(app.url("/api/v1/admin/services/cycled-service/restore"))
        .bearer_auth(&admin)
        .send()
        .await
        .expect("restore")
        .json()
        .await
        .expect("restore body");
    assert_eq!(restored["status"], "active");
    assert_eq!(
        restored["token_version"], 2,
        "restoring must bump the version so pre-removal tokens stay dead"
    );

    // A fresh login works again.
    let fresh = login(&app, &user, Some("cycled-service")).await;
    assert_eq!(
        client()
            .get(app.url("/api/v1/auth/me"))
            .bearer_auth(fresh["access_token"].as_str().unwrap())
            .send()
            .await
            .expect("me")
            .status(),
        200
    );

    // The token from before the removal does not come back to life.
    assert_eq!(
        client()
            .get(app.url("/api/v1/auth/me"))
            .bearer_auth(&stale)
            .send()
            .await
            .expect("me stale")
            .status(),
        401,
        "a pre-removal token must stay revoked after a restore"
    );
}

#[tokio::test]
async fn logging_in_for_an_unregistered_service_is_refused() {
    let app = app().await;
    let user = unique_email("wrongtarget");
    register(&app, &user).await;

    let response = client()
        .post(app.url("/api/v1/auth/login"))
        .json(&json!({
            "email": user,
            "password": TEST_PASSWORD,
            "service": "never-registered"
        }))
        .send()
        .await
        .expect("login");

    assert_eq!(response.status(), 400);
    let body: Value = response.json().await.expect("error body");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("not a registered service"),
        "got: {body}"
    );
}

#[tokio::test]
async fn scopes_and_description_can_be_edited() {
    let app = app().await;
    let admin = admin_token(&app).await;

    client()
        .post(app.url("/api/v1/admin/services"))
        .bearer_auth(&admin)
        .json(&json!({ "name": "editable", "description": "old", "scopes": ["a"] }))
        .send()
        .await
        .expect("create");

    let updated: Value = client()
        .patch(app.url("/api/v1/admin/services/editable"))
        .bearer_auth(&admin)
        .json(&json!({ "description": "new", "scopes": ["b", "a", "b"] }))
        .send()
        .await
        .expect("patch")
        .json()
        .await
        .expect("patch body");

    assert_eq!(updated["description"], "new");
    assert_eq!(
        updated["scopes"],
        json!(["a", "b"]),
        "scopes should be sorted and de-duplicated"
    );
}

#[tokio::test]
async fn the_summary_and_event_log_reflect_the_changes() {
    let app = app().await;
    let admin = admin_token(&app).await;

    let before: Value = client()
        .get(app.url("/api/v1/admin/services/summary"))
        .bearer_auth(&admin)
        .send()
        .await
        .expect("summary")
        .json()
        .await
        .expect("summary body");
    let starting_total = before["total"].as_i64().unwrap();

    client()
        .post(app.url("/api/v1/admin/services"))
        .bearer_auth(&admin)
        .json(&json!({ "name": "audited" }))
        .send()
        .await
        .expect("create");
    client()
        .delete(app.url("/api/v1/admin/services/audited"))
        .bearer_auth(&admin)
        .send()
        .await
        .expect("remove");

    let after: Value = client()
        .get(app.url("/api/v1/admin/services/summary"))
        .bearer_auth(&admin)
        .send()
        .await
        .expect("summary")
        .json()
        .await
        .expect("summary body");
    assert_eq!(after["total"].as_i64().unwrap(), starting_total + 1);
    assert_eq!(
        after["disabled"].as_i64().unwrap(),
        before["disabled"].as_i64().unwrap() + 1
    );

    let events: Value = client()
        .get(app.url("/api/v1/admin/services/events"))
        .bearer_auth(&admin)
        .send()
        .await
        .expect("events")
        .json()
        .await
        .expect("events body");

    let actions: Vec<&str> = events
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["service"] == "audited")
        .map(|e| e["action"].as_str().unwrap())
        .collect();
    assert!(actions.contains(&"created"), "got {actions:?}");
    assert!(actions.contains(&"removed"), "got {actions:?}");
}

#[tokio::test]
async fn acting_on_an_unknown_service_is_a_404() {
    let app = app().await;
    let admin = admin_token(&app).await;

    for (method, path) in [
        ("GET", "/api/v1/admin/services/ghost"),
        ("DELETE", "/api/v1/admin/services/ghost"),
    ] {
        let request = client()
            .request(
                reqwest::Method::from_bytes(method.as_bytes()).unwrap(),
                app.url(path),
            )
            .bearer_auth(&admin);
        let response = request.send().await.expect("request");
        assert_eq!(response.status(), 404, "{method} {path}");
    }
}

/// `time`'s default serde form is a tuple, which would put
/// `[seconds, nanoseconds, ..]` in the body instead of a readable date.
#[tokio::test]
async fn admin_timestamps_are_rfc3339_strings() {
    let app = app().await;
    let admin = admin_token(&app).await;

    client()
        .post(app.url("/api/v1/admin/services"))
        .bearer_auth(&admin)
        .json(&json!({ "name": "stamped" }))
        .send()
        .await
        .expect("create");

    let service: Value = client()
        .get(app.url("/api/v1/admin/services/stamped"))
        .bearer_auth(&admin)
        .send()
        .await
        .expect("get")
        .json()
        .await
        .expect("get body");

    for field in ["created_at", "updated_at"] {
        let value = service[field].as_str();
        assert!(value.is_some(), "{field} should be a string, got {service}");
        assert!(
            value.unwrap().contains('T') && value.unwrap().ends_with('Z'),
            "{field} should look like RFC 3339, got {:?}",
            value
        );
    }

    let events: Value = client()
        .get(app.url("/api/v1/admin/services/events"))
        .bearer_auth(&admin)
        .send()
        .await
        .expect("events")
        .json()
        .await
        .expect("events body");

    let first = &events.as_array().unwrap()[0];
    assert!(
        first["at"].as_str().is_some(),
        "event timestamps should be strings too, got {first}"
    );
}

#[tokio::test]
async fn the_admin_panel_page_is_served() {
    let app = app().await;

    let response = client()
        .get(app.url("/admin/"))
        .send()
        .await
        .expect("panel request");
    assert_eq!(response.status(), 200);

    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    assert!(content_type.starts_with("text/html"), "got {content_type}");

    let body = response.text().await.expect("panel body");
    assert!(body.contains(r#"data-panel="admin-services""#));
    assert!(body.contains("Remove"), "the panel needs a remove control");
    assert!(
        body.contains("Restore"),
        "the panel needs a restore control"
    );
}

#[tokio::test]
async fn the_admin_path_redirects_to_the_panel() {
    let app = app().await;

    let response = client()
        .get(app.url("/admin"))
        .send()
        .await
        .expect("redirect request");

    assert!(
        response.status().is_redirection(),
        "expected a redirect, got {}",
        response.status()
    );
    assert_eq!(
        response
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok()),
        Some("/admin/")
    );
}

/// Without a way to get the first admin token the panel would be unreachable.
#[tokio::test]
async fn a_bootstrapped_address_receives_the_admin_role() {
    let email = unique_email("founder");
    let app = harness::start_with_bootstrapped_admins(&email).await;

    let profile = register(&app, &email).await;
    assert!(
        profile["roles"]
            .as_array()
            .unwrap()
            .contains(&json!("admin")),
        "bootstrap address should get the admin role, got {profile}"
    );

    let token = login(&app, &email, None).await["access_token"]
        .as_str()
        .unwrap()
        .to_owned();

    let response = admin_request(&app, &token).send().await.expect("list");
    assert_eq!(response.status(), 200, "the bootstrap admin must get in");
}

#[tokio::test]
async fn an_unlisted_address_does_not_receive_the_admin_role() {
    let app = harness::start_with_bootstrapped_admins("someone-else@example.com").await;

    let profile = register(&app, &unique_email("nobody")).await;
    assert_eq!(profile["roles"], json!(["user"]));
}
