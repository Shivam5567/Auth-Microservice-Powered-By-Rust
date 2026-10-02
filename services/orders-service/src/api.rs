use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::caller::CurrentUser;
use crate::cookie;
use crate::db::{self, NewItem, NewOrder};
use crate::error::{AppError, AppResult};
use crate::state::AppState;

/// A deliberately small catalog. A real one would be its own service; the point
/// here is the order flow, not the catalogue.
const CATALOG: &[(&str, &str, i64)] = &[
    ("SKU-KEYBOARD", "Mechanical keyboard", 12900),
    ("SKU-MOUSE", "Wireless mouse", 4500),
    ("SKU-MONITOR", "27 inch monitor", 32900),
    ("SKU-CABLE", "USB-C cable", 1500),
];

// ---------------------------------------------------------------- public

/// The storefront page. No authentication: browsing is open.
pub async fn index() -> Redirect {
    Redirect::permanent("/shop/")
}

pub async fn shop(State(_state): State<AppState>) -> Response {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        include_str!("../assets/index.html"),
    )
        .into_response()
}

#[derive(Debug, Serialize)]
pub struct CatalogItem {
    pub sku: &'static str,
    pub name: &'static str,
    pub price_cents: i64,
    pub price: String,
}

pub async fn catalog() -> Json<Vec<CatalogItem>> {
    Json(
        CATALOG
            .iter()
            .map(|(sku, name, price_cents)| CatalogItem {
                sku,
                name,
                price_cents: *price_cents,
                price: format!("{}.{:02}", price_cents / 100, price_cents % 100),
            })
            .collect(),
    )
}

pub async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok", "service": "orders-service" }))
}

/// Readiness: the database answers, and reports which token strategy is live.
#[derive(Debug, Serialize)]
pub struct ReadyResponse {
    pub status: &'static str,
    pub service: &'static str,
    pub database: &'static str,
    pub orders: i64,
    pub token_check: String,
    /// RFC 3339 rather than the crate's default tuple form, which would put a
    /// raw `[seconds, nanoseconds, ..]` array in the body.
    #[serde(with = "time::serde::rfc3339")]
    pub checked_at: OffsetDateTime,
}

pub async fn ready(State(state): State<AppState>) -> AppResult<Json<ReadyResponse>> {
    let checked_at = db::ping(&state.pool).await.map_err(|e| {
        tracing::error!(error = %e, "readiness probe failed");
        AppError::internal("database is unreachable")
    })?;

    Ok(Json(ReadyResponse {
        status: "ok",
        service: "orders-service",
        database: "connected",
        orders: db::count_orders(&state.pool).await?,
        token_check: format!("{:?}", state.auth.mode()).to_lowercase(),
        checked_at,
    }))
}

// ------------------------------------------------------------------ auth

#[derive(Debug, Deserialize)]
pub struct LoginBody {
    pub email: String,
    pub password: String,
    /// Bind the session to this service, so an operator can revoke it in one move.
    #[serde(default)]
    pub bind_to_service: Option<bool>,
    #[serde(default)]
    pub register: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct AccessOnly {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: u64,
    pub user: serde_json::Value,
    pub token_check: String,
}

/// Signs a user in and puts the refresh token in a cookie.
///
/// The refresh token is never sent to JavaScript. Anything a page can read, an
/// injected script can read, and a refresh token is a long-lived credential.
pub async fn login(
    State(state): State<AppState>,
    Json(body): Json<LoginBody>,
) -> AppResult<Response> {
    let bind = body.bind_to_service.unwrap_or(true);

    if body.register.unwrap_or(false) {
        state.auth.register(&body.email, &body.password).await?;
    }

    let pair = state.auth.login(&body.email, &body.password, bind).await?;

    let user = whoami_payload(&state, &pair.access_token).await;

    let body = Json(AccessOnly {
        access_token: pair.access_token,
        token_type: "Bearer",
        expires_in: pair.expires_in,
        user,
        token_check: format!("{:?}", state.auth.mode()).to_lowercase(),
    });

    Ok((
        cookie::jar_with_refresh(&pair.refresh_token, state.refresh_cookie_ttl),
        body,
    )
        .into_response())
}

/// Exchanges the refresh cookie for a new access token.
///
/// Only ever one at a time per session. The auth service treats a second use of
/// the same refresh token as theft and revokes the family, so the browser has
/// to serialise these calls.
pub async fn refresh(
    State(state): State<AppState>,
    jar: axum_extra::extract::cookie::CookieJar,
) -> AppResult<Response> {
    let token = cookie::read_refresh(&jar)?;

    let pair = state.auth.refresh(&token).await?;

    let user = whoami_payload(&state, &pair.access_token).await;

    let body = Json(AccessOnly {
        access_token: pair.access_token,
        token_type: "Bearer",
        expires_in: pair.expires_in,
        user,
        token_check: format!("{:?}", state.auth.mode()).to_lowercase(),
    });

    Ok((
        cookie::jar_with_refresh(&pair.refresh_token, state.refresh_cookie_ttl),
        body,
    )
        .into_response())
}

pub async fn logout(
    State(state): State<AppState>,
    jar: axum_extra::extract::cookie::CookieJar,
) -> AppResult<Response> {
    if let Ok(token) = cookie::read_refresh(&jar)
        && let Err(err) = state.auth.logout(&token).await
    {
        // The cookie is cleared regardless, so a user is never left holding a
        // credential this service can no longer revoke.
        tracing::warn!(error = %err, "logout could not reach the auth service");
    }

    Ok((cookie::jar_without_refresh(), StatusCode::NO_CONTENT).into_response())
}

#[derive(Debug, Serialize)]
pub struct WhoAmI {
    pub user_id: Uuid,
    pub roles: Vec<String>,
    pub established_by: String,
    pub orders: i64,
}

/// Reports who the caller is, and how this service figured that out.
pub async fn whoami(State(state): State<AppState>, user: CurrentUser) -> AppResult<Json<WhoAmI>> {
    let orders = db::list_orders(&state.pool, user.user_id, 100).await?.len() as i64;

    Ok(Json(WhoAmI {
        user_id: user.user_id,
        roles: user.roles.clone(),
        established_by: format!("{:?}", user.established_by).to_lowercase(),
        orders,
    }))
}

async fn whoami_payload(state: &AppState, access_token: &str) -> serde_json::Value {
    match state.auth.caller(access_token).await {
        Ok(caller) => serde_json::json!({
            "id": caller.user_id,
            "roles": caller.roles,
        }),
        Err(_) => serde_json::json!({ "id": null, "roles": [] }),
    }
}

// ---------------------------------------------------------------- orders

#[derive(Debug, Deserialize)]
pub struct CreateOrderBody {
    pub items: Vec<OrderLineRequest>,
    #[serde(default = "default_currency")]
    pub currency: String,
}

fn default_currency() -> String {
    "USD".to_owned()
}

#[derive(Debug, Deserialize)]
pub struct OrderLineRequest {
    pub sku: String,
    pub quantity: i32,
}

#[derive(Debug, Serialize)]
pub struct OrderResponse {
    pub id: Uuid,
    pub user_id: Uuid,
    pub status: String,
    pub total_cents: i64,
    pub total: String,
    pub currency: String,
    pub items: Vec<LineResponse>,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Serialize)]
pub struct LineResponse {
    pub sku: String,
    pub name: String,
    pub quantity: i32,
    pub unit_price_cents: i64,
}

fn money(cents: i64) -> String {
    format!("{}.{:02}", cents.abs() / 100, cents.abs() % 100)
}

async fn render(pool: &sqlx::PgPool, order: db::Order) -> AppResult<OrderResponse> {
    let items = db::items_for_order(pool, order.id).await?;
    Ok(OrderResponse {
        id: order.id,
        user_id: order.user_id,
        status: order.status.clone(),
        total_cents: order.total_cents,
        total: money(order.total_cents),
        currency: order.currency.clone(),
        items: items
            .into_iter()
            .map(|i| LineResponse {
                sku: i.sku,
                name: i.name,
                quantity: i.quantity,
                unit_price_cents: i.unit_price_cents,
            })
            .collect(),
        created_at: order.created_at,
    })
}

/// Places an order for whoever is signed in.
pub async fn create_order(
    State(state): State<AppState>,
    user: CurrentUser,
    Json(body): Json<CreateOrderBody>,
) -> AppResult<impl IntoResponse> {
    // Prices come from the server's catalog, never from the request.
    let mut items = Vec::with_capacity(body.items.len());
    for line in &body.items {
        let Some((sku, name, price)) = CATALOG.iter().find(|(s, _, _)| *s == line.sku) else {
            return Err(AppError::validation(format!(
                "unknown product '{}'",
                line.sku
            )));
        };
        items.push(NewItem {
            sku,
            name,
            quantity: line.quantity,
            unit_price_cents: *price,
        });
    }

    let (order, _) = db::create_order(
        &state.pool,
        NewOrder {
            user_id: user.user_id,
            currency: &body.currency,
        },
        &items,
    )
    .await?;

    tracing::info!(
        order_id = %order.id,
        user_id = %user.user_id,
        total_cents = order.total_cents,
        "order placed"
    );

    Ok((StatusCode::CREATED, Json(render(&state.pool, order).await?)).into_response())
}

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    pub limit: Option<i64>,
    /// Administrators may pass `all=true` to see every customer's orders.
    #[serde(default)]
    pub all: Option<bool>,
}

pub async fn list_orders(
    State(state): State<AppState>,
    user: CurrentUser,
    Query(query): Query<ListQuery>,
) -> AppResult<Json<Vec<OrderResponse>>> {
    let limit = query.limit.unwrap_or(50);

    let orders = if query.all.unwrap_or(false) {
        user.require_role("admin")?;
        db::list_all_orders(&state.pool, limit).await?
    } else {
        db::list_orders(&state.pool, user.user_id, limit).await?
    };

    let mut out = Vec::with_capacity(orders.len());
    for order in orders {
        out.push(render(&state.pool, order).await?);
    }
    Ok(Json(out))
}

/// Fetches one order.
///
/// A caller who does not own the order gets 404, not 403: a 403 would confirm
/// that the order exists.
pub async fn get_order(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<Uuid>,
) -> AppResult<Json<OrderResponse>> {
    let order = db::find_order(&state.pool, id)
        .await?
        .filter(|o| o.user_id == user.user_id || user.has_role("admin"))
        .ok_or_else(|| AppError::not_found("no order with that id"))?;

    Ok(Json(render(&state.pool, order).await?))
}

/// Refunds an order. Administrators only.
pub async fn refund_order(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<Uuid>,
) -> AppResult<Json<OrderResponse>> {
    user.require_role("admin")?;

    let order = db::refund(&state.pool, id).await?;
    tracing::warn!(order_id = %order.id, refunded_by = %user.user_id, "order refunded");

    Ok(Json(render(&state.pool, order).await?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn money_is_two_decimal_places() {
        assert_eq!(money(0), "0.00");
        assert_eq!(money(5), "0.05");
        assert_eq!(money(4500), "45.00");
        assert_eq!(money(12999), "129.99");
    }

    #[test]
    fn the_catalog_prices_match_what_it_renders() {
        for (_, _, cents) in CATALOG {
            let rendered = money(*cents);
            assert_eq!(rendered.split('.').nth(1).unwrap().len(), 2);
        }
    }

    #[test]
    fn currency_defaults_to_usd() {
        assert_eq!(default_currency(), "USD");
    }

    #[test]
    fn a_login_body_tolerates_omitted_flags() {
        let body: LoginBody =
            serde_json::from_str(r#"{"email":"a@b.com","password":"x"}"#).unwrap();
        assert!(body.bind_to_service.is_none());
        assert!(body.register.is_none());
    }
}
