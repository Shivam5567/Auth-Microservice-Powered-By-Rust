use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::{AppError, AppResult, IntoAppResult as _};

pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

pub async fn connect(url: &str, max_connections: u32) -> AppResult<PgPool> {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(max_connections)
        .acquire_timeout(std::time::Duration::from_secs(10))
        .connect(url)
        .await
        .into_app()?;

    sqlx::query("SELECT 1").execute(&pool).await.into_app()?;
    Ok(pool)
}

pub async fn migrate(pool: &PgPool) -> AppResult<()> {
    MIGRATOR.run(pool).await.map_err(|e| {
        tracing::error!(error = %e, "migration failed");
        AppError::internal("database migration failed")
    })
}

pub async fn ping(pool: &PgPool) -> Result<OffsetDateTime, sqlx::Error> {
    sqlx::query_scalar("SELECT now()").fetch_one(pool).await
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Order {
    pub id: Uuid,
    /// The auth service's user id. This is the only thing the two services
    /// share, and it is what ties an order to the person who placed it.
    pub user_id: Uuid,
    pub status: String,
    pub total_cents: i64,
    pub currency: String,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct OrderItem {
    pub id: Uuid,
    pub order_id: Uuid,
    pub sku: String,
    pub name: String,
    pub quantity: i32,
    pub unit_price_cents: i64,
}

pub struct NewOrder<'a> {
    pub user_id: Uuid,
    pub currency: &'a str,
}

pub struct NewItem<'a> {
    pub sku: &'a str,
    pub name: &'a str,
    pub quantity: i32,
    pub unit_price_cents: i64,
}

/// Creates an order and its items in one transaction.
///
/// The total is computed from the items rather than accepted from the client,
/// so a caller cannot name their own price.
pub async fn create_order(
    pool: &PgPool,
    new: NewOrder<'_>,
    items: &[NewItem<'_>],
) -> AppResult<(Order, Vec<OrderItem>)> {
    if items.is_empty() {
        return Err(AppError::validation("an order needs at least one item"));
    }
    if items.iter().any(|i| i.quantity <= 0) {
        return Err(AppError::validation("item quantities must be positive"));
    }
    if items.len() > 100 {
        return Err(AppError::validation("an order may hold at most 100 lines"));
    }

    let total: i64 = items
        .iter()
        .map(|i| i.unit_price_cents * i.quantity as i64)
        .sum();

    let mut tx = pool.begin().await.map_err(|e| {
        tracing::error!(error = %e, "failed to begin order transaction");
        AppError::internal("database error")
    })?;

    let order: Order = sqlx::query_as(
        "INSERT INTO orders (user_id, total_cents, currency)
         VALUES ($1, $2, $3)
         RETURNING id, user_id, status, total_cents, currency, created_at, updated_at",
    )
    .bind(new.user_id)
    .bind(total)
    .bind(new.currency)
    .fetch_one(&mut *tx)
    .await
    .into_app()?;

    let mut stored = Vec::with_capacity(items.len());
    for item in items {
        let row: OrderItem = sqlx::query_as(
            "INSERT INTO order_items (order_id, sku, name, quantity, unit_price_cents)
             VALUES ($1, $2, $3, $4, $5)
             RETURNING id, order_id, sku, name, quantity, unit_price_cents",
        )
        .bind(order.id)
        .bind(item.sku)
        .bind(item.name)
        .bind(item.quantity)
        .bind(item.unit_price_cents)
        .fetch_one(&mut *tx)
        .await
        .into_app()?;

        stored.push(row);
    }

    tx.commit().await.map_err(|e| {
        tracing::error!(error = %e, "failed to commit order");
        AppError::internal("database error")
    })?;

    Ok((order, stored))
}

pub async fn find_order(pool: &PgPool, id: Uuid) -> AppResult<Option<Order>> {
    sqlx::query_as(
        "SELECT id, user_id, status, total_cents, currency, created_at, updated_at
         FROM orders WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await
    .into_app()
}

pub async fn items_for_order(pool: &PgPool, order_id: Uuid) -> AppResult<Vec<OrderItem>> {
    sqlx::query_as(
        "SELECT id, order_id, sku, name, quantity, unit_price_cents
         FROM order_items WHERE order_id = $1 ORDER BY sku",
    )
    .bind(order_id)
    .fetch_all(pool)
    .await
    .into_app()
}

pub async fn list_orders(pool: &PgPool, user_id: Uuid, limit: i64) -> AppResult<Vec<Order>> {
    sqlx::query_as(
        "SELECT id, user_id, status, total_cents, currency, created_at, updated_at
         FROM orders WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2",
    )
    .bind(user_id)
    .bind(limit.clamp(1, 100))
    .fetch_all(pool)
    .await
    .into_app()
}

/// Every order, for an administrator.
pub async fn list_all_orders(pool: &PgPool, limit: i64) -> AppResult<Vec<Order>> {
    sqlx::query_as(
        "SELECT id, user_id, status, total_cents, currency, created_at, updated_at
         FROM orders ORDER BY created_at DESC LIMIT $1",
    )
    .bind(limit.clamp(1, 100))
    .fetch_all(pool)
    .await
    .into_app()
}

/// Moves an order to `refunded`, but only from a state that can be refunded.
pub async fn refund(pool: &PgPool, id: Uuid) -> AppResult<Order> {
    let order = sqlx::query_as(
        "UPDATE orders
         SET status = 'refunded', updated_at = now()
         WHERE id = $1 AND status IN ('pending', 'paid')
         RETURNING id, user_id, status, total_cents, currency, created_at, updated_at",
    )
    .bind(id)
    .fetch_optional(pool)
    .await
    .into_app()?
    .ok_or_else(|| {
        // Either it does not exist, or it was already refunded. Both are 404:
        // telling the two apart would leak order state to non-owners.
        AppError::not_found("no refundable order with that id")
    })?;

    Ok(order)
}

pub async fn count_orders(pool: &PgPool) -> AppResult<i64> {
    sqlx::query_scalar("SELECT count(*) FROM orders")
        .fetch_one(pool)
        .await
        .into_app()
}
