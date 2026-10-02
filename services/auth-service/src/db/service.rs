use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::domain::service::ServiceName;
use crate::error::{AppResult, IntoAppResult as _, from_sqlx};

const SELECT_COLUMNS: &str =
    "id, name, description, status, scopes, token_version, created_at, updated_at, disabled_at";

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Service {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub status: String,
    pub scopes: Vec<String>,
    pub token_version: i32,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    pub disabled_at: Option<OffsetDateTime>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ServiceEvent {
    pub id: i64,
    pub service_name: String,
    pub action: String,
    pub actor: Option<String>,
    pub detail: Option<String>,
    pub created_at: OffsetDateTime,
}

/// A filter for the admin list view.
#[derive(Debug, Clone, Default)]
pub struct ListFilter {
    /// When set, only services in this state are returned.
    pub status: Option<String>,
    /// Case-insensitive substring match against the name or description.
    pub search: Option<String>,
    pub limit: i64,
    pub offset: i64,
}

pub async fn list(pool: &PgPool, filter: &ListFilter) -> AppResult<Vec<Service>> {
    // A single statement with optional predicates keeps the row-level
    // security rules in one place rather than splicing SQL together.
    sqlx::query_as::<_, Service>(&format!(
        "SELECT {SELECT_COLUMNS} FROM services
         WHERE ($1::text IS NULL OR status = $1)
           AND ($2::text IS NULL OR name ILIKE '%' || $2 || '%' OR description ILIKE '%' || $2 || '%')
         ORDER BY name
         LIMIT $3 OFFSET $4"
    ))
    .bind(filter.status.clone())
    .bind(filter.search.clone())
    .bind(filter.limit.clamp(1, 200))
    .bind(filter.offset.max(0))
    .fetch_all(pool)
    .await
    .into_app()
}

pub async fn count(pool: &PgPool, filter: &ListFilter) -> AppResult<i64> {
    sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM services
         WHERE ($1::text IS NULL OR status = $1)
           AND ($2::text IS NULL OR name ILIKE '%' || $2 || '%' OR description ILIKE '%' || $2 || '%')",
    )
    .bind(filter.status.clone())
    .bind(filter.search.clone())
    .fetch_one(pool)
    .await
    .into_app()
}

pub async fn find_by_name(pool: &PgPool, name: &ServiceName) -> AppResult<Option<Service>> {
    sqlx::query_as::<_, Service>(&format!(
        "SELECT {SELECT_COLUMNS} FROM services WHERE name = $1"
    ))
    .bind(name.as_str())
    .fetch_optional(pool)
    .await
    .into_app()
}

pub enum CreateOutcome {
    Created(Service),
    NameTaken,
}

pub async fn create(
    pool: &PgPool,
    name: &ServiceName,
    description: &str,
    scopes: &[String],
) -> AppResult<CreateOutcome> {
    let inserted = sqlx::query_as::<_, Service>(&format!(
        "INSERT INTO services (name, description, scopes)
         VALUES ($1, $2, $3)
         ON CONFLICT (name) DO NOTHING
         RETURNING {SELECT_COLUMNS}"
    ))
    .bind(name.as_str())
    .bind(description)
    .bind(scopes)
    .fetch_optional(pool)
    .await;

    match inserted {
        Ok(Some(row)) => Ok(CreateOutcome::Created(row)),
        Ok(None) => Ok(CreateOutcome::NameTaken),
        Err(err) if is_unique_violation(&err) => Ok(CreateOutcome::NameTaken),
        Err(err) => Err(from_sqlx(err)),
    }
}

/// The fields an admin is allowed to change. `name` is deliberately absent:
/// renaming a service would strand every token already issued for it.
#[derive(Debug, Clone, Default)]
pub struct Update {
    pub description: Option<String>,
    pub scopes: Option<Vec<String>>,
}

pub async fn update(
    pool: &PgPool,
    name: &ServiceName,
    patch: &Update,
) -> AppResult<Option<Service>> {
    sqlx::query_as::<_, Service>(&format!(
        "UPDATE services
         SET description = COALESCE($2, description),
             scopes = COALESCE($3, scopes),
             updated_at = now()
         WHERE name = $1
         RETURNING {SELECT_COLUMNS}"
    ))
    .bind(name.as_str())
    .bind(patch.description.as_deref())
    .bind(patch.scopes.as_deref())
    .fetch_optional(pool)
    .await
    .into_app()
}

/// Disables a service and bumps its version, which is what makes access tokens
/// already issued for it stop verifying.
///
/// Idempotent: re-removing a disabled service does not bump the version again,
/// so the recorded reason stays accurate.
pub async fn disable(pool: &PgPool, name: &ServiceName) -> AppResult<Option<Service>> {
    sqlx::query_as::<_, Service>(&format!(
        "UPDATE services
         SET status = 'disabled',
             disabled_at = now(),
             token_version = token_version + 1,
             updated_at = now()
         WHERE name = $1 AND status = 'active'
         RETURNING {SELECT_COLUMNS}"
    ))
    .bind(name.as_str())
    .fetch_optional(pool)
    .await
    .into_app()
}

/// Re-enables a service, bumping the version again so tokens minted before it
/// was removed cannot be resurrected.
pub async fn restore(pool: &PgPool, name: &ServiceName) -> AppResult<Option<Service>> {
    sqlx::query_as::<_, Service>(&format!(
        "UPDATE services
         SET status = 'active',
             disabled_at = NULL,
             token_version = token_version + 1,
             updated_at = now()
         WHERE name = $1 AND status = 'disabled'
         RETURNING {SELECT_COLUMNS}"
    ))
    .bind(name.as_str())
    .fetch_optional(pool)
    .await
    .into_app()
}

pub async fn record_event(
    pool: &PgPool,
    service_name: &str,
    action: &str,
    actor: Option<&str>,
    detail: Option<&str>,
) -> AppResult<()> {
    let service_id: Option<Uuid> = sqlx::query_scalar("SELECT id FROM services WHERE name = $1")
        .bind(service_name)
        .fetch_optional(pool)
        .await
        .into_app()?;

    sqlx::query(
        "INSERT INTO service_events (service_id, service_name, action, actor, detail)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(service_id)
    .bind(service_name)
    .bind(action)
    .bind(actor)
    .bind(detail)
    .execute(pool)
    .await
    .into_app()?;

    Ok(())
}

pub async fn recent_events(pool: &PgPool, limit: i64) -> AppResult<Vec<ServiceEvent>> {
    sqlx::query_as::<_, ServiceEvent>(
        "SELECT id, service_name, action, actor, detail, created_at
         FROM service_events
         ORDER BY created_at DESC, id DESC
         LIMIT $1",
    )
    .bind(limit.clamp(1, 200))
    .fetch_all(pool)
    .await
    .into_app()
}

fn is_unique_violation(err: &sqlx::Error) -> bool {
    matches!(
        err,
        sqlx::Error::Database(db) if db.code().as_deref() == Some("23505")
    )
}
