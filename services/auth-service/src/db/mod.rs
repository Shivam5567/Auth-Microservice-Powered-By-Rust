pub mod refresh_token;
pub mod user;

use sqlx::PgPool;
use sqlx::migrate::Migrator;
use time::OffsetDateTime;

use crate::error::{AppError, IntoAppResult as _};

/// Migrations are embedded in the binary so a container needs no extra files
/// to reach a consistent schema.
pub static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

/// Opens the connection pool and waits for the database to accept queries.
pub async fn connect(database_url: &str, max_connections: u32) -> Result<PgPool, AppError> {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(max_connections)
        .acquire_timeout(std::time::Duration::from_secs(10))
        .connect(database_url)
        .await
        .into_app()?;

    sqlx::query("SELECT 1").execute(&pool).await.into_app()?;
    Ok(pool)
}

pub async fn migrate(pool: &PgPool) -> Result<(), AppError> {
    MIGRATOR.run(pool).await.map_err(|e| {
        tracing::error!(error = %e, "migration failed");
        AppError::internal("database migration failed")
    })
}

/// A row that only carries timestamps, used to avoid re-reading a user
/// profile when all the caller needs is a liveness answer.
pub async fn ping(pool: &PgPool) -> Result<OffsetDateTime, sqlx::Error> {
    sqlx::query_scalar("SELECT now()")
        .fetch_one(pool)
        .await
}
