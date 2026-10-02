use sqlx::{PgPool, Postgres, Transaction};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::{AppError, AppResult, IntoAppResult as _, from_sqlx};

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub password_hash: String,
    pub is_active: bool,
    pub token_version: i32,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

/// What a caller is allowed to see about a user. Never includes the hash.
#[derive(Debug, Clone, serde::Serialize)]
pub struct UserProfile {
    pub id: Uuid,
    pub email: String,
    pub roles: Vec<String>,
    pub created_at: OffsetDateTime,
}

impl User {
    pub async fn find_by_email(pool: &PgPool, email: &str) -> AppResult<Option<Self>> {
        sqlx::query_as::<_, Self>(
            "SELECT id, email, password_hash, is_active, token_version, created_at, updated_at
             FROM users
             WHERE email = $1",
        )
        .bind(email)
        .fetch_optional(pool)
        .await
        .into_app()
    }

    pub async fn find_by_id(pool: &PgPool, id: Uuid) -> AppResult<Option<Self>> {
        sqlx::query_as::<_, Self>(
            "SELECT id, email, password_hash, is_active, token_version, created_at, updated_at
             FROM users
             WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(pool)
        .await
        .into_app()
    }

    pub async fn roles(pool: &PgPool, user_id: Uuid) -> AppResult<Vec<String>> {
        sqlx::query_scalar::<_, String>(
            "SELECT r.name
             FROM roles r
             JOIN user_roles ur ON ur.role_id = r.id
             WHERE ur.user_id = $1
             ORDER BY r.name",
        )
        .bind(user_id)
        .fetch_all(pool)
        .await
        .into_app()
    }

    pub async fn profile(pool: &PgPool, id: Uuid) -> AppResult<UserProfile> {
        let user = Self::find_by_id(pool, id)
            .await?
            .ok_or_else(|| AppError::not_found("user not found"))?;
        Ok(UserProfile {
            id: user.id,
            email: user.email,
            roles: Self::roles(pool, id).await?,
            created_at: user.created_at,
        })
    }

    /// Invalidates every outstanding access token for this user by bumping the
    /// version embedded in their claims.
    pub async fn bump_token_version(
        tx: &mut Transaction<'_, Postgres>,
        user_id: Uuid,
    ) -> AppResult<()> {
        sqlx::query("UPDATE users SET token_version = token_version + 1, updated_at = now() WHERE id = $1")
            .bind(user_id)
            .execute(&mut **tx)
            .await
            .into_app()?;
        Ok(())
    }
}

/// Result of attempting to insert a user, so the caller can tell a duplicate
/// email apart from any other constraint violation.
pub enum CreateUserOutcome {
    Created(Uuid),
    EmailTaken,
}

/// Creates a user and grants the default role, atomically.
///
/// Accepts an existing transaction so a caller can compose it with other
/// writes in the same unit of work.
pub async fn create_in(
    tx: &mut Transaction<'_, Postgres>,
    email: &str,
    password_hash: &str,
    default_role: &str,
) -> AppResult<CreateUserOutcome> {
    let inserted = sqlx::query_as::<_, (Uuid,)>(
        "INSERT INTO users (email, password_hash)
         VALUES ($1, $2)
         ON CONFLICT (email) DO NOTHING
         RETURNING id",
    )
    .bind(email)
    .bind(password_hash)
    .fetch_optional(&mut **tx)
    .await;

    let id = match inserted {
        Ok(Some((id,))) => id,
        // ON CONFLICT DO NOTHING returning no rows means the email is taken.
        Ok(None) => return Ok(CreateUserOutcome::EmailTaken),
        Err(err) if is_unique_violation(&err) => return Ok(CreateUserOutcome::EmailTaken),
        Err(err) => return Err(from_sqlx(err)),
    };

    sqlx::query(
        "INSERT INTO user_roles (user_id, role_id)
         SELECT $1, id FROM roles WHERE name = $2
         ON CONFLICT DO NOTHING",
    )
    .bind(id)
    .bind(default_role)
    .execute(&mut **tx)
    .await
    .into_app()?;

    Ok(CreateUserOutcome::Created(id))
}

fn is_unique_violation(err: &sqlx::Error) -> bool {
    matches!(
        err,
        sqlx::Error::Database(db) if db.code().as_deref() == Some("23505")
    )
}
