use sqlx::{PgPool, Postgres, Transaction};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::domain::refresh_token as domain;
use crate::error::{AppResult, IntoAppResult as _};

/// A stored refresh token, as read back from the database.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct RefreshToken {
    pub id: Uuid,
    pub user_id: Uuid,
    pub family_id: Uuid,
    pub expires_at: OffsetDateTime,
    pub used_at: Option<OffsetDateTime>,
    pub revoked_at: Option<OffsetDateTime>,
}

/// The lifecycle state of a presented refresh token, and what the caller must
/// do about it.
#[derive(Debug, Clone)]
pub enum Presented {
    /// Live and unused: exchange it for a new pair.
    Usable(RefreshToken),
    /// Already exchanged. Either the client replayed a stale token or someone
    /// stole it, so the whole family is treated as compromised.
    Reused(RefreshToken),
    /// Withdrawn by logout, or expired.
    Dead,
    /// No such token.
    Unknown,
}

const SELECT_COLUMNS: &str = "id, user_id, family_id, expires_at, used_at, revoked_at";

/// Looks a presented token up and classifies its state.
pub async fn classify(pool: &PgPool, token: &str) -> AppResult<Presented> {
    let row = sqlx::query_as::<_, RefreshToken>(&format!(
        "SELECT {SELECT_COLUMNS} FROM refresh_tokens WHERE token_hash = $1"
    ))
    .bind(domain::digest(token))
    .fetch_optional(pool)
    .await
    .into_app()?;

    let Some(row) = row else {
        return Ok(Presented::Unknown);
    };

    let now = OffsetDateTime::now_utc();
    if row.revoked_at.is_some() || row.expires_at <= now {
        return Ok(Presented::Dead);
    }
    if row.used_at.is_some() {
        return Ok(Presented::Reused(row));
    }
    Ok(Presented::Usable(row))
}

/// Marks a token as exchanged. Returns false if another request got there
/// first, which is the race that reuse detection depends on.
pub async fn mark_used(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
) -> AppResult<bool> {
    let result = sqlx::query(
        "UPDATE refresh_tokens SET used_at = now() WHERE id = $1 AND used_at IS NULL",
    )
    .bind(id)
    .execute(&mut **tx)
    .await
    .into_app()?;

    Ok(result.rows_affected() == 1)
}

/// Revokes every token descended from one login.
pub async fn revoke_family(
    tx: &mut Transaction<'_, Postgres>,
    family_id: Uuid,
) -> AppResult<u64> {
    let result = sqlx::query(
        "UPDATE refresh_tokens
         SET revoked_at = now()
         WHERE family_id = $1 AND revoked_at IS NULL",
    )
    .bind(family_id)
    .execute(&mut **tx)
    .await
    .into_app()?;

    Ok(result.rows_affected())
}

/// Revokes every live token belonging to a user, across all families.
pub async fn revoke_all_for_user(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
) -> AppResult<u64> {
    let result = sqlx::query(
        "UPDATE refresh_tokens
         SET revoked_at = now()
         WHERE user_id = $1 AND revoked_at IS NULL",
    )
    .bind(user_id)
    .execute(&mut **tx)
    .await
    .into_app()?;

    Ok(result.rows_affected())
}

/// Starts a new token family, which is what a successful login creates.
///
/// `ip_address` arrives pre-rendered because sqlx has no codec for `IpAddr`;
/// Postgres accepts the textual form for its `inet` column.
pub async fn start_family(
    pool: &PgPool,
    user_id: Uuid,
    ttl_secs: u64,
    user_agent: Option<&str>,
    ip_address: Option<String>,
) -> AppResult<(domain::IssuedRefreshToken, Uuid)> {
    let issued = domain::generate();
    let family_id = Uuid::new_v4();
    let expires_at = OffsetDateTime::now_utc() + time::Duration::seconds(ttl_secs as i64);

    sqlx::query(
        "INSERT INTO refresh_tokens
             (user_id, token_hash, family_id, expires_at, user_agent, ip_address)
         VALUES ($1, $2, $3, $4, $5, $6::inet)",
    )
    .bind(user_id)
    .bind(&issued.hash)
    .bind(family_id)
    .bind(expires_at)
    .bind(user_agent)
    .bind(ip_address)
    .execute(pool)
    .await
    .into_app()?;

    Ok((issued, family_id))
}

/// Issues the successor to an already-exchanged token, keeping the same family
/// so reuse detection still covers the whole chain.
pub async fn rotate(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    family_id: Uuid,
    parent_id: Uuid,
    ttl_secs: u64,
) -> AppResult<domain::IssuedRefreshToken> {
    let issued = domain::generate();
    let expires_at = OffsetDateTime::now_utc() + time::Duration::seconds(ttl_secs as i64);

    sqlx::query(
        "INSERT INTO refresh_tokens
             (user_id, token_hash, family_id, parent_id, expires_at)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(user_id)
    .bind(&issued.hash)
    .bind(family_id)
    .bind(parent_id)
    .bind(expires_at)
    .execute(&mut **tx)
    .await
    .into_app()?;

    Ok(issued)
}

/// Who a presented token belongs to, so logout can act without the caller
/// having to supply a user id.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct TokenOwner {
    pub user_id: Uuid,
    pub family_id: Uuid,
}

pub async fn find_owner(pool: &PgPool, token: &str) -> AppResult<Option<TokenOwner>> {
    sqlx::query_as::<_, TokenOwner>(
        "SELECT user_id, family_id FROM refresh_tokens WHERE token_hash = $1",
    )
    .bind(domain::digest(token))
    .fetch_optional(pool)
    .await
    .into_app()
}

/// Deletes tokens that expired long enough ago to be of no use to anyone.
pub async fn purge_expired(pool: &PgPool, older_than: time::Duration) -> AppResult<u64> {
    let result = sqlx::query("DELETE FROM refresh_tokens WHERE expires_at < now() - $1")
        .bind(older_than)
        .execute(pool)
        .await
        .into_app()?;

    Ok(result.rows_affected())
}
