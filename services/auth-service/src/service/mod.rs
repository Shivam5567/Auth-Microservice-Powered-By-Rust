use std::net::IpAddr;

use serde::Serialize;
use uuid::Uuid;

use crate::db::refresh_token as refresh_repo;
use crate::db::user::{self, CreateUserOutcome, UserProfile};
use crate::domain::{access_token, password};
use crate::error::{AppError, AppResult};
use crate::state::AppState;

/// Role granted to every newly registered account.
const DEFAULT_ROLE: &str = "user";

/// A real Argon2id hash of a value nobody knows, used to spend the same CPU on
/// a failed login whether or not the account exists.
///
/// It has to be a genuine, parseable hash: given a malformed one the verifier
/// would bail out early and skip the expensive work, which is the opposite of
/// the point.
static TIMING_EQUALISER: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    password::hash_password("no account uses this password")
        .expect("hashing the timing equaliser cannot fail")
});

#[derive(Debug, Serialize)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: &'static str,
    pub expires_in: u64,
    pub user: UserProfile,
}

/// Where a session was started, recorded for audit purposes.
#[derive(Debug, Clone, Default)]
pub struct SessionContext {
    pub user_agent: Option<String>,
    pub ip_address: Option<IpAddr>,
}

impl SessionContext {
    pub fn new(user_agent: Option<String>, ip_address: Option<IpAddr>) -> Self {
        Self {
            user_agent,
            ip_address,
        }
    }

    fn user_agent(&self) -> Option<&str> {
        self.user_agent.as_deref()
    }

    fn ip_address(&self) -> Option<String> {
        self.ip_address.map(|ip| ip.to_string())
    }
}

pub async fn register(state: &AppState, email: &str, raw_password: &str) -> AppResult<UserProfile> {
    let email = crate::domain::normalize_email(email);
    let password_hash = password::hash_password(raw_password)?;

    let mut tx = state.pool.begin().await.map_err(|e| {
        tracing::error!(error = %e, "failed to begin registration transaction");
        AppError::internal("database error")
    })?;

    let id = match user::create_in(&mut tx, &email, &password_hash, DEFAULT_ROLE).await? {
        CreateUserOutcome::Created(id) => id,
        CreateUserOutcome::EmailTaken => {
            return Err(AppError::conflict(
                "an account with that email already exists",
            ));
        }
    };

    commit(tx, "registration").await?;

    user::User::profile(&state.pool, id).await
}

pub async fn login(
    state: &AppState,
    email: &str,
    raw_password: &str,
    ctx: SessionContext,
) -> AppResult<TokenPair> {
    let email = crate::domain::normalize_email(email);
    let found = user::User::find_by_email(&state.pool, &email).await?;

    let Some(found) = found else {
        // Spend the same CPU as a real verification so that response timing
        // does not reveal whether the address is registered.
        password::verify_password(raw_password, &TIMING_EQUALISER);
        return Err(AppError::unauthorized("invalid email or password"));
    };

    if !password::verify_password(raw_password, &found.password_hash) {
        return Err(AppError::unauthorized("invalid email or password"));
    }

    if !found.is_active {
        return Err(AppError::forbidden("this account is disabled"));
    }

    let (issued, _) = refresh_repo::start_family(
        &state.pool,
        found.id,
        ttl_secs(state),
        ctx.user_agent(),
        ctx.ip_address(),
    )
    .await?;

    build_pair(state, found.id, issued.token).await
}

/// Exchanges a refresh token for a new pair, rotating the old one.
///
/// Presenting a token that was already exchanged is treated as theft: the
/// entire token family is revoked, forcing a fresh login.
pub async fn refresh(
    state: &AppState,
    presented: &str,
    ctx: SessionContext,
) -> AppResult<TokenPair> {
    let reusable = match refresh_repo::classify(&state.pool, presented).await? {
        refresh_repo::Presented::Usable(row) => row,
        refresh_repo::Presented::Reused(row) => {
            burn_family(state, row.family_id).await?;
            return Err(replay_error());
        }
        refresh_repo::Presented::Dead => {
            return Err(AppError::unauthorized("refresh token has expired"));
        }
        refresh_repo::Presented::Unknown => {
            return Err(AppError::unauthorized("invalid refresh token"));
        }
    };

    let mut tx = state.pool.begin().await.map_err(|e| {
        tracing::error!(error = %e, "failed to begin refresh transaction");
        AppError::internal("database error")
    })?;

    // Claiming the token is what makes rotation atomic. If a concurrent
    // request already claimed it, this one loses the race and the family goes.
    if !refresh_repo::mark_used(&mut tx, reusable.id).await? {
        let revoked = refresh_repo::revoke_family(&mut tx, reusable.family_id).await?;
        commit(tx, "refresh race handling").await?;
        tracing::warn!(
            family_id = %reusable.family_id,
            revoked,
            "concurrent reuse of a refresh token detected; family revoked"
        );
        return Err(replay_error());
    }

    let successor = refresh_repo::rotate(
        &mut tx,
        reusable.user_id,
        reusable.family_id,
        reusable.id,
        ttl_secs(state),
    )
    .await?;

    // Carry the original session's fingerprint forward so a rotated token
    // still shows where the session started.
    if let Err(e) = sqlx::query(
        "UPDATE refresh_tokens SET user_agent = $2, ip_address = $3 WHERE token_hash = $1",
    )
    .bind(&successor.hash)
    .bind(ctx.user_agent())
    .bind(ctx.ip_address())
    .execute(&mut *tx)
    .await
    {
        // Not fatal: the session simply loses its recorded origin.
        tracing::warn!(error = %e, "could not record session origin on rotated token");
    }

    commit(tx, "refresh").await?;

    build_pair(state, reusable.user_id, successor.token).await
}

/// Revokes one session, or every session the user has when `all` is set.
///
/// Signing out is idempotent: an unknown or already-revoked token succeeds.
pub async fn logout(state: &AppState, presented: &str, all: bool) -> AppResult<()> {
    let Some(owner) = refresh_repo::find_owner(&state.pool, presented).await? else {
        return Ok(());
    };

    let mut tx = state.pool.begin().await.map_err(|e| {
        tracing::error!(error = %e, "failed to begin logout transaction");
        AppError::internal("database error")
    })?;

    let revoked = if all {
        let count = refresh_repo::revoke_all_for_user(&mut tx, owner.user_id).await?;
        // Bump the version as well, so access tokens already in flight die too.
        user::User::bump_token_version(&mut tx, owner.user_id).await?;
        count
    } else {
        refresh_repo::revoke_family(&mut tx, owner.family_id).await?
    };

    commit(tx, "logout").await?;

    tracing::info!(
        user_id = %owner.user_id,
        all,
        revoked,
        "session revoked"
    );
    Ok(())
}

/// Resolves the profile behind an already-verified access token.
pub async fn me(state: &AppState, user_id: Uuid) -> AppResult<UserProfile> {
    let profile = user::User::profile(&state.pool, user_id).await?;

    if !user::User::find_by_id(&state.pool, user_id)
        .await?
        .is_some_and(|u| u.is_active)
    {
        return Err(AppError::forbidden("this account is disabled"));
    }

    Ok(profile)
}

/// Removes refresh tokens that expired more than a week ago.
pub async fn purge_stale_tokens(state: &AppState) -> AppResult<u64> {
    refresh_repo::purge_expired(&state.pool, time::Duration::days(7)).await
}

async fn burn_family(state: &AppState, family_id: Uuid) -> AppResult<()> {
    let mut tx = state.pool.begin().await.map_err(|e| {
        tracing::error!(error = %e, "failed to begin reuse-handling transaction");
        AppError::internal("database error")
    })?;

    let revoked = refresh_repo::revoke_family(&mut tx, family_id).await?;
    commit(tx, "reuse handling").await?;

    tracing::warn!(
        family_id = %family_id,
        revoked,
        "refresh token replay detected; whole family revoked"
    );
    Ok(())
}

fn replay_error() -> AppError {
    AppError::unauthorized("refresh token has already been used; please sign in again")
}

async fn build_pair(
    state: &AppState,
    user_id: Uuid,
    refresh_token: String,
) -> AppResult<TokenPair> {
    let profile = user::User::profile(&state.pool, user_id).await?;
    let user = user::User::find_by_id(&state.pool, user_id)
        .await?
        .ok_or_else(|| AppError::unauthorized("account no longer exists"))?;

    let access = access_token::issue(
        &state.keys,
        state.tokens.metadata(),
        user_id,
        profile.roles.clone(),
        user.token_version,
    )?;

    Ok(TokenPair {
        access_token: access.token,
        refresh_token,
        token_type: "Bearer",
        expires_in: access.expires_in,
        user: profile,
    })
}

fn ttl_secs(state: &AppState) -> u64 {
    state.config.refresh_token_ttl.as_secs()
}

async fn commit(
    tx: sqlx::Transaction<'_, sqlx::Postgres>,
    what: &'static str,
) -> AppResult<()> {
    tx.commit().await.map_err(|e| {
        tracing::error!(error = %e, operation = what, "transaction commit failed");
        AppError::internal("database error")
    })
}
