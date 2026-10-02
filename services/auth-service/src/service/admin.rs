use serde::Serialize;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::db::service::{self as repo, ListFilter};
use crate::domain::service::{ServiceName, Status};
use crate::error::{AppError, AppResult};
use crate::state::AppState;

/// What the admin panel needs to know about a registered service.
///
/// `token_version` is surfaced rather than hidden because it is the mechanism
/// behind revocation: an operator asking "why did this token stop working"
/// needs to see that the version moved.
#[derive(Debug, Clone, Serialize)]
pub struct ServiceView {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub status: Status,
    pub scopes: Vec<String>,
    pub token_version: i32,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub disabled_at: Option<OffsetDateTime>,
}

impl From<repo::Service> for ServiceView {
    fn from(s: repo::Service) -> Self {
        // The column is constrained by a CHECK, so an unrecognised value can
        // only mean someone edited the row by hand.
        let status = match s.status.as_str() {
            "active" => Status::Active,
            _ => Status::Disabled,
        };
        Self {
            id: s.id,
            name: s.name,
            description: s.description,
            status,
            scopes: s.scopes,
            token_version: s.token_version,
            created_at: s.created_at,
            updated_at: s.updated_at,
            disabled_at: s.disabled_at,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ListView {
    pub services: Vec<ServiceView>,
    pub total: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct EventView {
    pub id: i64,
    pub service: String,
    pub action: String,
    pub actor: Option<String>,
    pub detail: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub at: OffsetDateTime,
}

impl From<repo::ServiceEvent> for EventView {
    fn from(e: repo::ServiceEvent) -> Self {
        Self {
            id: e.id,
            service: e.service_name,
            action: e.action,
            actor: e.actor,
            detail: e.detail,
            at: e.created_at,
        }
    }
}

pub struct NewService<'a> {
    pub name: &'a str,
    pub description: &'a str,
    pub scopes: &'a [String],
}

pub struct PatchService<'a> {
    pub description: Option<&'a str>,
    pub scopes: Option<&'a [String]>,
}

pub async fn list(state: &AppState, filter: &ListFilter) -> AppResult<ListView> {
    let services = repo::list(&state.pool, filter)
        .await?
        .into_iter()
        .map(ServiceView::from)
        .collect();
    let total = repo::count(&state.pool, filter).await?;

    Ok(ListView { services, total })
}

pub async fn get(state: &AppState, name: &str) -> AppResult<ServiceView> {
    let name = parse_name(name)?;
    repo::find_by_name(&state.pool, &name)
        .await?
        .map(ServiceView::from)
        .ok_or_else(|| AppError::not_found(format!("no service named '{name}'")))
}

pub async fn create(
    state: &AppState,
    new: NewService<'_>,
    actor: Option<&str>,
) -> AppResult<ServiceView> {
    let name = parse_name(new.name)?;
    let scopes = normalise_scopes(new.scopes)?;

    match repo::create(&state.pool, &name, new.description, &scopes).await? {
        repo::CreateOutcome::Created(row) => {
            repo::record_event(
                &state.pool,
                &row.name,
                "created",
                actor,
                Some(&row.description),
            )
            .await?;
            tracing::info!(service = %row.name, ?actor, "downstream service registered");
            Ok(ServiceView::from(row))
        }
        repo::CreateOutcome::NameTaken => Err(AppError::conflict(format!(
            "a service named '{name}' already exists"
        ))),
    }
}

pub async fn update(
    state: &AppState,
    name: &str,
    patch: PatchService<'_>,
    actor: Option<&str>,
) -> AppResult<ServiceView> {
    let name = parse_name(name)?;
    let scopes = patch.scopes.map(normalise_scopes).transpose()?;

    let row = repo::update(
        &state.pool,
        &name,
        &repo::Update {
            description: patch.description.map(str::to_owned),
            scopes,
        },
    )
    .await?
    .ok_or_else(|| AppError::not_found(format!("no service named '{name}'")))?;

    repo::record_event(&state.pool, &row.name, "updated", actor, None).await?;
    Ok(ServiceView::from(row))
}

/// Removes a service by disabling it and bumping its version, which
/// invalidates access tokens already issued for it.
///
/// Returns the service as it now stands, or a not-found if it does not exist.
/// Removing an already-removed service is not an error, so the panel's remove
/// button is safe to press twice.
pub async fn remove(state: &AppState, name: &str, actor: Option<&str>) -> AppResult<ServiceView> {
    let name = parse_name(name)?;

    if let Some(row) = repo::find_by_name(&state.pool, &name).await?
        && row.status == Status::Active.as_str()
    {
        let updated = repo::disable(&state.pool, &name)
            .await?
            .ok_or_else(|| AppError::internal("service vanished mid-update"))?;

        repo::record_event(
            &state.pool,
            &updated.name,
            "removed",
            actor,
            Some("access tokens revoked"),
        )
        .await?;
        tracing::warn!(
            service = %updated.name,
            ?actor,
            token_version = updated.token_version,
            "downstream service decommissioned"
        );
        return Ok(ServiceView::from(updated));
    }

    // Already removed: report its current state rather than failing.
    repo::find_by_name(&state.pool, &name)
        .await?
        .map(ServiceView::from)
        .ok_or_else(|| AppError::not_found(format!("no service named '{name}'")))
}

/// Re-enables a previously removed service.
pub async fn restore(state: &AppState, name: &str, actor: Option<&str>) -> AppResult<ServiceView> {
    let name = parse_name(name)?;

    if let Some(row) = repo::find_by_name(&state.pool, &name).await?
        && row.status == Status::Disabled.as_str()
    {
        let restored = repo::restore(&state.pool, &name)
            .await?
            .ok_or_else(|| AppError::internal("service vanished mid-update"))?;

        repo::record_event(
            &state.pool,
            &restored.name,
            "restored",
            actor,
            Some("token version bumped; old tokens stay invalid"),
        )
        .await?;
        tracing::info!(service = %restored.name, ?actor, "downstream service restored");
        return Ok(ServiceView::from(restored));
    }

    repo::find_by_name(&state.pool, &name)
        .await?
        .map(ServiceView::from)
        .ok_or_else(|| AppError::not_found(format!("no service named '{name}'")))
}

pub async fn events(state: &AppState, limit: i64) -> AppResult<Vec<EventView>> {
    Ok(repo::recent_events(&state.pool, limit)
        .await?
        .into_iter()
        .map(EventView::from)
        .collect())
}

/// A small summary for the panel header, so an operator can see the shape of
/// the estate at a glance without counting rows.
#[derive(Debug, Clone, Serialize)]
pub struct Summary {
    pub total: i64,
    pub active: i64,
    pub disabled: i64,
}

pub async fn summary(state: &AppState) -> AppResult<Summary> {
    let (total, active) = sqlx::query_as::<_, (i64, i64)>(
        "SELECT count(*), count(*) FILTER (WHERE status = 'active') FROM services",
    )
    .fetch_one(&state.pool)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "failed to summarise services");
        AppError::internal("database error")
    })?;

    Ok(Summary {
        total,
        active,
        disabled: total - active,
    })
}

fn parse_name(raw: &str) -> AppResult<ServiceName> {
    ServiceName::parse(raw).map_err(|e| AppError::validation(e.to_string()))
}

/// Trims, drops blanks, and de-duplicates scopes so the stored array is stable
/// regardless of how the client spelled them.
fn normalise_scopes(scopes: &[String]) -> AppResult<Vec<String>> {
    let mut cleaned: Vec<String> = scopes
        .iter()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .collect();
    cleaned.sort();
    cleaned.dedup();

    const MAX_SCOPES: usize = 32;
    const MAX_SCOPE_LEN: usize = 64;
    if cleaned.len() > MAX_SCOPES {
        return Err(AppError::validation(format!(
            "a service may declare at most {MAX_SCOPES} scopes"
        )));
    }
    if let Some(too_long) = cleaned.iter().find(|s| s.len() > MAX_SCOPE_LEN) {
        return Err(AppError::validation(format!(
            "scope '{too_long}' is longer than {MAX_SCOPE_LEN} characters"
        )));
    }
    Ok(cleaned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scopes_are_trimmed_sorted_and_deduplicated() {
        let scopes = vec![
            " write ".into(),
            "read".into(),
            "read".into(),
            "".into(),
            "admin".into(),
        ];
        assert_eq!(
            normalise_scopes(&scopes).unwrap(),
            ["admin", "read", "write"]
        );
    }

    #[test]
    fn no_scopes_is_legal() {
        assert!(normalise_scopes(&[]).unwrap().is_empty());
    }

    #[test]
    fn an_absurd_number_of_scopes_is_rejected() {
        let scopes: Vec<String> = (0..40).map(|i| format!("scope{i}")).collect();
        let err = normalise_scopes(&scopes).unwrap_err();
        assert_eq!(err.status_code(), 400);
    }

    #[test]
    fn an_overlong_scope_is_rejected() {
        let scopes = vec!["x".repeat(100)];
        assert!(normalise_scopes(&scopes).is_err());
    }

    #[test]
    fn an_invalid_name_is_a_validation_error() {
        let err = parse_name("a").unwrap_err();
        assert_eq!(err.status_code(), 400);
        assert!(err.envelope().error.message.contains("at least"));
    }

    #[test]
    fn a_name_is_normalised_before_use() {
        assert_eq!(parse_name("Billing API").unwrap().as_str(), "billing-api");
    }
}
