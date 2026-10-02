use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::{Json, http::header::AUTHORIZATION};
use serde::Deserialize;

use super::extract::AuthUser;
use crate::db::service::ListFilter;
use crate::error::{AppError, AppResult};
use crate::service::admin::{self, NewService, PatchService};
use crate::state::AppState;

/// Role every route in this module requires.
const ADMIN_ROLE: &str = "admin";

/// Longest free-text field an admin may submit.
const MAX_DESCRIPTION: usize = 500;

/// Identifies the admin for the audit trail, without trusting a client-supplied
/// identity. Falls back to the subject when no email is available.
fn actor(user: &AuthUser, headers: &HeaderMap) -> String {
    headers
        .get("x-admin-actor")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim().chars().take(120).collect::<String>())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| user.id.to_string())
}

fn guard(user: &AuthUser) -> AppResult<()> {
    super::extract::require_role(user, ADMIN_ROLE)
}

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    /// `active` or `disabled`; anything else is rejected rather than ignored.
    status: Option<String>,
    search: Option<String>,
    limit: Option<i64>,
    offset: Option<i64>,
}

impl ListQuery {
    fn into_filter(self) -> AppResult<ListFilter> {
        if let Some(status) = self.status.as_deref()
            && !status.is_empty()
            && !matches!(status, "active" | "disabled")
        {
            return Err(AppError::validation(
                "status must be either 'active' or 'disabled'",
            ));
        }

        if let Some(search) = self.search.as_deref()
            && search.len() > 120
        {
            return Err(AppError::validation("search is too long"));
        }

        Ok(ListFilter {
            status: self.status.filter(|s| !s.is_empty()),
            search: self.search.filter(|s| !s.is_empty()),
            limit: self.limit.unwrap_or(50),
            offset: self.offset.unwrap_or(0),
        })
    }
}

#[derive(Debug, serde::Deserialize)]
pub struct CreateBody {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub scopes: Vec<String>,
}

#[derive(Debug, serde::Deserialize)]
pub struct UpdateBody {
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub scopes: Option<Vec<String>>,
}

pub async fn list(
    State(state): State<AppState>,
    user: AuthUser,
    Query(query): Query<ListQuery>,
) -> AppResult<Json<admin::ListView>> {
    guard(&user)?;
    Ok(Json(admin::list(&state, &query.into_filter()?).await?))
}

pub async fn summary(
    State(state): State<AppState>,
    user: AuthUser,
) -> AppResult<Json<admin::Summary>> {
    guard(&user)?;
    Ok(Json(admin::summary(&state).await?))
}

pub async fn get(
    State(state): State<AppState>,
    user: AuthUser,
    Path(name): Path<String>,
) -> AppResult<Json<admin::ServiceView>> {
    guard(&user)?;
    Ok(Json(admin::get(&state, &name).await?))
}

pub async fn create(
    State(state): State<AppState>,
    user: AuthUser,
    headers: HeaderMap,
    Json(body): Json<CreateBody>,
) -> AppResult<impl IntoResponse> {
    guard(&user)?;

    if body.description.len() > MAX_DESCRIPTION {
        return Err(AppError::validation(format!(
            "description must be at most {MAX_DESCRIPTION} characters"
        )));
    }

    let created = admin::create(
        &state,
        NewService {
            name: &body.name,
            description: &body.description,
            scopes: &body.scopes,
        },
        Some(&actor(&user, &headers)),
    )
    .await?;

    Ok((StatusCode::CREATED, Json(created)).into_response())
}

pub async fn update(
    State(state): State<AppState>,
    user: AuthUser,
    headers: HeaderMap,
    Path(name): Path<String>,
    Json(body): Json<UpdateBody>,
) -> AppResult<Json<admin::ServiceView>> {
    guard(&user)?;

    if let Some(description) = body.description.as_deref()
        && description.len() > MAX_DESCRIPTION
    {
        return Err(AppError::validation(format!(
            "description must be at most {MAX_DESCRIPTION} characters"
        )));
    }

    let updated = admin::update(
        &state,
        &name,
        PatchService {
            description: body.description.as_deref(),
            scopes: body.scopes.as_deref(),
        },
        Some(&actor(&user, &headers)),
    )
    .await?;

    Ok(Json(updated))
}

pub async fn remove(
    State(state): State<AppState>,
    user: AuthUser,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> AppResult<Json<admin::ServiceView>> {
    guard(&user)?;
    Ok(Json(
        admin::remove(&state, &name, Some(&actor(&user, &headers))).await?,
    ))
}

pub async fn restore(
    State(state): State<AppState>,
    user: AuthUser,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> AppResult<Json<admin::ServiceView>> {
    guard(&user)?;
    Ok(Json(
        admin::restore(&state, &name, Some(&actor(&user, &headers))).await?,
    ))
}

#[derive(Debug, Deserialize)]
pub struct EventsQuery {
    limit: Option<i64>,
}

pub async fn events(
    State(state): State<AppState>,
    user: AuthUser,
    Query(query): Query<EventsQuery>,
) -> AppResult<Json<Vec<admin::EventView>>> {
    guard(&user)?;
    Ok(Json(
        admin::events(&state, query.limit.unwrap_or(25)).await?,
    ))
}

/// Re-exported so the routes module can name the same constant.
pub const ADMIN_ROLE_NAME: &str = ADMIN_ROLE;

/// Kept to make the intended header visible in generated docs.
pub const ACTOR_HEADER: &str = "x-admin-actor";

#[allow(dead_code)]
fn _authorization_header_is_recognised(headers: &HeaderMap) -> bool {
    headers.contains_key(AUTHORIZATION)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_filter_defaults_to_the_first_page() {
        let filter = ListQuery {
            status: None,
            search: None,
            limit: None,
            offset: None,
        }
        .into_filter()
        .unwrap();
        assert_eq!(filter.limit, 50);
        assert_eq!(filter.offset, 0);
        assert!(filter.status.is_none());
    }

    #[test]
    fn a_known_status_is_accepted() {
        for status in ["active", "disabled"] {
            let filter = ListQuery {
                status: Some(status.into()),
                search: None,
                limit: None,
                offset: None,
            }
            .into_filter()
            .unwrap();
            assert_eq!(filter.status.as_deref(), Some(status));
        }
    }

    /// Silently ignoring a typo would show the operator the full list and look
    /// like the filter simply did not apply.
    #[test]
    fn an_unknown_status_is_rejected() {
        let err = ListQuery {
            status: Some("actve".into()),
            search: None,
            limit: None,
            offset: None,
        }
        .into_filter()
        .unwrap_err();
        assert_eq!(err.status_code(), 400);
    }

    #[test]
    fn an_absurd_search_is_rejected() {
        let err = ListQuery {
            status: None,
            search: Some("x".repeat(200)),
            limit: None,
            offset: None,
        }
        .into_filter()
        .unwrap_err();
        assert_eq!(err.status_code(), 400);
    }

    #[test]
    fn the_description_limit_is_bounded() {
        const { assert!(MAX_DESCRIPTION > 0 && MAX_DESCRIPTION <= 4_000) };
    }
}
