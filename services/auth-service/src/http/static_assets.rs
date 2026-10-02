//! The admin panel page, embedded in the binary so the service ships as a
//! single artefact with no separate static hosting.

use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};

use crate::state::AppState;

pub const PANEL: &str = include_str!("../../assets/admin.html");

/// `GET /admin` redirects to the panel so the trailing-slash form is not a 404.
pub async fn root() -> Redirect {
    Redirect::permanent("/admin/")
}

/// Serves the single-page panel.
pub async fn panel(State(_state): State<AppState>) -> Response {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            // The page is part of the binary, so it is safe to cache briefly
            // but must not be cached by a proxy across deploys.
            (header::CACHE_CONTROL, "no-cache"),
            // No external scripts or styles, so the policy can stay tight.
            (
                header::CONTENT_SECURITY_POLICY,
                "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; form-action 'none'; frame-ancestors 'none'",
            ),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        PANEL,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_panel_is_embedded_and_looks_like_a_page() {
        assert!(PANEL.contains("<!doctype html>"));
        assert!(PANEL.contains(r#"data-panel="admin-services""#));
    }

    /// The panel must not carry a hard-coded credential or a real token.
    #[test]
    fn the_panel_ships_without_secrets() {
        assert!(!PANEL.contains("BEGIN PRIVATE KEY"));
        assert!(!PANEL.contains("eyJhbGciOi"), "no embedded JWT");
    }

    /// The page is a single embedded file, so any external fetch would be a
    /// supply-chain problem.
    #[test]
    fn the_panel_loads_nothing_from_the_network() {
        for marker in ["http://", "https://", "//cdn", "src=\"http"] {
            assert!(
                !PANEL.contains(marker),
                "panel references an external resource: {marker}"
            );
        }
    }

    /// A ready-to-use link has to be possible, otherwise the panel can only be
    /// used by pasting a token by hand.
    #[test]
    fn the_panel_accepts_a_token_from_the_fragment() {
        assert!(PANEL.contains("tokenFromHash"));
        assert!(PANEL.contains("location.hash"));
    }

    /// The token must not survive in the address bar or in history.
    #[test]
    fn the_panel_scrubs_the_token_from_the_url() {
        assert!(PANEL.contains("replaceState"));
    }
}
