pub use common::{AppError, AppResult, ErrorEnvelope};

/// Bridges driver errors into [`AppError`].
///
/// `AppError` lives in the shared `common` crate, so the orphan rule rules out
/// a `From<sqlx::Error>` impl here; an extension trait is the idiomatic
/// equivalent.
pub trait IntoAppResult<T> {
    fn into_app(self) -> AppResult<T>;
}

impl<T> IntoAppResult<T> for Result<T, sqlx::Error> {
    /// Driver failures are logged in full and reported to the caller as a
    /// generic 500, so messages such as constraint names or host addresses
    /// never reach an untrusted caller.
    fn into_app(self) -> AppResult<T> {
        self.map_err(|err| match err {
            sqlx::Error::RowNotFound => AppError::not_found("resource not found"),
            other => {
                tracing::error!(error = %other, "database error");
                AppError::internal("database error")
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_row_becomes_a_404() {
        let err = Err::<(), _>(sqlx::Error::RowNotFound).into_app().unwrap_err();
        assert_eq!(err.status_code(), 404);
    }

    #[test]
    fn other_driver_errors_are_not_leaked_to_clients() {
        let err = Err::<(), _>(sqlx::Error::Protocol("server said no".into()))
            .into_app()
            .unwrap_err();
        assert_eq!(err.status_code(), 500);
        assert_eq!(err.envelope().error.message, "an internal error occurred");
    }

    #[test]
    fn a_successful_query_passes_its_value_through() {
        let value = Ok::<_, sqlx::Error>(7usize).into_app().unwrap();
        assert_eq!(value, 7);
    }
}
