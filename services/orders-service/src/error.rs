pub use common::{AppError, AppResult, ErrorEnvelope};

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("missing required environment variable {0}")]
    Missing(&'static str),
    #[error("environment variable {name} has invalid value: {reason}")]
    Invalid { name: &'static str, reason: String },
}

pub trait IntoAppResult<T> {
    fn into_app(self) -> AppResult<T>;
}

impl<T> IntoAppResult<T> for Result<T, sqlx::Error> {
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
