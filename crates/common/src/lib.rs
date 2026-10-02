//! Shared building blocks for every service in the workspace.

pub mod error;
pub mod telemetry;

pub use error::{AppError, AppResult, ErrorBody, ErrorEnvelope};
