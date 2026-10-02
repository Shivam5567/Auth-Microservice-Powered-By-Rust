//! A small e-commerce service that shows how to consume `auth-service`.
//!
//! Nothing here is about commerce. The interesting part is `auth.rs` and
//! `cookie.rs`: how a service establishes who is calling, where the refresh
//! token lives, and why the browser must not fire two refreshes at once.

pub mod api;
pub mod auth;
pub mod caller;
pub mod config;
pub mod cookie;
pub mod db;
pub mod error;
pub mod routes;
pub mod state;

pub use routes::router;
pub use state::AppState;
