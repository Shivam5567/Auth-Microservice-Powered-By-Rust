pub mod admin;
pub mod dto;
pub mod extract;
pub mod handlers;
pub mod middleware;
pub mod routes;
pub mod static_assets;

pub use routes::{router, router_with_rate_limit};
