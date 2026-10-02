use std::net::SocketAddr;
use std::process::ExitCode;

use auth_service::config::Config;
use auth_service::{build_state, http, spawn_purge_task};
use tokio::net::TcpListener;
use tokio::signal;

#[tokio::main]
async fn main() -> ExitCode {
    // A missing .env is normal in production, where the values come from the
    // environment, so a failure here is not fatal.
    let _ = dotenvy::dotenv();

    let config = match Config::from_env() {
        Ok(config) => config,
        Err(err) => {
            eprintln!("configuration error: {err}");
            return ExitCode::FAILURE;
        }
    };

    common::telemetry::init(config.service_name);

    let state = match build_state(config).await {
        Ok(state) => state,
        Err(err) => {
            // `err` may wrap a connection string, so log the rendered message
            // rather than the struct.
            tracing::error!(error = %err, "failed to start");
            return ExitCode::FAILURE;
        }
    };

    let addr = state.config.bind_addr;
    let listener = match TcpListener::bind(addr).await {
        Ok(listener) => listener,
        Err(err) => {
            tracing::error!(error = %err, %addr, "could not bind");
            return ExitCode::FAILURE;
        }
    };

    let kid = state.keys.kid().to_owned();
    let app = http::router(state.clone()).into_make_service_with_connect_info::<SocketAddr>();
    let purge = spawn_purge_task(state);

    tracing::info!(%addr, %kid, "auth-service listening");

    let result = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await;

    purge.abort();

    match result {
        Ok(()) => {
            tracing::info!("auth-service stopped cleanly");
            ExitCode::SUCCESS
        }
        Err(err) => {
            tracing::error!(error = %err, "server error");
            ExitCode::FAILURE
        }
    }
}

/// Resolves on Ctrl+C or a container stop signal, so in-flight requests get to
/// finish instead of the process being cut off mid-response.
async fn shutdown_signal() {
    let interrupt = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = interrupt => tracing::info!("received shutdown signal"),
        _ = terminate => tracing::info!("received terminate signal"),
    }
}
