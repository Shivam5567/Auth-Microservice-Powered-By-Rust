use std::process::ExitCode;

use orders_service::config::Config;
use orders_service::{AppState, db, router, state};
use tokio::net::TcpListener;
use tokio::signal;

#[tokio::main]
async fn main() -> ExitCode {
    let _ = dotenvy::dotenv();

    if std::env::args().any(|arg| arg == "--healthcheck") {
        return healthcheck();
    }

    let config = match Config::from_env() {
        Ok(config) => config,
        Err(err) => {
            eprintln!("configuration error: {err}");
            return ExitCode::FAILURE;
        }
    };

    common::telemetry::init("orders-service");

    let addr = config.bind_addr;
    let token_check = config.token_check;
    let service_name = config.auth_base_url.clone();

    // Compose orders the dependencies, but a cold start can still lose the
    // race, so retry rather than crash-looping.
    let state = match warm_up(config).await {
        Ok(state) => state,
        Err(err) => {
            tracing::error!(error = %err, "could not reach a dependency");
            return ExitCode::FAILURE;
        }
    };

    let listener = match TcpListener::bind(addr).await {
        Ok(listener) => listener,
        Err(err) => {
            tracing::error!(error = %err, %addr, "could not bind");
            return ExitCode::FAILURE;
        }
    };

    tracing::info!(%addr, ?token_check, %service_name, "orders-service listening");

    let result = axum::serve(listener, router(state))
        .with_graceful_shutdown(shutdown_signal())
        .await;

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            tracing::error!(error = %err, "server error");
            ExitCode::FAILURE
        }
    }
}

/// Connects to the database, migrates, and warms the auth key cache.
async fn warm_up(config: Config) -> Result<AppState, String> {
    let mut last = String::new();

    for attempt in 1..=30u32 {
        match state::build(config.clone()).await {
            Ok(state) => {
                if let Err(err) = db::migrate(&state.pool).await {
                    last = format!("migrations failed: {err}");
                    tracing::warn!(attempt, error = %err, "retrying");
                } else if let Err(err) = state.auth.prefetch_key().await {
                    last = format!("could not fetch the auth public key: {err}");
                    tracing::warn!(attempt, error = %err, "retrying");
                } else {
                    return Ok(state);
                }
            }
            Err(err) => {
                last = format!("{err}");
                tracing::warn!(attempt, error = %err, "database not ready, retrying");
            }
        }

        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }

    Err(last)
}

fn healthcheck() -> ExitCode {
    use std::io::{Read, Write};
    use std::net::{TcpStream, ToSocketAddrs};
    use std::time::Duration;

    let address = std::env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8081".into());
    let target = address
        .replace("0.0.0.0", "127.0.0.1")
        .to_socket_addrs()
        .and_then(|mut addrs| addrs.next().ok_or(std::io::ErrorKind::NotFound.into()))
        .expect("BIND_ADDR must be a host:port pair");

    let Ok(mut stream) = TcpStream::connect_timeout(&target, Duration::from_secs(2)) else {
        eprintln!("healthcheck: cannot reach {address}");
        return ExitCode::FAILURE;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));

    if stream
        .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .is_err()
    {
        return ExitCode::FAILURE;
    }

    let mut response = String::new();
    if stream.read_to_string(&mut response).is_err() {
        return ExitCode::FAILURE;
    }

    if response.starts_with("HTTP/1.1 200") {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

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
