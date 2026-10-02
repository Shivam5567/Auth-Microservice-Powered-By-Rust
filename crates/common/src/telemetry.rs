use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

/// Installs the global tracing subscriber.
///
/// `RUST_LOG` controls filtering (e.g. `info,sqlx=debug`). Setting
/// `LOG_FORMAT=json` switches to machine-readable output for log shippers;
/// anything else produces human-readable output for local development.
pub fn init(service_name: &str) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(format!("{service_name}=info,tower_http=info,info")));

    let registry = tracing_subscriber::registry().with(filter);

    if std::env::var("LOG_FORMAT").as_deref() == Ok("json") {
        registry
            .with(
                fmt::layer()
                    .json()
                    .with_current_span(true)
                    .with_span_list(true)
                    .with_target(true),
            )
            .init();
    } else {
        registry
            .with(fmt::layer().with_target(true).with_level(true).pretty())
            .init();
    }
}
