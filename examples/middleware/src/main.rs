use axum::{middleware, routing::get, Router};
use axum_jwks::KeyManagerBuilder;
use reqwest::Client;
use std::env;
use std::net::SocketAddr;
use tracing::Level;

mod auth;

#[tokio::main]
async fn main() {
    let subscriber = tracing_subscriber::FmtSubscriber::builder()
        .with_max_level(Level::DEBUG)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");
    let key_manager = KeyManagerBuilder::new(
        // The Authorization Server that signs the JWTs you want to consume.
        env::var("AUTHSERVER").unwrap(),
        // The audience identifier for the application. This ensures that
        // JWTs are intended for this application.
        env::var("AUDIENCE").unwrap(),
    )
    .periodical_update(36000)
    .minimal_update_interval(600)
    .client(Client::default())
    .build()
    .await
    .unwrap();

    let state = auth::AppState { key_manager };
    let router = Router::new()
        .route("/", get(|| async { "ok" }))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth::validate_token,
        ))
        .with_state(state);

    axum::Server::bind(&SocketAddr::from(([0, 0, 0, 0], 3000)))
        .serve(router.into_make_service())
        .await
        .unwrap();
}
