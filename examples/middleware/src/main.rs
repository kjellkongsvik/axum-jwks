use std::net::SocketAddr;

use axum::{middleware, routing::get, Router};
use axum_jwks::KeyManager;

mod auth;

#[tokio::main]
async fn main() {
    let key_manager = KeyManager::new(
        // The Authorization Server that signs the JWTs you want to consume.
        "https://my-auth-server.example.com/.well-known/openid-configuration".to_string(),
        // The audience identifier for the application. This ensures that
        // JWTs are intended for this application.
        "https://my-api-identifier.example.com/".to_string(),
    )
    .await
    .expect("Valid configuration")
    .with_periodical_update(36000)
    .with_minimal_update_interval(600);

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
