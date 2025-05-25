use std::net::SocketAddr;

use axum::{middleware, routing::get, Router};
use axum_jwks::KeyManagerBuilder;
use std::env;
use tokio::net::TcpListener;

mod auth;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_target(true)
        .with_max_level(tracing::Level::DEBUG)
        .init();
    let key_manager = KeyManagerBuilder::new(
        // The Authorization Server that signs the JWTs you want to consume.
        env::var("AUTHSERVER")
            .expect("https://my-auth-server.example.com/.well-known/openid-configuration".into()),
        // The audience identifier for the application. This ensures that
        // JWTs are intended for this application.
        Some(env::var("AUDIENCE").expect("https://my-api-identifier.example.com/".into())),
    )
    .update_interval(std::time::Duration::from_secs(3))
    .build()
    .await;

    let state = auth::AppState { key_manager };
    let router = Router::new()
        .route("/", get(|| async { "ok" }))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth::validate_token,
        ))
        .with_state(state);

    let tcp = TcpListener::bind(SocketAddr::from(([0, 0, 0, 0], 3000)))
        .await
        .unwrap();
    axum::serve(tcp, router).await.unwrap();
}
