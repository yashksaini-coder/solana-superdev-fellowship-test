use axum::{
    response::Json as ResponseJson,
    routing::{get, post},
    Router,
};
use std::net::SocketAddr;
use tower_http::cors::CorsLayer;
use tracing::info;

mod handlers;
mod models;
mod solana;
mod errors;

use handlers::*;
use models::*;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    // Setting our application with routes
    let app = Router::new()
        .route("/", get(health_check))
        .route("/health", get(health_check))
        .route("/keypair", post(generate_keypair))
        .route("/token/create", post(create_token))
        .route("/token/mint", post(mint_token))
        .route("/message/sign", post(sign_message))
        .route("/message/verify", post(verify_message))
        .route("/send/sol", post(send_sol))
        .route("/send/token", post(send_token))
        .layer(CorsLayer::permissive());

    // Determine port from environment variable or default to 3000
    let port = std::env::var("PORT")
        .unwrap_or_else(|_| "3000".to_string())
        .parse::<u16>()
        .unwrap_or(3000);
    
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    
    info!("Starting Solana API server on {}", addr);
    
    // Run the server
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn health_check() -> ResponseJson<ApiResponse<serde_json::Value>> {
    ResponseJson(ApiResponse {
        success: true,
        data: Some(serde_json::json!({
            "status": "healthy",
            "service": "solana-api-server",
            "version": "0.1.0"
        })),
        error: None,
    })
}