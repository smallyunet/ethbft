use crate::node::Node;
use alloy_primitives::B256;
use axum::{
    extract::{Path, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde_json::{json, Value};
use std::{str::FromStr, sync::Arc};
use tokio::{net::TcpListener, sync::Mutex};
use tracing::info;

type Shared = Arc<Mutex<Node>>;

pub async fn serve(node: Shared, listen_addr: String) -> anyhow::Result<()> {
    let app = Router::new()
        .route("/live", get(live))
        .route("/health", get(health))
        .route("/metrics", get(metrics))
        .route("/tx/{hash}", get(transaction))
        .with_state(node);
    let listener = TcpListener::bind(&listen_addr).await?;
    info!(address = %listen_addr, "health and metrics server listening");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn live() -> Json<Value> {
    Json(json!({"status": "ok", "version": crate::VERSION}))
}

async fn health(State(node): State<Shared>) -> Response {
    let (engine, comet_endpoint, bridge_height, max_lag, stall_timeout, stalled_for) = {
        let node = node.lock().await;
        (
            node.engine.clone(),
            node.config.cometbft.endpoint.clone(),
            node.state.abci_last_block_height as i64,
            node.config.bridge.max_bridge_lag,
            node.config.bridge.stall_timeout,
            node.last_progress_seconds(),
        )
    };
    let mut status = StatusCode::OK;
    let mut body = json!({"status": "ok", "bridge_height": bridge_height});
    match engine.block_number().await {
        Ok(height) => body["ethereum_height"] = json!(height),
        Err(error) => {
            status = StatusCode::SERVICE_UNAVAILABLE;
            body["status"] = json!("error");
            body["ethereum_error"] = json!(error.to_string());
        }
    }
    let url = format!("{}/status", comet_endpoint.trim_end_matches('/'));
    match reqwest::get(url).await.and_then(|r| r.error_for_status()) {
        Ok(response) => match response.json::<Value>().await {
            Ok(value) => {
                let comet_height = value
                    .pointer("/result/sync_info/latest_block_height")
                    .and_then(Value::as_str)
                    .and_then(|h| h.parse::<i64>().ok())
                    .unwrap_or_default();
                body["cometbft_height"] = json!(comet_height);
                if max_lag > 0 && comet_height - bridge_height > max_lag {
                    status = StatusCode::SERVICE_UNAVAILABLE;
                    body["status"] = json!("error");
                    body["bridge_error"] = json!(format!(
                        "bridge is {} blocks behind CometBFT",
                        comet_height - bridge_height
                    ));
                } else if comet_height > bridge_height
                    && stall_timeout > 0
                    && stalled_for > stall_timeout
                {
                    status = StatusCode::SERVICE_UNAVAILABLE;
                    body["status"] = json!("error");
                    body["bridge_error"] =
                        json!(format!("bridge has made no progress for {stalled_for}s"));
                }
            }
            Err(error) => {
                status = StatusCode::SERVICE_UNAVAILABLE;
                body["status"] = json!("error");
                body["cometbft_error"] = json!(error.to_string());
            }
        },
        Err(error) => {
            status = StatusCode::SERVICE_UNAVAILABLE;
            body["status"] = json!("error");
            body["cometbft_error"] = json!(error.to_string());
        }
    }
    (status, Json(body)).into_response()
}

async fn metrics(State(node): State<Shared>) -> Response {
    match node.lock().await.metrics() {
        Ok(body) => ([(header::CONTENT_TYPE, "text/plain; version=0.0.4")], body).into_response(),
        Err(error) => (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response(),
    }
}

async fn transaction(Path(hash): Path<String>, State(node): State<Shared>) -> Response {
    let hash = match B256::from_str(&hash) {
        Ok(hash) => hash,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "invalid transaction hash"})),
            )
                .into_response()
        }
    };
    match node.lock().await.delivery(hash).cloned() {
        Some(delivery) => (StatusCode::OK, Json(json!(delivery))).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "transaction not found"})),
        )
            .into_response(),
    }
}
