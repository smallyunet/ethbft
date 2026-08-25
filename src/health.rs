use crate::node::Node;
use axum::{
    extract::State,
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::{net::TcpListener, sync::Mutex};
use tracing::info;

type Shared = Arc<Mutex<Node>>;

pub async fn serve(node: Shared, listen_addr: String) -> anyhow::Result<()> {
    let app = Router::new()
        .route("/live", get(live))
        .route("/ready", get(ready))
        .route("/health", get(ready))
        .route("/status", get(status))
        .route("/metrics", get(metrics))
        .with_state(node);
    let listener = TcpListener::bind(&listen_addr).await?;
    info!(address = %listen_addr, "health and metrics server listening");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn live() -> Json<Value> {
    Json(json!({"status":"ok", "version":crate::VERSION, "protocol":2}))
}

async fn status(State(node): State<Shared>) -> Json<Value> {
    let node = node.lock().await;
    Json(
        json!({"version":crate::VERSION, "protocol":2, "chainId":node.chain_id, "executionGenesis":node.el_genesis,
        "protocolFingerprint":node.protocol_fingerprint, "consensusHeight":node.state.last_committed_height,
        "executionBlockHash":node.state.last_execution_hash}),
    )
}

async fn ready(State(node): State<Shared>) -> Response {
    let (engine, comet_endpoint, consensus_height, max_lag, stall_timeout, stalled_for) = {
        let node = node.lock().await;
        (
            node.engine.clone(),
            node.config.cometbft.endpoint.clone(),
            node.state.last_committed_height as i64,
            node.config.node.max_consensus_lag,
            node.config.node.stall_timeout,
            node.last_progress_seconds(),
        )
    };
    let mut http_status = StatusCode::OK;
    let mut body = json!({"status":"ready", "consensusHeight":consensus_height});
    match engine.syncing().await {
        Ok(Value::Bool(false)) => body["executionSyncing"] = json!(false),
        Ok(value) => {
            http_status = StatusCode::SERVICE_UNAVAILABLE;
            body["status"] = json!("not_ready");
            body["executionSyncing"] = value;
        }
        Err(error) => {
            http_status = StatusCode::SERVICE_UNAVAILABLE;
            body["status"] = json!("not_ready");
            body["executionError"] = json!(error.to_string());
        }
    }
    match engine.block_number().await {
        Ok(height) => body["executionHeight"] = json!(height),
        Err(error) => {
            http_status = StatusCode::SERVICE_UNAVAILABLE;
            body["status"] = json!("not_ready");
            body["executionError"] = json!(error.to_string());
        }
    }
    let url = format!("{}/status", comet_endpoint.trim_end_matches('/'));
    match reqwest::get(url)
        .await
        .and_then(|response| response.error_for_status())
    {
        Ok(response) => match response.json::<Value>().await {
            Ok(value) => {
                let comet_height = value
                    .pointer("/result/sync_info/latest_block_height")
                    .and_then(Value::as_str)
                    .and_then(|height| height.parse::<i64>().ok())
                    .unwrap_or_default();
                let catching_up = value
                    .pointer("/result/sync_info/catching_up")
                    .and_then(Value::as_bool)
                    .unwrap_or(true);
                body["cometBftHeight"] = json!(comet_height);
                body["cometBftCatchingUp"] = json!(catching_up);
                let lag = comet_height - consensus_height;
                if catching_up
                    || (max_lag > 0 && lag > max_lag)
                    || (lag > 0 && stall_timeout > 0 && stalled_for > stall_timeout)
                {
                    http_status = StatusCode::SERVICE_UNAVAILABLE;
                    body["status"] = json!("not_ready");
                    body["consensusError"] = json!(if catching_up {
                        "CometBFT is catching up".into()
                    } else if max_lag > 0 && lag > max_lag {
                        format!("application is {lag} blocks behind CometBFT")
                    } else {
                        format!("application has made no progress for {stalled_for}s")
                    });
                }
            }
            Err(error) => {
                http_status = StatusCode::SERVICE_UNAVAILABLE;
                body["status"] = json!("not_ready");
                body["cometBftError"] = json!(error.to_string());
            }
        },
        Err(error) => {
            http_status = StatusCode::SERVICE_UNAVAILABLE;
            body["status"] = json!("not_ready");
            body["cometBftError"] = json!(error.to_string());
        }
    }
    (http_status, Json(body)).into_response()
}

async fn metrics(State(node): State<Shared>) -> Response {
    match node.lock().await.metrics() {
        Ok(body) => ([(header::CONTENT_TYPE, "text/plain; version=0.0.4")], body).into_response(),
        Err(error) => (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response(),
    }
}
