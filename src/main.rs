use anyhow::Context;
use ethbft::{abci, config::Config, health, node::Node};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = Config::load().context("load configuration")?;
    tracing_subscriber::fmt()
        .with_env_filter(config.node.log_level.clone())
        .json()
        .init();

    info!(version = ethbft::VERSION, "starting EthBFT Rust node");
    let node = Arc::new(Mutex::new(Node::connect(config.clone()).await?));

    let abci_node = node.clone();
    let abci_addr = config.node.listen_addr.clone();
    let abci_task = tokio::spawn(async move { abci::serve(abci_node, abci_addr).await });

    let health_node = node.clone();
    let health_addr = config.node.health_addr.clone();
    let health_task = tokio::spawn(async move { health::serve(health_node, health_addr).await });

    tokio::select! {
        result = abci_task => result.context("ABCI task join")??,
        result = health_task => result.context("health task join")??,
        _ = tokio::signal::ctrl_c() => info!("shutdown signal received"),
    }
    Ok(())
}
