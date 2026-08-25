pub mod abci;
pub mod config;
pub mod engine;
pub mod health;
pub mod node;
pub mod protocol;
pub mod state;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
