use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::{json, Value};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant},
};

const RAW_TX: &str = "f86d80843b9aca008252089499999999999999999999999999999999999999998806f05b59d3b2000080820a96a0995bbba829e895250d69146aee4e822b5c5abfbd050a22886f94eaa6c9f1e54aa00fc5039b077a9e2c0fa9d8f1422e012f4c05ce48c30143cbaad9546802449a52";
const TX_HASH: &str = "0xa453138fb4827254d32753d01c357fd4ad1d403c2aba559b53685ec7713faee5";
const TEST_ADDRESS: &str = "f39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

#[tokio::test]
async fn docker_execution_path() {
    if std::env::var("ETHBFT_E2E").as_deref() != Ok("1") {
        return;
    }
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    compose(&root, &["down", "-v", "--remove-orphans"], false);
    prepare(&root);
    let _guard = Cleanup(root.clone());

    let mut args = vec!["up", "-d"];
    if std::env::var("ETHBFT_E2E_NO_BUILD").as_deref() != Ok("1") {
        args.push("--build");
    }
    compose(&root, &args, true);
    wait_http("http://localhost:26657/status", Duration::from_secs(120)).await;
    wait_http("http://localhost:8081/live", Duration::from_secs(120)).await;

    let balance = rpc(
        "http://localhost:8545",
        "eth_getBalance",
        json!([format!("0x{TEST_ADDRESS}"), "latest"]),
    )
    .await;
    assert_eq!(balance.as_str(), Some("0x3635c9adc5dea00000"));

    let raw = hex::decode(RAW_TX).unwrap();
    let broadcast = rpc(
        "http://localhost:26657",
        "broadcast_tx_sync",
        json!([STANDARD.encode(raw)]),
    )
    .await;
    assert_eq!(
        broadcast.get("code").and_then(Value::as_u64),
        Some(0),
        "{broadcast}"
    );

    wait_until(Duration::from_secs(120), || async {
        rpc_optional(
            "http://localhost:8545",
            "eth_getTransactionReceipt",
            json!([TX_HASH]),
        )
        .await
        .and_then(|receipt| receipt.get("status").cloned())
            == Some(json!("0x1"))
    })
    .await;
    wait_until(Duration::from_secs(30), || async {
        reqwest::get(format!("http://localhost:8081/tx/{TX_HASH}"))
            .await
            .ok()
            .filter(|r| r.status().is_success())
            .is_some()
    })
    .await;

    let before = hex_quantity(&rpc("http://localhost:8545", "eth_blockNumber", json!([])).await);
    compose(
        &root,
        &["up", "-d", "--force-recreate", "--no-deps", "ethbft"],
        true,
    );
    wait_http("http://localhost:8081/health", Duration::from_secs(90)).await;
    wait_until(Duration::from_secs(60), || async {
        hex_quantity(&rpc("http://localhost:8545", "eth_blockNumber", json!([])).await) > before
    })
    .await;
}

fn prepare(root: &Path) {
    let data = root.join("e2e/data");
    fs::create_dir_all(&data).unwrap();
    for name in ["geth", "cometbft", "ethbft"] {
        let path = data.join(name);
        fs::create_dir_all(&path).unwrap();
        for entry in fs::read_dir(&path).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                fs::remove_dir_all(entry.path()).unwrap();
            } else {
                fs::remove_file(entry.path()).unwrap();
            }
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o777)).unwrap();
        }
    }
    fs::write(data.join("jwt.hex"), "00".repeat(32)).unwrap();
    fs::write(data.join("geth/genesis.json"), format!(r#"{{
      "config": {{"chainId":1337,"homesteadBlock":0,"eip150Block":0,"eip155Block":0,"eip158Block":0,"byzantiumBlock":0,"constantinopleBlock":0,"petersburgBlock":0,"istanbulBlock":0,"berlinBlock":0,"londonBlock":0,"terminalTotalDifficulty":0,"shanghaiTime":0}},
      "alloc": {{"{TEST_ADDRESS}":{{"balance":"1000000000000000000000"}}}},
      "difficulty":"1","gasLimit":"30000000"
    }}"#)).unwrap();
    fs::write(
        data.join("config.yaml"),
        r#"ethereum:
  endpoint: "http://ethbft-geth:8545"
  engineAPI: "http://ethbft-geth:8551"
  jwtSecret: "/app/jwt.hex"
cometbft:
  endpoint: "http://ethbft-cometbft:26657"
  homeDir: "/cometbft"
bridge:
  listenAddr: "0.0.0.0:8080"
  healthAddr: "0.0.0.0:8081"
  stateFile: "/app/data/ethbft_state.json"
  appVersion: "0.2.0"
  logLevel: "debug"
  enableBridging: true
"#,
    )
    .unwrap();
}

fn compose(root: &Path, args: &[&str], required: bool) {
    let plugin_available = Command::new("docker")
        .args(["compose", "version"])
        .output()
        .is_ok_and(|output| output.status.success());
    let mut command = if plugin_available {
        let mut command = Command::new("docker");
        command.arg("compose");
        command
    } else {
        Command::new("docker-compose")
    };
    command
        .current_dir(root)
        .args([
            "-f",
            "docker-compose.yml",
            "-f",
            "e2e/docker-compose.override.yml",
        ])
        .args(args);
    let status = command.status();
    if required {
        assert!(
            status.is_ok_and(|s| s.success()),
            "docker compose {args:?} failed"
        );
    }
}

async fn rpc(url: &str, method: &str, params: Value) -> Value {
    let value: Value = reqwest::Client::new()
        .post(url)
        .json(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))
        .send()
        .await
        .unwrap_or_else(|error| panic!("RPC {method} request failed: {error}"))
        .json()
        .await
        .unwrap_or_else(|error| panic!("RPC {method} response was invalid: {error}"));
    assert!(value.get("error").is_none(), "RPC {method} failed: {value}");
    value
        .get("result")
        .cloned()
        .unwrap_or_else(|| panic!("{method} returned no result"))
}

async fn rpc_optional(url: &str, method: &str, params: Value) -> Option<Value> {
    let value: Value = reqwest::Client::new()
        .post(url)
        .json(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))
        .send()
        .await
        .ok()?
        .json()
        .await
        .ok()?;
    if value.get("error").is_some() {
        return None;
    }
    value.get("result").cloned()
}

async fn wait_http(url: &str, timeout: Duration) {
    wait_until(timeout, || async {
        reqwest::get(url)
            .await
            .ok()
            .filter(|r| r.status().is_success())
            .is_some()
    })
    .await;
}

async fn wait_until<F, Fut>(timeout: Duration, mut condition: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = Instant::now() + timeout;
    loop {
        if condition().await {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "condition did not become true within {timeout:?}"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

fn hex_quantity(value: &Value) -> u64 {
    u64::from_str_radix(value.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
}

struct Cleanup(PathBuf);
impl Drop for Cleanup {
    fn drop(&mut self) {
        if std::thread::panicking() {
            compose(&self.0, &["logs", "--tail=200"], false);
        } else {
            compose(&self.0, &["down", "-v", "--remove-orphans"], false);
        }
    }
}
