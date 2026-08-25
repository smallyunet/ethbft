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
const GETH_URLS: [&str; 4] = [
    "http://localhost:18545",
    "http://localhost:18555",
    "http://localhost:18565",
    "http://localhost:18575",
];
const COMET_URLS: [&str; 4] = [
    "http://localhost:26657",
    "http://localhost:27657",
    "http://localhost:28657",
    "http://localhost:29657",
];
const HEALTH_URLS: [&str; 4] = [
    "http://localhost:18081/live",
    "http://localhost:18091/live",
    "http://localhost:18101/live",
    "http://localhost:18111/live",
];

#[tokio::test]
async fn four_validators_survive_one_failure_and_recover() {
    if std::env::var("ETHBFT_MULTINODE_E2E").as_deref() != Ok("1") {
        return;
    }

    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    compose(&root, &["down", "-v", "--remove-orphans"], false);
    prepare(&root);
    let _guard = Cleanup(root.clone());

    if std::env::var("ETHBFT_MULTINODE_E2E_NO_BUILD").as_deref() != Ok("1") {
        compose(&root, &["build", "ethbft0"], true);
    }
    compose(&root, &["up", "-d"], true);

    for url in COMET_URLS {
        wait_http(&format!("{url}/status"), Duration::from_secs(180)).await;
    }
    for url in HEALTH_URLS {
        wait_http(url, Duration::from_secs(180)).await;
    }
    wait_comet_height(COMET_URLS[0], 5, Duration::from_secs(120)).await;

    assert_comet_block_equal(3, &COMET_URLS).await;
    for url in GETH_URLS {
        let balance = rpc(
            url,
            "eth_getBalance",
            json!([format!("0x{TEST_ADDRESS}"), "latest"]),
        )
        .await;
        assert_eq!(balance.as_str(), Some("0x3635c9adc5dea00000"));
    }

    compose(&root, &["stop", "comet3", "ethbft3", "geth3"], true);
    let height_before_failure = comet_height(COMET_URLS[0]).await;

    let submitted = rpc(
        GETH_URLS[0],
        "eth_sendRawTransaction",
        json!([format!("0x{RAW_TX}")]),
    )
    .await;
    assert_eq!(submitted.as_str(), Some(TX_HASH));

    let receipt = wait_receipt(GETH_URLS[0], Duration::from_secs(180)).await;
    assert_eq!(receipt.get("status").and_then(Value::as_str), Some("0x1"));
    let execution_height = hex_quantity(&receipt["blockNumber"]);
    let execution_hash = receipt["blockHash"].as_str().unwrap().to_owned();

    for url in &GETH_URLS[..3] {
        let peer_receipt = wait_receipt(url, Duration::from_secs(120)).await;
        assert_eq!(peer_receipt["blockHash"], execution_hash);
    }
    wait_comet_height(
        COMET_URLS[0],
        height_before_failure + 3,
        Duration::from_secs(120),
    )
    .await;
    assert_comet_block_equal(execution_height, &COMET_URLS[..3]).await;
    assert_execution_block_equal(execution_height, &GETH_URLS[..3]).await;

    compose(&root, &["up", "-d", "geth3", "ethbft3", "comet3"], true);
    wait_http(HEALTH_URLS[3], Duration::from_secs(180)).await;
    let catch_up_target = comet_height(COMET_URLS[0]).await;
    wait_until(Duration::from_secs(180), || async {
        let Some(status) = get_json(&format!("{}/status", COMET_URLS[3])).await else {
            return false;
        };
        status
            .pointer("/result/sync_info/catching_up")
            .and_then(Value::as_bool)
            == Some(false)
            && status
                .pointer("/result/sync_info/latest_block_height")
                .and_then(Value::as_str)
                .and_then(|height| height.parse::<u64>().ok())
                .is_some_and(|height| height >= catch_up_target)
    })
    .await;

    let recovered_receipt = wait_receipt(GETH_URLS[3], Duration::from_secs(120)).await;
    assert_eq!(recovered_receipt["blockHash"], execution_hash);
    assert_comet_block_equal(execution_height, &COMET_URLS).await;
    assert_execution_block_equal(execution_height, &GETH_URLS).await;
}

fn prepare(root: &Path) {
    let data = root.join("e2e/multinode/data");
    if data.exists() {
        fs::remove_dir_all(&data).unwrap();
    }
    fs::create_dir_all(data.join("comet")).unwrap();
    fs::write(data.join("jwt.hex"), "00".repeat(32)).unwrap();

    let genesis = format!(
        r#"{{
  "config": {{"chainId":1337,"homesteadBlock":0,"eip150Block":0,"eip155Block":0,"eip158Block":0,"byzantiumBlock":0,"constantinopleBlock":0,"petersburgBlock":0,"istanbulBlock":0,"berlinBlock":0,"londonBlock":0,"terminalTotalDifficulty":0,"shanghaiTime":0}},
  "alloc": {{"{TEST_ADDRESS}":{{"balance":"1000000000000000000000"}}}},
  "difficulty":"1","gasLimit":"30000000"
}}"#
    );

    for index in 0..4 {
        let geth = data.join(format!("geth{index}"));
        let app = data.join(format!("ethbft{index}"));
        fs::create_dir_all(&geth).unwrap();
        fs::create_dir_all(&app).unwrap();
        fs::write(geth.join("genesis.json"), &genesis).unwrap();
        fs::write(
            data.join(format!("config{index}.yaml")),
            format!(
                r#"execution:
  endpoint: "http://geth{index}:8551"
  jwtSecret: "/app/jwt.hex"
cometbft:
  endpoint: "http://comet{index}:26657"
protocol:
  shanghaiTime: 0
  maxPayloadBytes: 16777216
node:
  listenAddr: "0.0.0.0:8080"
  healthAddr: "0.0.0.0:8081"
  stateFile: "/app/data/ethbft_state.json"
  appVersion: "0.3.0-alpha.2"
  logLevel: "debug"
"#
            ),
        )
        .unwrap();
    }
    make_tree_writable(&data);

    let container_user = format!("{}:{}", host_id("-u"), host_id("-g"));
    let output = Command::new("docker")
        .args([
            "run",
            "--rm",
            "--user",
            &container_user,
            "--entrypoint",
            "cometbft",
            "-e",
            "CMTHOME=/out/.home",
            "-v",
            &format!("{}:/out", data.join("comet").display()),
            "cometbft/cometbft:v0.38.21@sha256:97201755bec7079c41d3ec8f0de3b55bc11f8b590046bc31dd616727d0fbb47f",
            "testnet",
            "--v",
            "4",
            "--n",
            "0",
            "--o",
            "/out",
            "--hostname-prefix",
            "comet",
            "--node-dir-prefix",
            "node",
            "--populate-persistent-peers",
        ])
        .status()
        .expect("failed to run CometBFT testnet generator");
    assert!(output.success(), "CometBFT testnet generation failed");
    make_tree_writable(&data);
}

fn host_id(flag: &str) -> String {
    let output = Command::new("id")
        .arg(flag)
        .output()
        .expect("failed to query the host user ID");
    assert!(output.status.success(), "id {flag} failed");
    String::from_utf8(output.stdout)
        .expect("host user ID was not UTF-8")
        .trim()
        .to_owned()
}

#[cfg(unix)]
fn make_tree_writable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;

    let metadata = fs::metadata(path).unwrap();
    let mode = if metadata.is_dir() { 0o777 } else { 0o666 };
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    if metadata.is_dir() {
        for entry in fs::read_dir(path).unwrap() {
            make_tree_writable(&entry.unwrap().path());
        }
    }
}

#[cfg(not(unix))]
fn make_tree_writable(_path: &Path) {}

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
            "-p",
            "ethbft-multinode",
            "-f",
            "e2e/multinode/docker-compose.yml",
        ])
        .args(args);
    let status = command.status();
    if required {
        assert!(
            status.is_ok_and(|value| value.success()),
            "docker compose {args:?} failed"
        );
    }
}

async fn assert_comet_block_equal(height: u64, urls: &[&str]) {
    let mut expected: Option<(Value, Value)> = None;
    for url in urls {
        let block = get_json(&format!("{url}/block?height={height}"))
            .await
            .unwrap_or_else(|| panic!("missing CometBFT block {height} from {url}"));
        let pair = (
            block["result"]["block_id"]["hash"].clone(),
            block["result"]["block"]["header"]["app_hash"].clone(),
        );
        if let Some(expected) = &expected {
            assert_eq!(&pair, expected, "CometBFT block {height} differs at {url}");
        } else {
            expected = Some(pair);
        }
    }
}

async fn assert_execution_block_equal(height: u64, urls: &[&str]) {
    let mut expected: Option<Value> = None;
    for url in urls {
        let block = rpc(
            url,
            "eth_getBlockByNumber",
            json!([format!("0x{height:x}"), false]),
        )
        .await;
        let hash = block["hash"].clone();
        if let Some(expected) = &expected {
            assert_eq!(&hash, expected, "execution block {height} differs at {url}");
        } else {
            expected = Some(hash);
        }
    }
}

async fn wait_receipt(url: &str, timeout: Duration) -> Value {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(receipt) =
            rpc_optional(url, "eth_getTransactionReceipt", json!([TX_HASH])).await
        {
            return receipt;
        }
        assert!(
            Instant::now() < deadline,
            "transaction receipt did not appear at {url} within {timeout:?}"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

async fn wait_comet_height(url: &str, target: u64, timeout: Duration) {
    wait_until(timeout, || async {
        comet_height_optional(url).await >= Some(target)
    })
    .await;
}

async fn comet_height(url: &str) -> u64 {
    comet_height_optional(url)
        .await
        .unwrap_or_else(|| panic!("missing CometBFT height from {url}"))
}

async fn comet_height_optional(url: &str) -> Option<u64> {
    get_json(&format!("{url}/status"))
        .await?
        .pointer("/result/sync_info/latest_block_height")?
        .as_str()?
        .parse()
        .ok()
}

async fn rpc(url: &str, method: &str, params: Value) -> Value {
    let value = rpc_response(url, method, params)
        .await
        .unwrap_or_else(|| panic!("RPC {method} request to {url} failed"));
    assert!(value.get("error").is_none(), "RPC {method} failed: {value}");
    value
        .get("result")
        .cloned()
        .unwrap_or_else(|| panic!("{method} returned no result"))
}

async fn rpc_optional(url: &str, method: &str, params: Value) -> Option<Value> {
    let value = rpc_response(url, method, params).await?;
    if value.get("error").is_some() {
        return None;
    }
    value
        .get("result")
        .filter(|result| !result.is_null())
        .cloned()
}

async fn rpc_response(url: &str, method: &str, params: Value) -> Option<Value> {
    reqwest::Client::new()
        .post(url)
        .json(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))
        .send()
        .await
        .ok()?
        .json()
        .await
        .ok()
}

async fn get_json(url: &str) -> Option<Value> {
    reqwest::get(url).await.ok()?.json().await.ok()
}

async fn wait_http(url: &str, timeout: Duration) {
    wait_until(timeout, || async {
        reqwest::get(url)
            .await
            .ok()
            .is_some_and(|response| response.status().is_success())
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
        }
        compose(&self.0, &["down", "-v", "--remove-orphans"], false);
    }
}
