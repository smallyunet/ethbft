use crate::node::{ConsensusApplication, Node};
use bytes::Bytes as AbciBytes;
use futures::{future::BoxFuture, FutureExt};
use std::{
    num::NonZeroU32,
    sync::Arc,
    task::{Context, Poll},
};
use tendermint::{
    abci::{response, types::ExecTxResult, Code},
    v0_38::abci::{Request, Response},
};
use tokio::sync::Mutex;
use tower::Service;
use tower_abci::{
    v038::{split, Server},
    BoxError,
};
use tracing::{info, warn};

#[derive(Clone)]
struct EthBftService {
    node: Arc<Mutex<Node>>,
}

impl Service<Request> for EthBftService {
    type Response = Response;
    type Error = BoxError;
    type Future = BoxFuture<'static, Result<Response, BoxError>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request) -> Self::Future {
        let node = self.node.clone();
        async move {
            let mut node = node.lock().await;
            let response = match request {
                Request::Info(_) => Response::Info(response::Info {
                    data: "ethbft-protocol-v2".into(),
                    version: node.config.node.app_version.clone(),
                    app_version: 3,
                    last_block_height: node.state.last_committed_height.try_into()?,
                    last_block_app_hash: node.state.last_app_hash.to_vec().try_into()?,
                }),
                Request::Query(query) => {
                    let mut result = response::Query::default();
                    if query.path == "/status" {
                        result.value = serde_json::to_vec(&serde_json::json!({
                            "protocol":2, "height":node.state.last_committed_height,
                            "executionBlockHash":node.state.last_execution_hash, "chainId":node.chain_id,
                        }))?.into();
                    }
                    Response::Query(result)
                }
                Request::CheckTx(_) => {
                    let result = response::CheckTx {
                        code: Code::Err(NonZeroU32::new(1).expect("non-zero")),
                        log: "EthBFT has no transaction mempool; submit transactions to the execution client's JSON-RPC endpoint".into(),
                        ..Default::default()
                    };
                    Response::CheckTx(result)
                }
                Request::InitChain(init) => {
                    info!(chain_id = %init.chain_id, initial_height = %init.initial_height, "ABCI InitChain");
                    Response::InitChain(Default::default())
                }
                Request::PrepareProposal(proposal) => {
                    let height = proposal.height.value();
                    let timestamp = proposal.time.unix_timestamp().try_into()?;
                    match node.propose(height, timestamp, proposal.max_tx_bytes).await {
                        Ok(envelope) => Response::PrepareProposal(response::PrepareProposal { txs: vec![AbciBytes::copy_from_slice(&envelope)] }),
                        Err(error) => { warn!(height, %error, "failed to build execution proposal"); Response::PrepareProposal(response::PrepareProposal { txs: vec![] }) }
                    }
                }
                Request::ProcessProposal(proposal) => {
                    let height = proposal.height.value();
                    let timestamp = proposal.time.unix_timestamp().try_into()?;
                    let result = match proposal.txs.as_slice() {
                        [envelope] => node.validate(height, timestamp, envelope).await,
                        _ => Err(anyhow::anyhow!("proposal must contain exactly one execution envelope")),
                    };
                    match result {
                        Ok(_) => Response::ProcessProposal(response::ProcessProposal::Accept),
                        Err(error) => { warn!(height, %error, "rejected execution proposal"); Response::ProcessProposal(response::ProcessProposal::Reject) }
                    }
                }
                Request::FinalizeBlock(block) => {
                    let height = block.height.value();
                    let timestamp = block.time.unix_timestamp().try_into()?;
                    let envelope = match block.txs.as_slice() {
                        [envelope] => envelope,
                        _ => return Err(anyhow::anyhow!("finalized block must contain exactly one execution envelope").into()),
                    };
                    let app_hash = node.decide(height, timestamp, envelope).await?;
                    Response::FinalizeBlock(response::FinalizeBlock {
                        tx_results: vec![ExecTxResult { code:Code::Ok, log:"execution envelope committed".into(), ..Default::default() }],
                        app_hash: app_hash.to_vec().try_into()?, events:vec![], validator_updates:vec![], consensus_param_updates:None,
                    })
                }
                Request::Commit => { node.commit()?; Response::Commit(response::Commit { data:AbciBytes::new(), retain_height:0u32.into() }) }
                Request::ExtendVote(_) => Response::ExtendVote(response::ExtendVote { vote_extension:AbciBytes::new() }),
                Request::VerifyVoteExtension(_) => Response::VerifyVoteExtension(response::VerifyVoteExtension::Accept),
                Request::ListSnapshots => Response::ListSnapshots(Default::default()),
                Request::OfferSnapshot(_) => Response::OfferSnapshot(Default::default()),
                Request::LoadSnapshotChunk(_) => Response::LoadSnapshotChunk(Default::default()),
                Request::ApplySnapshotChunk(_) => Response::ApplySnapshotChunk(Default::default()),
                Request::Flush => Response::Flush,
                Request::Echo(echo) => Response::Echo(response::Echo { message:echo.message }),
            };
            Ok(response)
        }.boxed()
    }
}

pub async fn serve(node: Arc<Mutex<Node>>, listen_addr: String) -> anyhow::Result<()> {
    let (consensus, mempool, snapshot, info) = split::service(EthBftService { node }, 8);
    let server = Server::builder()
        .consensus(consensus)
        .mempool(mempool)
        .snapshot(snapshot)
        .info(info)
        .finish()
        .expect("all ABCI services configured");
    info!(address = %listen_addr, "ABCI server listening");
    server
        .listen_tcp(listen_addr)
        .await
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    Ok(())
}
