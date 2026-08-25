use crate::node::{ConsensusExecution, Node};
use alloy_primitives::Bytes as EthBytes;
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
                    data: "ethbft-rs".into(),
                    version: node.config.bridge.app_version.clone(),
                    app_version: 2,
                    last_block_height: node.state.abci_last_block_height.try_into()?,
                    last_block_app_hash: node.state.abci_last_app_hash.to_vec().try_into()?,
                }),
                Request::Query(query) => {
                    let mut result = response::Query::default();
                    if query.path == "/tx" && query.data.len() == 32 {
                        if let Ok(hash) = alloy_primitives::B256::try_from(query.data.as_ref()) {
                            if let Some(delivery) = node.delivery(hash) {
                                result.value = serde_json::to_vec(delivery)?.into();
                            }
                        }
                    }
                    Response::Query(result)
                }
                Request::CheckTx(check) => {
                    let mut result = response::CheckTx::default();
                    match node.check_transaction(&check.tx) {
                        Ok(_) => result.log = "accepted into the EthBFT transaction mempool".into(),
                        Err(error) => {
                            node.metrics.txs_rejected.inc();
                            result.code = Code::Err(NonZeroU32::new(1).expect("non-zero"));
                            result.log = error.to_string();
                        }
                    }
                    Response::CheckTx(result)
                }
                Request::InitChain(init) => {
                    info!(chain_id = %init.chain_id, initial_height = %init.initial_height, "ABCI InitChain");
                    Response::InitChain(Default::default())
                }
                Request::PrepareProposal(proposal) => {
                    let height = proposal.height.value();
                    let timestamp = proposal.time.unix_timestamp().try_into()?;
                    let candidates = proposal.txs.into_iter().map(|tx| EthBytes::from(tx.to_vec())).collect();
                    match node.build_proposal(height, timestamp, candidates, proposal.max_tx_bytes).await {
                        Ok(txs) => Response::PrepareProposal(response::PrepareProposal {
                            txs: txs.into_iter().map(|tx| AbciBytes::copy_from_slice(&tx)).collect(),
                        }),
                        Err(error) => {
                            warn!(height, %error, "failed to build execution proposal");
                            Response::PrepareProposal(response::PrepareProposal { txs: vec![] })
                        }
                    }
                }
                Request::ProcessProposal(proposal) => {
                    let height = proposal.height.value();
                    let timestamp = proposal.time.unix_timestamp().try_into()?;
                    let txs = proposal.txs.iter().map(|tx| EthBytes::from(tx.to_vec())).collect::<Vec<_>>();
                    match node.validate_proposal(height, timestamp, &txs).await {
                        Ok(_) => Response::ProcessProposal(response::ProcessProposal::Accept),
                        Err(error) => {
                            warn!(height, %error, "rejected execution proposal");
                            Response::ProcessProposal(response::ProcessProposal::Reject)
                        }
                    }
                }
                Request::FinalizeBlock(block) => {
                    let height = block.height.value();
                    let timestamp = block.time.unix_timestamp().try_into()?;
                    let proposal = block.txs.iter().map(|tx| EthBytes::from(tx.to_vec())).collect::<Vec<_>>();
                    let app_hash = node.stage_decision(height, timestamp, &proposal).await?;
                    let mut tx_results = Vec::with_capacity(block.txs.len());
                    for (index, tx) in block.txs.iter().enumerate() {
                        tx_results.push(ExecTxResult {
                            code: Code::Ok,
                            data: if index == 0 { AbciBytes::new() } else { tx.clone() },
                            log: if index == 0 { "execution payload metadata committed".into() } else { "executed in BFT-committed payload".into() },
                            ..Default::default()
                        });
                    }
                    Response::FinalizeBlock(response::FinalizeBlock {
                        tx_results,
                        app_hash: app_hash.to_vec().try_into()?,
                        events: vec![],
                        validator_updates: vec![],
                        consensus_param_updates: None,
                    })
                }
                Request::Commit => {
                    node.commit()?;
                    Response::Commit(response::Commit {
                        data: AbciBytes::new(),
                        retain_height: 0u32.into(),
                    })
                }
                Request::ExtendVote(_) => Response::ExtendVote(response::ExtendVote { vote_extension: AbciBytes::new() }),
                Request::VerifyVoteExtension(_) => Response::VerifyVoteExtension(response::VerifyVoteExtension::Accept),
                Request::ListSnapshots => Response::ListSnapshots(Default::default()),
                Request::OfferSnapshot(_) => Response::OfferSnapshot(Default::default()),
                Request::LoadSnapshotChunk(_) => Response::LoadSnapshotChunk(Default::default()),
                Request::ApplySnapshotChunk(_) => Response::ApplySnapshotChunk(Default::default()),
                Request::Flush => Response::Flush,
                Request::Echo(echo) => Response::Echo(response::Echo { message: echo.message }),
            };
            Ok(response)
        }.boxed()
    }
}

pub async fn serve(node: Arc<Mutex<Node>>, listen_addr: String) -> anyhow::Result<()> {
    let service = EthBftService { node };
    let (consensus, mempool, snapshot, info) = split::service(service, 8);
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
