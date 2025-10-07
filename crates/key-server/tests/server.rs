use async_trait::async_trait;
use sui_sdk::error::SuiRpcResult;
use sui_sdk::rpc_types::{Checkpoint, CheckpointId, DryRunTransactionBlockResponse, SuiObjectDataOptions, SuiObjectResponse, ZkLoginIntentScope, ZkLoginVerifyResult};
use sui_sdk::SuiClient;
use sui_types::base_types::{ObjectID, SuiAddress};
use sui_types::dynamic_field::DynamicFieldName;
use sui_types::messages_checkpoint::CheckpointSequenceNumber;
use sui_types::transaction::TransactionData;
use key_server::sui_rpc_client::RpcClient;

#[derive(Clone)]
struct MockSuiClient;

#[async_trait]
impl RpcClient for MockSuiClient {
    async fn new_from_builder<Fut>(_build: Fut) -> SuiRpcResult<Self>
    where
        Fut: Future<Output=SuiRpcResult<SuiClient>> + Send
    {
        todo!()
    }

    async fn dry_run_transaction_block(&self, _tx: TransactionData) -> SuiRpcResult<DryRunTransactionBlockResponse> {
        todo!()
    }

    async fn get_object_with_options(&self, _object_id: ObjectID, _options: SuiObjectDataOptions) -> SuiRpcResult<SuiObjectResponse> {
        todo!()
    }

    async fn get_latest_checkpoint_sequence_number(&self) -> SuiRpcResult<CheckpointSequenceNumber> {
        todo!()
    }

    async fn get_checkpoint(&self, _id: CheckpointId) -> SuiRpcResult<Checkpoint> {
        todo!()
    }

    async fn get_dynamic_field_object(&self, _parent_object_id: ObjectID, _name: DynamicFieldName) -> SuiRpcResult<SuiObjectResponse> {
        todo!()
    }

    async fn get_reference_gas_price(&self) -> SuiRpcResult<u64> {
        todo!()
    }

    async fn verify_zklogin_signature(&self, _bytes: String, _signature: String, _intent_scope: ZkLoginIntentScope, _address: SuiAddress) -> SuiRpcResult<ZkLoginVerifyResult> {
        todo!()
    }
}