use async_trait::async_trait;
use sui_sdk::error::SuiRpcResult;
use sui_sdk::rpc_types::SuiObjectResponse;
use sui_types::base_types::ObjectID;
use sui_types::dynamic_field::DynamicFieldName;

#[async_trait]
pub trait SuiClient: Sync {
    async fn get_dynamic_field_object(
        &self,
        parent_object_id: ObjectID,
        name: DynamicFieldName,
    ) -> SuiRpcResult<SuiObjectResponse>;
}

#[async_trait]
impl SuiClient for sui_sdk::SuiClient {
    async fn get_dynamic_field_object(
        &self,
        parent_object_id: ObjectID,
        name: DynamicFieldName,
    ) -> SuiRpcResult<SuiObjectResponse> {
        self.read_api()
            .get_dynamic_field_object(
                parent_object_id,
                name,
            ).await
    }
}