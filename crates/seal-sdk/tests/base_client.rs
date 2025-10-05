use std::collections::HashMap;
use std::str::FromStr;
use anyhow::anyhow;
use async_trait::async_trait;
use sui_types::base_types::ObjectID;
use seal_sdk::client::base_client::{BaseSealClient, DerivedKeys, KeyServerInfo};
use seal_sdk::client::cache::NoCache;
use seal_sdk::client::cache_key::{DerivedKeyCacheKey, KeyServerInfoCacheKey};
use seal_sdk::client::http_client::{HttpClient, PostResponse};
use seal_sdk::client::sui_client::SuiClient;

struct MockSuiClient;

#[async_trait]
impl SuiClient for MockSuiClient {
    type Error = anyhow::Error;

    async fn get_key_server_info(
        &self,
        key_server_id: [u8; 32]
    ) -> Result<KeyServerInfo, Self::Error> {
        Err(anyhow!("Not yet implemented"))
    }
}

struct MockHttpClient;

#[async_trait]
impl HttpClient for MockHttpClient {
    type PostError = anyhow::Error;

    async fn post<S: ToString + Send + Sync>(
        &self,
        url: &str,
        headers: HashMap<String, String>,
        body: S
    ) -> Result<PostResponse, Self::PostError> {
        Err(anyhow!("Not yet implemented"))
    }
}

type MockSealClient = BaseSealClient<
    NoCache<KeyServerInfoCacheKey, KeyServerInfo>,
    NoCache<DerivedKeyCacheKey, Vec<DerivedKeys>>,
    anyhow::Error,
    MockSuiClient,
    anyhow::Error,
    MockHttpClient
>;

fn new_mock_seal_client() -> MockSealClient {
    BaseSealClient::new_custom(
        Default::default(),
        Default::default(),
        MockSuiClient,
        MockHttpClient
    )
}

#[tokio::test]
async fn test_encrypt_and_decrypt_data_one_server() {
    let client = new_mock_seal_client();

    let package_id = ObjectID::from_str("0x2").unwrap();
    let decrypted_message: Vec<u8> = vec![];
    let message_id: Vec<u8> = vec![];
    let key_servers: Vec<ObjectID> = vec![ObjectID::from_str("0x1").unwrap()];

    client.encrypt_bytes(
        package_id,
        message_id,
        1,
        key_servers,
        decrypted_message,
    ).await.unwrap();
}
