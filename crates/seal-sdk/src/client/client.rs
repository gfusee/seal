use crate::client::cache::{NoCache, SealCache};
use crate::client::cache_key::{DerivedKeyCacheKey, KeyServerInfoCacheKey};
use crate::client::error::SealClientError;
use crate::types::{ElGamalPublicKey, ElgamalVerificationKey};
use crate::{
    seal_decrypt_all_objects, signed_message, Certificate, ElGamalSecretKey,
    FetchKeyRequest, FetchKeyResponse, IBEPublicKey,
};
use base64::Engine;
use crypto::elgamal::genkey;
use crypto::{
    seal_encrypt, EncryptedObject, EncryptionInput, IBEPublicKeys,
};
use fastcrypto::ed25519::Ed25519KeyPair;
use fastcrypto::groups::FromTrustedByteArray;
use fastcrypto::traits::{KeyPair, Signer};
use futures::future::join_all;
use reqwest::{Body, Client};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use shared_crypto::intent::{Intent, IntentMessage};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use sui_sdk::rpc_types::{SuiMoveValue, SuiParsedData};
use sui_sdk::SuiClient;
use sui_sdk_types::{SimpleSignature, UserSignature};
use sui_types::base_types::ObjectID;
use sui_types::crypto::{get_key_pair, Signature, SuiSignature};
use sui_types::dynamic_field::DynamicFieldName;
use sui_types::transaction::ProgrammableTransaction;
use sui_types::TypeTag;
use tokio::sync::Mutex;

/// Key server object layout containing object id, name, url, and public key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyServerInfo {
    pub object_id: ObjectID,
    pub name: String,
    pub url: String,
    pub public_key: String,
}

pub type DerivedKeys = (ObjectID, FetchKeyResponse);

pub type SealClient = BaseSealClient<
    NoCache<KeyServerInfoCacheKey, KeyServerInfo>,
    NoCache<DerivedKeyCacheKey, Vec<DerivedKeys>>,
>;

pub type SealClientLeakingCache = BaseSealClient<
    Arc<Mutex<HashMap<KeyServerInfoCacheKey, KeyServerInfo>>>,
    Arc<Mutex<HashMap<DerivedKeyCacheKey, Vec<DerivedKeys>>>>,
>;

#[derive(Clone)]
pub struct BaseSealClient<KeyServerInfoCache, DerivedKeysCache>
where
    KeyServerInfoCache: SealCache<Key = KeyServerInfoCacheKey, Value = KeyServerInfo>,
    DerivedKeysCache: SealCache<Key = DerivedKeyCacheKey, Value = Vec<DerivedKeys>>,
{
    key_server_info_cache: KeyServerInfoCache,
    derived_key_cache: DerivedKeysCache,
    sui_client: SuiClient,
    http: Client,
}

#[derive(Serialize, Deserialize)]
struct RequestFormat {
    ptb: Vec<u8>,
    enc_key: Vec<u8>,
    enc_verification_key: Vec<u8>,
}

impl SealClient {
    pub fn new_no_cache(
        sui_client: SuiClient
    ) -> SealClient {
        BaseSealClient::new_custom_caches(
            ().into(),
            ().into(),
            sui_client
        )
    }
}

impl SealClientLeakingCache {
    pub fn new_no_cache(
        sui_client: SuiClient
    ) -> SealClientLeakingCache {
        BaseSealClient::new_custom_caches(
            Default::default(),
            Default::default(),
            sui_client
        )
    }
}

impl<KeyServerInfoCache, DerivedKeysCache> BaseSealClient<KeyServerInfoCache, DerivedKeysCache>
where
    KeyServerInfoCache: SealCache<Key = KeyServerInfoCacheKey, Value = KeyServerInfo>,
    DerivedKeysCache: SealCache<Key = DerivedKeyCacheKey, Value = Vec<DerivedKeys>>,
{
    pub fn new_custom_caches(
        key_server_info_cache: KeyServerInfoCache,
        derived_key_cache: DerivedKeysCache,
        sui_client: SuiClient
    ) -> Self {
        BaseSealClient {
            key_server_info_cache,
            derived_key_cache,
            sui_client,
            http: Client::new(),
        }
    }

    pub async fn encrypt_bytes(
        &mut self,
        package_id: ObjectID,
        id: Vec<u8>,
        threshold: u8,
        key_servers: Vec<ObjectID>,
        data: Vec<u8>,
    ) -> Result<EncryptedObject, SealClientError> {
        let key_server_info = self.fetch_key_server_info(key_servers.clone()).await?;
        let public_keys_g2 = key_server_info
            .iter()
            .map(|info| self.decode_public_key(info))
            .collect::<Result<_, _>>()?;

        let public_keys = IBEPublicKeys::BonehFranklinBLS12381(public_keys_g2);

        let key_servers = key_servers
            .into_iter()
            .map(|object_id| sui_sdk_types::ObjectId::from(object_id.into_bytes()))
            .collect();

        let result = seal_encrypt(
            sui_sdk_types::ObjectId::from(package_id.into_bytes()),
            id,
            key_servers,
            &public_keys,
            threshold,
            EncryptionInput::Aes256Gcm { data, aad: None },
        )?;

        Ok(result.0)
    }

    #[allow(dead_code)]
    pub async fn key_server_info(
        &mut self,
        key_server_ids: Vec<ObjectID>,
    ) -> Result<Vec<KeyServerInfo>, SealClientError> {
        self.fetch_key_server_info(key_server_ids).await
    }

    pub async fn decrypt_object<T: DeserializeOwned>(
        &mut self,
        package_id: ObjectID,
        encrypted_object_data: &[u8],
        approve_transaction_data: ProgrammableTransaction,
    ) -> Result<T, SealClientError> {
        let encrypted_object = bcs::from_bytes::<EncryptedObject>(encrypted_object_data)?;

        let service_ids: Vec<ObjectID> = encrypted_object
            .services
            .iter()
            .map(|(id, _)| ObjectID::new(id.into_inner()))
            .collect();

        let key_server_info = self.fetch_key_server_info(service_ids).await?;
        let servers_public_keys_map = key_server_info
            .iter()
            .map(|info| {
                Ok::<_, SealClientError>((
                    sui_sdk_types::ObjectId::new(info.object_id.into_bytes()),
                    self.decode_public_key(info)?,
                ))
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .collect::<HashMap<_, _>>();

        let (enc_secret, signed_request) = self.get_signed_request_dummy_wallet(
            sui_sdk_types::ObjectId::from(package_id.into_bytes()),
            bcs::to_bytes(&approve_transaction_data)?,
        )?;

        let derived_keys = self
            .fetch_derived_keys(
                signed_request,
                key_server_info,
                encrypted_object.threshold,
            )
            .await?
            .into_iter()
            .map(|derived_key| (sui_sdk_types::ObjectId::new(derived_key.0.into_bytes()), derived_key.1))
            .collect::<Vec<_>>();

        let encrypted_objects = [encrypted_object];
        let decrypted_result = seal_decrypt_all_objects(
            &enc_secret,
            &derived_keys,
            &encrypted_objects,
            &servers_public_keys_map,
        )?
            .into_iter()
            .next()
            .ok_or_else(|| SealClientError::MissingDecryptedObject)?;

        Ok(bcs::from_bytes::<T>(&decrypted_result)?)
    }

    async fn fetch_key_server_info(
        &self,
        key_server_ids: Vec<ObjectID>,
    ) -> Result<Vec<KeyServerInfo>, SealClientError> {
        let mut key_server_info_futures = vec![];
        for key_server_id in key_server_ids {
            let cache_key = KeyServerInfoCacheKey::new(key_server_id);

            let future = async move {
                self.key_server_info_cache
                    .try_get_with(
                        cache_key,
                        self.load_key_server_info(key_server_id)
                    )
                    .await
                    .map_err(unwrap_cache_error)
            };

            key_server_info_futures.push(future);
        }

        join_all(key_server_info_futures)
            .await
            .into_iter()
            .collect::<Result<_, _>>()
    }

    async fn load_key_server_info(
        &self,
        key_server_id: ObjectID,
    ) -> Result<KeyServerInfo, SealClientError> {
        let dynamic_field_name = DynamicFieldName {
            type_: TypeTag::U64,
            value: Value::String("1".to_string()),
        };

        let response = self
            .sui_client
            .read_api()
            .get_dynamic_field_object(key_server_id, dynamic_field_name)
            .await?;

        let object_data = response.data.ok_or_else(|| {
            SealClientError::NoObjectDataFromTheSuiRPC {
                object_id: key_server_id,
            }
        })?;

        let content = object_data.content.ok_or_else(|| {
            SealClientError::NoObjectDataFromTheSuiRPC {
                object_id: key_server_id,
            }
        })?;

        let parsed = match content {
            SuiParsedData::MoveObject(obj) => obj,
            _ => {
                return Err(SealClientError::InvalidObjectDataFromTheSuiRPC {
                    object_id: key_server_id,
                })
            }
        };

        let error_no_move_field = |field_name: &str| {
            SealClientError::MissingKeyServerField { field_name: field_name.to_string() }
        };

        let url_value = parsed.fields
            .field_value("url")
            .ok_or_else(|| error_no_move_field("url"))?;

        let name_value = parsed.fields
            .field_value("name")
            .ok_or_else(|| error_no_move_field("name"))?;

        let public_key_value = parsed.fields
            .field_value("pk")
            .ok_or_else(|| error_no_move_field("pk"))?;

        let (url, name, public_key) = match (url_value, name_value, public_key_value) {
            (SuiMoveValue::String(url), SuiMoveValue::String(name), SuiMoveValue::Vector(public_key_values)) => {
                let public_key_bytes = public_key_values
                    .into_iter()
                    .map(|value| {
                        match value {
                            SuiMoveValue::Number(byte) => {
                                match u8::try_from(byte) {
                                    Ok(byte) => Ok(byte),
                                    Err(_) => Err(SealClientError::InvalidKeyServerDynamicFieldsType { object_id: key_server_id }),
                                }
                            },
                            _ => Err(SealClientError::InvalidKeyServerDynamicFieldsType { object_id: key_server_id }),
                        }
                    })
                    .collect::<Result<Vec<u8>, _>>()?;

                let public_key = hex::encode(&public_key_bytes);

                (url, name, public_key)
            }
            _ => return Err(SealClientError::InvalidKeyServerDynamicFieldsType { object_id: key_server_id }),
        };

        let key_server_info = KeyServerInfo {
            object_id: key_server_id,
            name,
            url,
            public_key,
        };

        Ok(key_server_info)
    }

    async fn fetch_derived_keys(
        &mut self,
        request: FetchKeyRequest,
        key_servers_info: Vec<KeyServerInfo>,
        threshold: u8,
    ) -> Result<Vec<DerivedKeys>, SealClientError> {
        let request_json = request.to_json_string()?;

        let server_ids: Vec<ObjectID> =
            key_servers_info.iter().map(|info| info.object_id).collect();

        let cache_key = DerivedKeyCacheKey::new(
            request_json.clone().into_bytes(),
            server_ids,
            threshold
        );

        let cache_future = async {
            let mut seal_responses: Vec<DerivedKeys> = Vec::new();
            for server in key_servers_info.iter() {
                let url = format!("{}/v1/fetch_key", server.url);
                let response = self
                    .http
                    .post(&url)
                    .header("Client-Sdk-Type", "rust")
                    .header("Client-Sdk-Version", "1.0.0")
                    .header("Content-Type", "application/json")
                    .body(Body::from(request_json.clone()))
                    .send()
                    .await?;

                let response_status = response.status();
                let response = response.text()
                    .await
                    .ok();

                if !response_status.is_success() || response.is_none() {
                    return Err(SealClientError::ErrorWhileFetchingDerivedKeys {
                        url,
                        status: response_status.as_u16(),
                        response
                    });
                }

                let response = response.unwrap();

                let response: FetchKeyResponse = serde_json::from_str(&response)?;

                seal_responses.push((server.object_id, response));

                if seal_responses.len() >= threshold as usize {
                    break;
                }
            }

            let seal_responses_len = seal_responses.len();

            if seal_responses_len < threshold as usize {
                return Err(SealClientError::InsufficientKeys {
                    received: seal_responses_len,
                    threshold,
                });
            }

            Ok(seal_responses)
        };

        self.derived_key_cache
            .try_get_with(
                cache_key,
                cache_future
            )
            .await
            .map_err(unwrap_cache_error)
    }

    fn decode_public_key(&self, info: &KeyServerInfo) -> Result<IBEPublicKey, SealClientError> {
        let bytes = hex::decode(&info.public_key)?;

        let array: [u8; 96] = bytes.as_slice().try_into().map_err(|_| {
            SealClientError::InvalidPublicKey {
                public_key: info.public_key.clone(),
                reason: "Invalid length.".to_string()
            }
        })?;

        Ok(IBEPublicKey::from_trusted_byte_array(&array)?)
    }

    fn get_signed_request_dummy_wallet(
        &self,
        package_id: sui_sdk_types::ObjectId,
        approve_transaction_data: Vec<u8>,
    ) -> Result<(ElGamalSecretKey, FetchKeyRequest), SealClientError> {
        let eg_keys = genkey(&mut rand::thread_rng());

        let (key_pair_address, key_pair): (_, Ed25519KeyPair) = get_key_pair();

        let creation_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let ttl_min = 1u16;

        let message_to_sign = signed_message(
            package_id.to_string(),
            key_pair.public(),
            creation_time,
            ttl_min,
        );

        let personal_message = IntentMessage::new(
            Intent::personal_message(),
            message_to_sign.as_bytes().to_vec(),
        );

        let Signature::Ed25519SuiSignature(personal_message_signature) =
            Signature::new_secure(&personal_message, &key_pair)
        else {
            return Err(SealClientError::CannotSignPersonalMessage { message: message_to_sign });
        };

        let approve_transaction_data_base64 = base64::engine::general_purpose::STANDARD.encode(&approve_transaction_data);

        let request_to_be_signed = self.request_to_be_signed(approve_transaction_data, &eg_keys.1, &eg_keys.2)?;

        let request = FetchKeyRequest {
            ptb: approve_transaction_data_base64,
            enc_key: eg_keys.1,
            enc_verification_key: eg_keys.2,
            request_signature: key_pair.sign(&request_to_be_signed),
            certificate: Certificate {
                user: sui_sdk_types::Address::from(key_pair_address.to_inner()),
                session_vk: key_pair.public().clone(),
                creation_time,
                ttl_min,
                signature: UserSignature::Simple(SimpleSignature::Ed25519 {
                    signature: sui_sdk_types::Ed25519Signature::from_bytes(
                        &personal_message_signature.signature_bytes(),
                    )
                        .unwrap(),
                    public_key: sui_sdk_types::Ed25519PublicKey::new(
                        personal_message_signature
                            .public_key_bytes()
                            .try_into()
                            .unwrap(),
                    ),
                }),
                mvr_name: None,
            },
        };

        Ok((eg_keys.0, request))
    }

    fn request_to_be_signed(
        &self,
        approve_transaction_data: Vec<u8>,
        enc_key: &ElGamalPublicKey,
        enc_verification_key: &ElgamalVerificationKey,
    ) -> Result<Vec<u8>, SealClientError> {
        let req = RequestFormat {
            ptb: approve_transaction_data,
            enc_key: bcs::to_bytes(enc_key)?,
            enc_verification_key: bcs::to_bytes(enc_verification_key)?,
        };

        Ok(bcs::to_bytes(&req)?)
    }
}

fn unwrap_cache_error(err: Arc<SealClientError>) -> SealClientError {
    Arc::try_unwrap(err)
        .unwrap_or_else(|wrapped_error| {
            SealClientError::CannotUnwrapTypedError {
                error_message: wrapped_error.to_string(),
            }
        })
}
