use crate::client::cache::SealCache;
use crate::client::cache_key::{DerivedKeyCacheKey, KeyServerInfoCacheKey};
use crate::client::error::SealClientError;
use crate::client::generic_types::{BCSSerializableProgrammableTransaction, ObjectID};
use crate::client::http_client::HttpClient;
use crate::client::signer::Signer;
use crate::client::sui_client::SuiClient;
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
use fastcrypto::groups::FromTrustedByteArray;
use futures::future::join_all;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use shared_crypto::intent::{Intent, IntentMessage};
use std::collections::HashMap;
use std::fmt::Display;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use sui_sdk_types::{SimpleSignature, UserSignature};

/// Key server object layout containing object id, name, url, and public key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyServerInfo {
    pub object_id: ObjectID,
    pub name: String,
    pub url: String,
    pub public_key: String,
}

pub type DerivedKeys = (ObjectID, FetchKeyResponse);

#[derive(Clone)]
pub struct BaseSealClient<KeyServerInfoCache, DerivedKeysCache, SuiError, Sui, HttpError, Http>
where
    KeyServerInfoCache: SealCache<Key = KeyServerInfoCacheKey, Value = KeyServerInfo>,
    DerivedKeysCache: SealCache<Key = DerivedKeyCacheKey, Value = Vec<DerivedKeys>>,
    SealClientError: From<SuiError>,
    SuiError: Send + Sync + Display + 'static,
    Sui: SuiClient<Error = SuiError>,
    SealClientError: From<HttpError>,
    Http: HttpClient<PostError = HttpError>,
{
    key_server_info_cache: KeyServerInfoCache,
    derived_key_cache: DerivedKeysCache,
    sui_client: Sui,
    http_client: Http,
}

#[derive(Serialize, Deserialize)]
struct RequestFormat {
    ptb: Vec<u8>,
    enc_key: Vec<u8>,
    enc_verification_key: Vec<u8>,
}

impl<KeyServerInfoCache, DerivedKeysCache, SuiError, Sui, HttpError, Http> BaseSealClient<KeyServerInfoCache, DerivedKeysCache, SuiError, Sui, HttpError, Http>
where
    KeyServerInfoCache: SealCache<Key = KeyServerInfoCacheKey, Value = KeyServerInfo>,
    DerivedKeysCache: SealCache<Key = DerivedKeyCacheKey, Value = Vec<DerivedKeys>>,
    SealClientError: From<SuiError>,
    SuiError: Send + Sync + Display + 'static,
    Sui: SuiClient<Error = SuiError>,
    SealClientError: From<HttpError>,
    Http: HttpClient<PostError = HttpError>,
{
    pub fn new_custom(
        key_server_info_cache: KeyServerInfoCache,
        derived_key_cache: DerivedKeysCache,
        sui_client: Sui,
        http_client: Http
    ) -> Self {
        BaseSealClient {
            key_server_info_cache,
            derived_key_cache,
            sui_client,
            http_client,
        }
    }

    pub async fn encrypt_bytes<ID1, ID2>(
        &mut self,
        package_id: ID1,
        id: Vec<u8>,
        threshold: u8,
        key_servers: Vec<ID2>,
        data: Vec<u8>,
    ) -> Result<EncryptedObject, SealClientError>
    where
        ObjectID: From<ID1>,
        ObjectID: From<ID2>,
    {
        let package_id: ObjectID = package_id.into();
        let key_servers = key_servers
            .into_iter()
            .map(ObjectID::from)
            .collect::<Vec<_>>();

        let key_server_info = self.fetch_key_server_info(key_servers.clone()).await?;
        let public_keys_g2 = key_server_info
            .iter()
            .map(|info| self.decode_public_key(info))
            .collect::<Result<_, _>>()?;

        let public_keys = IBEPublicKeys::BonehFranklinBLS12381(public_keys_g2);

        let key_servers = key_servers
            .into_iter()
            .map(|e| e.into())
            .collect();

        let result = seal_encrypt(
            package_id.0.into(),
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

    pub async fn decrypt_object<T, ID, PTB, Sig>(
        &mut self,
        package_id: ID,
        encrypted_object_data: &[u8],
        approve_transaction_data: PTB,
        signer: Sig
    ) -> Result<T, SealClientError>
    where
        T: DeserializeOwned,
        ObjectID: From<ID>,
        PTB: BCSSerializableProgrammableTransaction,
        Sig: Signer
    {
        let package_id: ObjectID = package_id.into();
        let encrypted_object = bcs::from_bytes::<EncryptedObject>(encrypted_object_data)?;

        let service_ids: Vec<ObjectID> = encrypted_object
            .services
            .iter()
            .map(|(id, _)| ObjectID(id.into_inner()))
            .collect();

        let key_server_info = self.fetch_key_server_info(service_ids).await?;
        let servers_public_keys_map = key_server_info
            .iter()
            .map(|info| {
                Ok::<_, SealClientError>((
                    info.object_id.into(),
                    self.decode_public_key(info)?,
                ))
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .collect::<HashMap<_, _>>();

        let (enc_secret, signed_request) = self.get_signed_request(
            package_id.into(),
            approve_transaction_data.to_bcs_bytes()?,
            signer
        ).await?;

        let derived_keys = self
            .fetch_derived_keys(
                signed_request,
                key_server_info,
                encrypted_object.threshold,
            )
            .await?
            .into_iter()
            .map(|derived_key| (derived_key.0.into(), derived_key.1))
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
                        self.sui_client.get_key_server_info(key_server_id.0)
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
            .map_err(Into::into)
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
                let mut headers = HashMap::new();

                headers.insert("Client-Sdk-Type".to_string(), "rust".to_string());
                headers.insert("Client-Sdk-Version".to_string(), "1.0.0".to_string());
                headers.insert("Content-Type".to_string(), "application/json".to_string());

                let url = format!("{}/v1/fetch_key", server.url);
                let response = self
                    .http_client
                    .post(
                        &url,
                        headers,
                        request_json.clone()
                    )
                    .await?;

                if !response.is_success() {
                    return Err(SealClientError::ErrorWhileFetchingDerivedKeys {
                        url,
                        status: response.status,
                        response: response.text
                    });
                }

                let response: FetchKeyResponse = serde_json::from_str(&response.text)?;

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

    async fn get_signed_request<Sig>(
        &self,
        package_id: sui_sdk_types::ObjectId,
        approve_transaction_data: Vec<u8>,
        mut signer: Sig
    ) -> Result<(ElGamalSecretKey, FetchKeyRequest), SealClientError>
    where
        Sig: Signer
    {
        let eg_keys = genkey(&mut rand::thread_rng());

        let creation_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let ttl_min = 1u16;

        let signer_public_key = signer.get_public_key()?;

        let message_to_sign = signed_message(
            package_id.to_string(),
            &signer_public_key,
            creation_time,
            ttl_min,
        );

        let personal_message = IntentMessage::new(
            Intent::personal_message(),
            message_to_sign.as_bytes().to_vec(),
        );

        let personal_message_signature = signer.sign_personal_message(
            bcs::to_bytes(&personal_message)?
        ).await?;

        let approve_transaction_data_base64 = base64::engine::general_purpose::STANDARD.encode(&approve_transaction_data);

        let request_to_be_signed = self.request_to_be_signed(approve_transaction_data, &eg_keys.1, &eg_keys.2)?;

        let request = FetchKeyRequest {
            ptb: approve_transaction_data_base64,
            enc_key: eg_keys.1,
            enc_verification_key: eg_keys.2,
            request_signature: signer.sign_bytes(request_to_be_signed).await?,
            certificate: Certificate {
                user: signer.get_sui_address()?.into(),
                session_vk: signer_public_key.clone(),
                creation_time,
                ttl_min,
                signature: UserSignature::Simple(SimpleSignature::Ed25519 {
                    signature: sui_sdk_types::Ed25519Signature::from_bytes(
                        &personal_message_signature.sig.to_bytes(),
                    )
                        .unwrap(),
                    public_key: sui_sdk_types::Ed25519PublicKey::new(
                        signer_public_key.0.to_bytes()
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

fn unwrap_cache_error<T>(err: Arc<T>) -> SealClientError
where
    T: Display,
    SealClientError: From<T>
{
    Arc::try_unwrap(err)
        .map(Into::into)
        .unwrap_or_else(|wrapped_error| {
            SealClientError::CannotUnwrapTypedError {
                error_message: wrapped_error.to_string(),
            }
        })
}
