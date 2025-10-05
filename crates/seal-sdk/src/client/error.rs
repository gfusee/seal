use fastcrypto::error::FastCryptoError;
use http::header::{InvalidHeaderName, InvalidHeaderValue};
use sui_types::base_types::ObjectID;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SealClientError {
    #[error("Cannot unwrap typed error: {error_message}")]
    CannotUnwrapTypedError { error_message: String },

    #[error("FastCrypto error: {0}")]
    FastCrypto(#[from] FastCryptoError),

    #[error("BCS serialization error: {0}")]
    BCSSerialization(#[from] bcs::Error),

    #[error("JSON serialization error: {0}")]
    JSONSerialization(#[from] serde_json::Error),

    #[error("HEX deserialization error: {0}")]
    JSONDeserialization(#[from] hex::FromHexError),

    #[cfg(feature = "reqwest")]
    #[error("Reqwest error: {0}")]
    Reqwest(#[from] ReqwestError),

    #[error("Sui SDK error: {0}")]
    SuiSdk(#[from] sui_sdk::error::Error),

    #[error("Error while fetching derived keys from {url}: HTTP {status} - {response}")]
    ErrorWhileFetchingDerivedKeys {
        url: String,
        status: u16,
        response: String,
    },

    #[error("Insufficient keys: received {received}, but threshold is {threshold}")]
    InsufficientKeys { received: usize, threshold: u8 },

    #[error("Missing decrypted object")]
    MissingDecryptedObject,

    #[error("No object data from the Sui RPC for object {object_id}")]
    NoObjectDataFromTheSuiRPC { object_id: ObjectID },

    #[error("Invalid object data from the Sui RPC for object {object_id}")]
    InvalidObjectDataFromTheSuiRPC { object_id: ObjectID },

    #[error("Missing key server field: {field_name}")]
    MissingKeyServerField { field_name: String },

    #[error("Invalid dynamic fields type from key server for object {object_id}")]
    InvalidKeyServerDynamicFieldsType { object_id: ObjectID },

    #[error("Invalid public key {public_key}: {reason}")]
    InvalidPublicKey { public_key: String, reason: String },

    #[error("Cannot sign personal message")]
    CannotSignPersonalMessage { message: String },
}

#[cfg(feature = "reqwest")]
#[derive(Debug, Error)]
pub enum ReqwestError {
    #[error("A reqwest error occurred: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("Unable to convert http headers: InvalidHeaderValue")]
    InvalidHeaderValue(#[from] InvalidHeaderValue),
    #[error("Unable to convert http headers: InvalidHeaderName")]
    InvalidHeaderName(#[from] InvalidHeaderName),
}