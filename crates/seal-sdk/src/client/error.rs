use fastcrypto::error::FastCryptoError;
use http::header::{InvalidHeaderName, InvalidHeaderValue};
use sui_types::signature;
use thiserror::Error;
use crate::client::native_sui_sdk::client::sui_client::SuiClientError;

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

    #[cfg(all(feature = "client", feature = "native-sui-sdk"))]
    #[error("Sui client error: {0}")]
    SuiClient(#[from] SuiClientError),

    #[cfg(feature = "reqwest")]
    #[error("Reqwest error: {0}")]
    Reqwest(#[from] ReqwestError),

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

    #[error("Invalid public key {public_key}: {reason}")]
    InvalidPublicKey { public_key: String, reason: String },

    #[error("Signature error: {message}")]
    SignatureError { message: String },

    #[error("Unknown error: {0}")]
    UnknownError(#[from] anyhow::Error),
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