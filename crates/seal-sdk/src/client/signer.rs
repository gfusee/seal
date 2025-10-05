use crate::client::error::SealClientError;
use crate::client::generic_types::SuiAddress;
use async_trait::async_trait;
use fastcrypto::ed25519::{Ed25519PublicKey, Ed25519Signature};

#[async_trait]
pub trait Signer {
    async fn sign_personal_message(
        &mut self,
        message: Vec<u8>
    ) -> Result<Ed25519Signature, SealClientError>;

    async fn sign_bytes(
        &mut self,
        bytes: Vec<u8>
    ) -> Result<Ed25519Signature, SealClientError>;

    fn get_public_key(&mut self) -> Result<Ed25519PublicKey, SealClientError>;

    fn get_sui_address(&mut self) -> Result<SuiAddress, SealClientError> {
        Ok(SuiAddress([0; 32]))
    }
}