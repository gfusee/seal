use serde::{Deserialize, Serialize};
use crate::client::error::SealClientError;

#[derive(PartialEq, Eq, Hash, Debug, Copy, Clone, Serialize, Deserialize)]
pub struct ObjectID(pub [u8; 32]);

#[derive(PartialEq, Eq, Hash, Debug, Copy, Clone, Serialize, Deserialize)]
pub struct SuiAddress(pub [u8; 32]);

pub trait BCSSerializableProgrammableTransaction {
    fn to_bcs_bytes(&self) -> Result<Vec<u8>, SealClientError>;
}

#[cfg(feature = "sui_sdk")]
impl BCSSerializableProgrammableTransaction for sui_sdk::types::transaction::ProgrammableTransaction {
    fn to_bcs_bytes(&self) -> Result<Vec<u8>, SealClientError> {
        Ok(bcs::to_bytes(self)?)
    }
}