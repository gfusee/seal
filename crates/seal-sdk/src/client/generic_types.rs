use serde::{Deserialize, Serialize};
use crate::client::error::SealClientError;

#[derive(PartialEq, Eq, Hash, Debug, Copy, Clone, Serialize, Deserialize)]
pub struct ObjectID(pub [u8; 32]);

impl<T> From<T> for ObjectID
where
    [u8; 32]: From<T>
{
    fn from(value: T) -> Self {
        Self(value.into())
    }
}

impl From<ObjectID> for sui_sdk_types::ObjectId {
    fn from(value: ObjectID) -> Self {
        Self::new(value.0)
    }
}

#[cfg(feature = "native-sui-sdk")]
impl From<ObjectID> for sui_sdk::types::base_types::ObjectID {
    fn from(value: ObjectID) -> Self {
        Self::new(value.0)
    }
}

#[derive(PartialEq, Eq, Hash, Debug, Copy, Clone, Serialize, Deserialize)]
pub struct SuiAddress(pub [u8; 32]);

impl<T> From<T> for SuiAddress
where
    [u8; 32]: From<T>
{
    fn from(value: T) -> Self {
        Self(value.into())
    }
}

impl From<SuiAddress> for sui_sdk_types::Address {
    fn from(value: SuiAddress) -> Self {
        Self::new(value.0)
    }
}

#[cfg(feature = "native-sui-sdk")]
impl From<SuiAddress> for sui_sdk::types::base_types::SuiAddress {
    fn from(value: SuiAddress) -> Self {
        Self::from(sui_sdk::types::base_types::ObjectID::new(value.0))
    }
}

pub trait BCSSerializableProgrammableTransaction {
    fn to_bcs_bytes(&self) -> Result<Vec<u8>, SealClientError>;
}

#[cfg(feature = "native-sui-sdk")]
impl BCSSerializableProgrammableTransaction for sui_sdk::types::transaction::ProgrammableTransaction {
    fn to_bcs_bytes(&self) -> Result<Vec<u8>, SealClientError> {
        Ok(bcs::to_bytes(self)?)
    }
}