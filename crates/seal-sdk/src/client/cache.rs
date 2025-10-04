use std::collections::HashMap;
use std::sync::Arc;
use core::future::Future;
use std::hash::Hash;
use std::marker::PhantomData;
use async_trait::async_trait;
use tokio::sync::Mutex;

#[async_trait]
pub trait SealCache: Send + Sync {
    type Key;
    type Value;

    async fn try_get_with<Fut, Error>(&self, key: Self::Key, init: Fut) -> Result<Self::Value, Arc<Error>>
    where
        Fut: Future<Output = Result<Self::Value, Error>> + Send,
        Error: Send + Sync + 'static;
}

pub struct NoCache<Key, Value> {
    _phantom_key: PhantomData<Key>,
    _phantom_value: PhantomData<Value>,
}

impl<Key, Value> From<()> for NoCache<Key, Value> {
    fn from(_: ()) -> Self {
        Self {
            _phantom_key: PhantomData,
            _phantom_value: PhantomData,
        }
    }
}

#[async_trait]
impl<Key: Send + Sync, Value: Send + Sync> SealCache for NoCache<Key, Value> {
    type Key = Key;
    type Value = Value;

    async fn try_get_with<Fut, Error>(&self, _key: Self::Key, init: Fut) -> Result<Self::Value, Arc<Error>>
    where
        Fut: Future<Output=Result<Self::Value, Error>> + Send,
        Error: Send + Sync + 'static
    {
        init.await.map_err(Arc::new)
    }
}

#[async_trait]
impl<Key, Value> SealCache for Arc<Mutex<HashMap<Key, Value>>>
where
    Key: Eq + Hash + Send,
    Value: Clone + Send,
{
    type Key = Key;
    type Value = Value;

    async fn try_get_with<Fut, Error>(&self, key: Self::Key, init: Fut) -> Result<Self::Value, Arc<Error>>
    where
        Fut: Future<Output = Result<Self::Value, Error>> + Send,
        Error: Send + Sync + 'static,
    {
        let cached_value = {
            let cache = self.lock().await;
            cache.get(&key).cloned()
        };
        
        if let Some(value) = cached_value {
            Ok(value.clone())
        } else {
            let value = init.await;

            match value {
                Ok(value) => {
                    {
                        let mut cache = self.lock().await;
                        cache.insert(key, value.clone());
                    }

                    Ok(value)
                },
                Err(err) => {
                    Err(Arc::new(err))
                }
            }
        }
    }
}