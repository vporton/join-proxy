use async_trait::async_trait;

use super::lockable_map::MutexGuard;
use crate::errors::MyResult;

#[async_trait]
pub trait Cache<K, V>: Sync + Send {
    // type Guard<'a>: MutexGuard<Option<V>> where Self: 'a, V: 'a;

    // async fn lock<'a>(&'a mut self, key: &K) -> MyResult<Self::Guard<'a>> where V: 'a;
    async fn lock<'a>(&'a mut self, key: &K) -> MyResult<Box<dyn MutexGuard<Option<V>> + 'a>>
    where
        V: 'a;

    // async fn put(&mut self, key: K, value: V) -> MyResult<()>;
}

pub type BinaryCache = dyn Cache<Vec<u8>, Vec<u8>>;
