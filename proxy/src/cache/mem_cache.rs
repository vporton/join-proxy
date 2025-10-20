use super::lockable_map::{AbstractLockableMap, LockableHashMap, MutexGuard};
use std::collections::BTreeMap;
use std::hash::Hash;
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use tokio::sync::Mutex;

use crate::{cache::cache::Cache, errors::MyResult};

pub struct MemCache<K, V> {
    data: LockableHashMap<K, V>, // TODO: Use `dashmap` crate instead?
    put_times: Mutex<BTreeMap<SystemTime, Vec<K>>>,
    keep_duration: Duration,
}

impl<K, V> MemCache<K, V> {
    pub fn new(keep_duration: Duration) -> Self {
        Self {
            data: LockableHashMap::new(),
            put_times: Mutex::new(BTreeMap::new()),
            keep_duration,
        }
    }
}

#[async_trait]
impl<K, V> Cache<K, V> for MemCache<K, V>
where
    // TODO: superfluous conditions?
    K: Clone + Hash + std::cmp::Eq + std::marker::Sync + std::marker::Send,
    V: std::marker::Send,
{
    async fn lock<'a>(&'a mut self, key: &K) -> MyResult<Box<dyn MutexGuard<Option<V>> + 'a>>
    where
        V: 'a,
    {
        // Remove expired entries.
        let time_threshold = SystemTime::now() - self.keep_duration;

        let mut put_times = self.put_times.lock().await; // a short-time lock
        while let Some(kv) = put_times.first_key_value() {
            if *kv.0 < time_threshold {
                for kv2 in kv.1 {
                    self.data.remove(kv2).await;
                }
                put_times.pop_first();
            }
        }

        let data = self.data.lock(key).await;
        Ok(Box::new(data))
    }
}

pub type BinaryMemCache = MemCache<Vec<u8>, Vec<u8>>;
