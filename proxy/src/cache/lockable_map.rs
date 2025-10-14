use std::collections::HashMap;
use std::ops::{Deref, DerefMut};

use async_trait::async_trait;

#[async_trait]
pub trait MutexGuard<T>: Deref<Target = T> /*+ DerefMut<Target = T>*/ {
    async fn set(&mut self, value: T);
    async fn inner(&self) -> T where T: Sized + Clone + std::marker::Sync; // TODO: `Clone` is bad.
}

#[async_trait]
impl<T> MutexGuard<T> for tokio::sync::MutexGuard<'_, T>
    where T: std::marker::Send
{
    async fn set(&mut self, value: T) {
        *self.deref_mut() = value;
    }

    async fn inner(&self) -> T where T: Sized + Clone + std::marker::Sync
    {
        (*self.deref()).clone()
    }
}

pub trait AbstractLockableMap<K, V> {
    type Guard<'a>: MutexGuard<Option<V>> where Self: 'a;

    async fn lock(&mut self, key: &K) -> Self::Guard<'_>;

    async fn remove(&mut self, key: &K);
}

pub struct LockableHashMap<K, V> {
    map: HashMap<K, tokio::sync::Mutex<Option<V>>>,
}

impl<K, V> LockableHashMap<K, V> {
    pub fn new() -> Self {
        Self { map: HashMap::new() }
    }
}

// Code based on https://g.co/gemini/share/5045754c1381
impl<K, V> AbstractLockableMap<K, V> for LockableHashMap<K, V> 
where
    K: std::hash::Hash + Eq + Clone, // TODO: Is `Clone` needed?
    V: std::marker::Send, // TODO: It is an over-specification.
{
    type Guard<'a> = tokio::sync::MutexGuard<'a, Option<V>> where K: 'a, V: 'a;

    async fn lock(&'_ mut self, key: &K) -> tokio::sync::MutexGuard<'_, Option<V>> {
        self.map.entry(key.clone())
            .or_insert_with(|| tokio::sync::Mutex::new(None))
            .lock()
            .await
    }

    async fn remove(&mut self, key: &K) {
        self.map.remove(key);
    }
}
