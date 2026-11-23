//! Reuse a successful authentication for a short time. Feature `cache`.
//!
//! Verifying a JWT costs tens of microseconds of signature arithmetic, and a Kubernetes token
//! costs a `TokenReview` request to the API server. Clients send the same token for most of
//! its lifetime. [`CachedAuthenticator`] wraps any [`Authenticator`] and answers a token it
//! verified less than `time_to_live` ago from memory.
//!
//! ```
//! use std::time::Duration;
//! use limes::Authenticator;
//! use limes::cache::{CacheConfig, CachedAuthenticator};
//!
//! fn with_cache<A: Authenticator>(authenticator: A) -> CachedAuthenticator<A> {
//!     let config = CacheConfig::builder()
//!         .time_to_live(Duration::from_secs(30))
//!         .build();
//!     CachedAuthenticator::new(authenticator, config)
//! }
//! ```
//!
//! # What a cached answer means
//!
//! A cached authentication is returned only while a fresh verification of the same token
//! would still accept it, with one exception: a change the authenticator learns from outside
//! the token reaches tokens in the cache up to `time_to_live` later, in each process. Such
//! changes are a key removed from the JWKS, a deleted Kubernetes service account or pod, the
//! expiry of a token that is no JWT, such as a Kubernetes bootstrap token, or a revoked API key
//! of an authenticator of your own.
//!
//! - An entry ends `time_to_live` after its verification started, or when the token stops
//!   being valid ([`Authentication::valid_until`]), whichever is earlier. The JWKS authenticator
//!   and, for service account tokens, the Kubernetes API server accept a token up to 60 seconds
//!   after its `exp`, to allow for clock differences; the cache returns no entry after `exp`.
//! - The cache checks both the monotonic clock and the system clock. If the system clock jumps
//!   forward, or the machine was suspended, entries end on time. If the system clock moves
//!   backwards, entries end early.
//! - Only successes are stored. A rejected token is verified again on the next request.
//! - Requests that arrive with the same token before its first verification finished each
//!   verify it, as without a cache.
//!
//! Do not wrap an authenticator of single-use tokens, or one that counts the uses of a token:
//! a cached answer does not call it.
//!
//! # Memory
//!
//! The cache is keyed by an HMAC-SHA-256 of the whole token, under a random key per cache.
//! It never holds the token itself. It does hold each [`Authentication`], which carries the
//! claims of the token, until a newer entry takes its place or
//! [`remove_expired`](CachedAuthenticator::remove_expired) removes it. Call `remove_expired`
//! periodically, for example when you export [`stats`](CachedAuthenticator::stats), so the
//! claims of expired tokens do not stay in memory.
//!
//! `max_bytes` bounds an estimate of the memory the entries hold. Plan for about 20 % more:
//! the estimate leaves out the index of the cache and runs a little low. An authentication from a
//! Kubernetes token takes about 2 KB, one from a typical OpenID Connect token about 5 to 6 KB,
//! and one from a Microsoft Entra ID token with 200 groups 20 to 30 KB. Once the cache is full,
//! a new entry waits in a small part of it, and only an entry that is used again there moves
//! on to the main part. So a flood of tokens that are used once does not push out the tokens
//! clients keep sending.
//!
//! [`stats`](CachedAuthenticator::stats) reports hits, misses, evictions and size, for example
//! to export them as metrics.

use std::{
    fmt,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering::Relaxed},
    },
    time::{Duration, SystemTime},
};

use aws_lc_rs::hmac;
use tokio::time::Instant;
use typed_builder::TypedBuilder;

use crate::{Authentication, Authenticator, Identity, Token, error::Result};

/// The smallest part of `max_bytes` one shard of the store holds, so that large entries fit.
const MIN_SHARD_BYTES: u64 = 1024 * 1024;
const MAX_SHARDS: usize = 64;
/// The size of a typical entry, to size the index of the store.
const TYPICAL_ENTRY_BYTES: u64 = 4 * 1024;

type Digest = [u8; 32];
type Store = quick_cache::sync::Cache<
    Digest,
    Entry,
    EntryWeight,
    quick_cache::DefaultHashBuilder,
    Evictions,
>;

/// The bounds of a [`CachedAuthenticator`]. Build it with
/// `CacheConfig::builder().time_to_live(..).build()`; `max_bytes` is 64 MiB by default.
///
/// `time_to_live` is the longest delay before a change the authenticator learns from outside
/// the token reaches cached tokens. While a client keeps using a token, each process verifies
/// it about once per `time_to_live`. 30 seconds is a good start.
#[derive(Debug, Clone, TypedBuilder)]
pub struct CacheConfig {
    /// How long one verification is reused, at most. An entry also ends when its token stops
    /// being valid. Zero turns the cache off.
    time_to_live: Duration,
    /// The memory the cached authentications may hold, estimated, in bytes. 64 MiB by
    /// default.
    #[builder(default = 64 * 1024 * 1024)]
    max_bytes: u64,
}

/// An [`Authenticator`] that reuses a successful authentication of the same token for up to
/// `time_to_live`. See the [module documentation](self) for what a cached answer means.
///
/// Clones share one cache. Two `CachedAuthenticator`s created with [`new`](Self::new) share
/// nothing. [`can_handle_token`](Authenticator::can_handle_token),
/// [`idp_id`](Authenticator::idp_id) and [`idp_ids`](Authenticator::idp_ids) are those of the
/// wrapped authenticator.
pub struct CachedAuthenticator<A> {
    shared: Arc<Shared<A>>,
}

struct Shared<A> {
    inner: A,
    config: CacheConfig,
    hmac_key: hmac::Key,
    store: Store,
    counters: Arc<Counters>,
}

/// What a [`CachedAuthenticator`] did since it was created, and its size now.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct CacheStats {
    /// Requests answered from the cache.
    pub hits: u64,
    /// Requests the wrapped authenticator answered.
    pub misses: u64,
    /// Entries removed to make room while they were still valid. If this keeps rising,
    /// `max_bytes` is too small. Most entries of tokens that were used only once leave without
    /// being counted.
    pub evicted: u64,
    /// The entries in the cache, also those that ended and were not removed yet.
    pub entries: u64,
    /// The estimated memory of the entries, in bytes.
    pub bytes: u64,
}

#[derive(Debug, Default)]
struct Counters {
    hits: AtomicU64,
    misses: AtomicU64,
    evicted: AtomicU64,
}

#[derive(Clone)]
struct Entry {
    authentication: Authentication,
    /// When the verification started, on the monotonic clock and on the system clock.
    verified_at: Instant,
    verified_at_system: SystemTime,
    weight: u64,
}

impl Entry {
    fn is_valid(&self, time_to_live: Duration, now: Instant, now_system: SystemTime) -> bool {
        now.saturating_duration_since(self.verified_at) < time_to_live
            // A system clock that moved backwards ends the entry early.
            && now_system
                .duration_since(self.verified_at_system)
                .is_ok_and(|age| age < time_to_live)
            && self
                .authentication
                .valid_until()
                .is_none_or(|valid_until| now_system < valid_until)
    }

    /// Whether the entry ended at the time `now_system` was read. An entry whose verification
    /// started later is fresh: a request stored it while the caller looked at the store.
    fn has_ended(&self, time_to_live: Duration, now: Instant, now_system: SystemTime) -> bool {
        self.verified_at_system <= now_system && !self.is_valid(time_to_live, now, now_system)
    }
}

#[derive(Debug, Clone)]
struct EntryWeight;

impl quick_cache::Weighter<Digest, Entry> for EntryWeight {
    fn weight(&self, _: &Digest, entry: &Entry) -> u64 {
        entry.weight
    }
}

/// Counts the entries evicted from the main ("hot") part of the store while still valid.
/// Entries that leave from the part for new entries ("cold"), entries too large to store, and
/// entries replaced by a newer entry of the same token are not counted.
#[derive(Debug, Clone)]
struct Evictions {
    time_to_live: Duration,
    counters: Arc<Counters>,
}

/// What one insert into the store removed. Dropped after the store released its lock, so the
/// removed entries are freed outside it.
#[derive(Default)]
struct Removed {
    /// The key the insert stores. quick_cache reports the entry it replaces as evicted.
    inserted: Option<Digest>,
    entries: Vec<Entry>,
}

impl quick_cache::Lifecycle<Digest, Entry> for Evictions {
    type RequestState = Removed;

    fn on_evict(&self, removed: &mut Removed, _: Digest, entry: Entry) {
        removed.entries.push(entry);
    }

    fn on_evict_hot(&self, removed: &mut Removed, key: Digest, entry: Entry) {
        if removed.inserted != Some(key)
            && entry.is_valid(self.time_to_live, Instant::now(), SystemTime::now())
        {
            self.counters.evicted.fetch_add(1, Relaxed);
        }
        removed.entries.push(entry);
    }
}

impl<A: Authenticator> CachedAuthenticator<A> {
    /// Wrap `authenticator` in a new, empty cache.
    ///
    /// # Panics
    /// If the operating system provides no random numbers for the key of the cache.
    #[must_use]
    pub fn new(authenticator: A, config: CacheConfig) -> Self {
        let counters = Arc::new(Counters::default());
        let shards = usize::try_from(config.max_bytes / MIN_SHARD_BYTES)
            .unwrap_or(usize::MAX)
            .clamp(1, MAX_SHARDS);
        let options = quick_cache::OptionsBuilder::new()
            // A power of two, so that every shard holds at least `MIN_SHARD_BYTES`.
            .shards(1 << shards.ilog2())
            .estimated_items_capacity(
                usize::try_from(config.max_bytes / TYPICAL_ENTRY_BYTES)
                    .unwrap_or(usize::MAX)
                    .max(1),
            )
            .weight_capacity(config.max_bytes)
            .build()
            .expect("every required option is set");
        let store = Store::with_options(
            options,
            EntryWeight,
            quick_cache::DefaultHashBuilder::default(),
            Evictions {
                time_to_live: config.time_to_live,
                counters: Arc::clone(&counters),
            },
        );
        let hmac_key =
            hmac::Key::generate(hmac::HMAC_SHA256, &aws_lc_rs::rand::SystemRandom::new())
                .expect("the operating system provides random numbers");
        Self {
            shared: Arc::new(Shared {
                inner: authenticator,
                config,
                hmac_key,
                store,
                counters,
            }),
        }
    }
}

impl<A> CachedAuthenticator<A> {
    /// The wrapped authenticator. Read-only, because the entries hold results of exactly
    /// this configuration.
    #[must_use]
    pub fn inner(&self) -> &A {
        &self.shared.inner
    }

    /// What this cache did since it was created, and its size now.
    #[must_use]
    pub fn stats(&self) -> CacheStats {
        let shared = &self.shared;
        let counters = &shared.counters;
        CacheStats {
            hits: counters.hits.load(Relaxed),
            misses: counters.misses.load(Relaxed),
            evicted: counters.evicted.load(Relaxed),
            entries: u64::try_from(shared.store.len()).unwrap_or(u64::MAX),
            bytes: shared.store.weight(),
        }
    }

    /// Remove the entries that ended. Call it periodically, for example every few seconds when
    /// you export [`stats`](Self::stats): a cache keeps an entry that ended until a newer entry
    /// takes its place, and the entries hold the claims of the tokens.
    pub fn remove_expired(&self) {
        let (now, now_system) = (Instant::now(), SystemTime::now());
        let time_to_live = self.shared.config.time_to_live;
        self.shared
            .store
            .retain(|_, entry| !entry.has_ended(time_to_live, now, now_system));
    }
}

impl<A> Clone for CachedAuthenticator<A> {
    fn clone(&self) -> Self {
        Self {
            shared: Arc::clone(&self.shared),
        }
    }
}

impl<A: fmt::Debug> fmt::Debug for CachedAuthenticator<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CachedAuthenticator")
            .field("inner", &self.shared.inner)
            .field("config", &self.shared.config)
            .finish_non_exhaustive()
    }
}

impl<A: Authenticator> Authenticator for CachedAuthenticator<A> {
    async fn authenticate(&self, token: &Token<'_>) -> Result<Authentication> {
        let shared = &self.shared;
        if shared.config.time_to_live.is_zero() {
            return shared.inner.authenticate(token).await;
        }
        let key = shared.digest(token.as_str());
        if let Some(authentication) = shared.lookup(&key) {
            shared.counters.hits.fetch_add(1, Relaxed);
            return Ok(authentication);
        }
        shared.counters.misses.fetch_add(1, Relaxed);
        let started = (Instant::now(), SystemTime::now());
        let authentication = shared.inner.authenticate(token).await?;
        shared.store(key, &authentication, started);
        Ok(authentication)
    }

    fn can_handle_token(&self, token: &Token<'_>) -> bool {
        self.shared.inner.can_handle_token(token)
    }

    fn idp_id(&self) -> Option<&str> {
        self.shared.inner.idp_id()
    }

    fn idp_ids(&self) -> Vec<Option<&str>> {
        self.shared.inner.idp_ids()
    }
}

impl<A> Shared<A> {
    fn digest(&self, token: &str) -> Digest {
        let tag = hmac::sign(&self.hmac_key, token.as_bytes());
        let mut digest = Digest::default();
        digest.copy_from_slice(tag.as_ref());
        digest
    }

    fn lookup(&self, key: &Digest) -> Option<Authentication> {
        let entry = self.store.get(key)?;
        let (now, now_system) = (Instant::now(), SystemTime::now());
        let time_to_live = self.config.time_to_live;
        if entry.is_valid(time_to_live, now, now_system) {
            return Some(entry.authentication);
        }
        self.store
            .remove_if(key, |entry| entry.has_ended(time_to_live, now, now_system));
        None
    }

    fn store(&self, key: Digest, authentication: &Authentication, started: (Instant, SystemTime)) {
        let (verified_at, verified_at_system) = started;
        let entry = Entry {
            authentication: authentication.clone(),
            verified_at,
            verified_at_system,
            weight: weight(authentication),
        };
        // Ended already: verified within the leeway that verifiers allow after `exp`, or the
        // verification took longer than `time_to_live`.
        if !entry.is_valid(self.config.time_to_live, Instant::now(), SystemTime::now()) {
            return;
        }
        let mut removed = Removed {
            inserted: Some(key),
            ..Removed::default()
        };
        self.store.insert_with_lifecycle(key, entry, &mut removed);
    }
}

const VALUE: usize = size_of::<serde_json::Value>();
const STRING: usize = size_of::<String>();
/// Per member of a JSON object, beyond the memory of its key and value: the slot, with about
/// 40 % for the unused room of a `BTreeMap` node or the growth of an `IndexMap`.
const MEMBER: usize = (STRING + VALUE + 8) * 7 / 5;
/// Per JSON object: its first `BTreeMap` node or `IndexMap` table.
const OBJECT: usize = 400;
/// Per entry: the slot and the index of the store, and the key.
const ENTRY: usize = size_of::<Entry>() + size_of::<Digest>() + 64;

/// The estimated memory an entry holds, in bytes. Within about 15 % of what an allocator counts
/// for the authentications of Kubernetes, Keycloak and Entra ID tokens, mostly below, which the
/// test `cache_weight` checks. Saturates, so it never panics.
fn weight(authentication: &Authentication) -> u64 {
    let mut weight = Weight(0);
    weight.add(ENTRY);
    let subject = authentication.subject();
    weight.add(subject.subject_in_idp().len());
    weight.add(subject.idp_id().map_or(0, str::len));
    for audience in authentication.audiences() {
        weight.add(STRING + 16);
        weight.add(audience.capacity());
    }
    match authentication.identity() {
        Identity::Claims(claims) => {
            // The `Arc` of the claims and its counters.
            weight.add(16 + VALUE);
            weight.add_json(claims.as_json());
        }
        Identity::Kubernetes(user) => {
            weight.add(user.username().map_or(0, str::len));
            weight.add(user.uid().map_or(0, str::len));
            for group in user.groups() {
                weight.add(STRING);
                weight.add(group.capacity());
            }
            // A `BTreeMap` node holds up to 11 entries.
            let extra = user.extra();
            weight.add_n(extra.len().div_ceil(11), 11 * 2 * STRING + 16);
            for (key, values) in extra {
                weight.add(key.capacity());
                for value in values {
                    weight.add(STRING);
                    weight.add(value.capacity());
                }
            }
        }
    }
    weight.0
}

struct Weight(u64);

impl Weight {
    fn add(&mut self, bytes: usize) {
        self.0 = self
            .0
            .saturating_add(u64::try_from(bytes).unwrap_or(u64::MAX));
    }

    fn add_n(&mut self, count: usize, bytes: usize) {
        self.add(count.saturating_mul(bytes));
    }

    fn add_json(&mut self, root: &serde_json::Value) {
        let mut pending = vec![root];
        while let Some(value) = pending.pop() {
            match value {
                serde_json::Value::String(string) => self.add(string.capacity()),
                serde_json::Value::Array(items) => {
                    self.add_n(items.capacity(), VALUE);
                    pending.extend(items);
                }
                serde_json::Value::Object(members) => {
                    self.add(OBJECT);
                    for (key, value) in members {
                        self.add(MEMBER);
                        self.add(key.capacity());
                        pending.push(value);
                    }
                }
                serde_json::Value::Null
                | serde_json::Value::Bool(_)
                | serde_json::Value::Number(_) => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};

    use super::*;
    use crate::{
        AuthenticatorChain, Subject, VerifiedClaims,
        error::{Error, RejectionReason},
    };

    const TTL: Duration = Duration::from_secs(30);

    /// An authenticator that counts its calls and accepts every token, after `delay`.
    #[derive(Clone, Default)]
    struct Fake {
        calls: Arc<AtomicUsize>,
        delay: Duration,
        valid_until: Option<SystemTime>,
        rejects: bool,
        claims: Option<serde_json::Value>,
    }

    impl Fake {
        fn calls(&self) -> usize {
            self.calls.load(SeqCst)
        }
    }

    impl Authenticator for Fake {
        async fn authenticate(&self, token: &Token<'_>) -> Result<Authentication> {
            self.calls.fetch_add(1, SeqCst);
            // `sleep` waits for the next tick of the timer, also for zero.
            if !self.delay.is_zero() {
                tokio::time::sleep(self.delay).await;
            }
            if self.rejects {
                return Err(Error::rejected(RejectionReason::Expired));
            }
            let claims = self.claims.clone().unwrap_or_else(|| serde_json::json!({}));
            Ok(Authentication::builder()
                .subject(Subject::new(Some("fake".into()), token.as_str().into()))
                .identity(VerifiedClaims::try_from(claims).unwrap())
                .valid_until_opt(self.valid_until)
                .build())
        }

        fn can_handle_token(&self, token: &Token<'_>) -> bool {
            token.as_str().starts_with("handled")
        }

        fn idp_id(&self) -> Option<&str> {
            Some("fake")
        }
    }

    fn cached(fake: &Fake) -> CachedAuthenticator<Fake> {
        CachedAuthenticator::new(
            fake.clone(),
            CacheConfig::builder().time_to_live(TTL).build(),
        )
    }

    fn small(fake: &Fake) -> CachedAuthenticator<Fake> {
        CachedAuthenticator::new(
            fake.clone(),
            CacheConfig::builder()
                .time_to_live(TTL)
                .max_bytes(256 * 1024)
                .build(),
        )
    }

    async fn auth(cache: &CachedAuthenticator<Fake>, token: &str) -> Result<Authentication> {
        cache.authenticate(&Token::new(token)).await
    }

    #[tokio::test]
    async fn test_a_hit_does_not_call_the_authenticator() {
        let fake = Fake::default();
        let cache = cached(&fake);
        let first = auth(&cache, "token").await.unwrap();
        let second = auth(&cache, "token").await.unwrap();
        assert_eq!(first, second);
        assert_eq!(fake.calls(), 1);
        let stats = cache.stats();
        assert_eq!((stats.hits, stats.misses, stats.entries), (1, 1, 1));
    }

    #[tokio::test]
    async fn test_tokens_one_byte_apart_are_separate_entries() {
        let fake = Fake::default();
        let cache = cached(&fake);
        let a = auth(&cache, "token-a").await.unwrap();
        let b = auth(&cache, "token-b").await.unwrap();
        assert_eq!(a.subject().subject_in_idp(), "token-a");
        assert_eq!(b.subject().subject_in_idp(), "token-b");
        assert_eq!(fake.calls(), 2);
    }

    #[tokio::test]
    async fn test_clones_share_the_cache_and_new_caches_share_nothing() {
        let fake = Fake::default();
        let cache = cached(&fake);
        auth(&cache, "token").await.unwrap();
        auth(&cache.clone(), "token").await.unwrap();
        assert_eq!(fake.calls(), 1);
        auth(&cached(&fake), "token").await.unwrap();
        assert_eq!(fake.calls(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn test_an_entry_ends_after_the_time_to_live() {
        let fake = Fake {
            delay: Duration::from_secs(1),
            ..Fake::default()
        };
        let cache = cached(&fake);
        auth(&cache, "token").await.unwrap();
        // The time to live starts when the verification starts, 1 s before it ends.
        tokio::time::advance(Duration::from_secs(28)).await;
        auth(&cache, "token").await.unwrap();
        assert_eq!(fake.calls(), 1);
        tokio::time::advance(Duration::from_secs(1)).await;
        auth(&cache, "token").await.unwrap();
        assert_eq!(fake.calls(), 2);
    }

    fn entry(verified_at_system: SystemTime, valid_until: Option<SystemTime>) -> Entry {
        let authentication = Authentication::builder()
            .subject(Subject::new(None, "sub".into()))
            .identity(VerifiedClaims::default())
            .valid_until_opt(valid_until)
            .build();
        Entry {
            weight: weight(&authentication),
            authentication,
            verified_at: Instant::now(),
            verified_at_system,
        }
    }

    fn at(seconds: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(seconds)
    }

    #[test]
    fn test_an_entry_ends_when_its_token_stops_being_valid() {
        let entry = entry(at(100), Some(at(105)));
        let now = Instant::now();
        assert!(entry.is_valid(TTL, now, at(104)));
        assert!(!entry.is_valid(TTL, now, at(105)));
    }

    /// A suspended machine or a forward step of the system clock: the monotonic clock did not
    /// advance, the system clock did.
    #[test]
    fn test_the_system_clock_ends_an_entry_the_monotonic_clock_would_keep() {
        let entry = entry(at(100), None);
        let now = Instant::now();
        assert!(entry.is_valid(TTL, now, at(129)));
        assert!(!entry.is_valid(TTL, now, at(130)));
    }

    #[test]
    fn test_the_monotonic_clock_ends_an_entry_the_system_clock_would_keep() {
        let entry = entry(at(100), None);
        assert!(!entry.is_valid(TTL, entry.verified_at + TTL, at(100)));
    }

    #[test]
    fn test_a_backward_step_of_the_system_clock_ends_an_entry() {
        let entry = entry(at(100), None);
        assert!(!entry.is_valid(TTL, Instant::now(), at(99)));
    }

    /// Removing ended entries reads the clocks once. An entry stored after that is fresh.
    #[test]
    fn test_an_entry_verified_after_the_clocks_were_read_has_not_ended() {
        let entry = entry(at(100), None);
        let now = Instant::now();
        assert!(!entry.has_ended(TTL, now, at(99)));
        assert!(!entry.has_ended(TTL, now, at(129)));
        assert!(entry.has_ended(TTL, now, at(130)));
    }

    #[tokio::test]
    async fn test_a_token_verified_after_it_stopped_being_valid_is_returned_but_not_stored() {
        // Verifiers accept a token for a while after `exp`.
        let fake = Fake {
            valid_until: SystemTime::now().checked_sub(Duration::from_secs(10)),
            ..Fake::default()
        };
        let cache = cached(&fake);
        auth(&cache, "token").await.unwrap();
        auth(&cache, "token").await.unwrap();
        assert_eq!(fake.calls(), 2);
        assert_eq!(cache.stats().entries, 0);
    }

    #[tokio::test]
    async fn test_failures_are_not_stored() {
        let fake = Fake {
            rejects: true,
            ..Fake::default()
        };
        let cache = cached(&fake);
        auth(&cache, "token").await.unwrap_err();
        auth(&cache, "token").await.unwrap_err();
        assert_eq!(fake.calls(), 2);
        assert_eq!(cache.stats().entries, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn test_a_cancelled_verification_stores_nothing() {
        let fake = Fake {
            delay: Duration::from_secs(5),
            ..Fake::default()
        };
        let cache = cached(&fake);
        tokio::time::timeout(Duration::from_secs(1), auth(&cache, "token"))
            .await
            .unwrap_err();
        tokio::time::sleep(Duration::from_secs(5)).await;
        assert_eq!(cache.stats().entries, 0);
    }

    #[tokio::test]
    async fn test_a_time_to_live_of_zero_calls_the_authenticator_every_time() {
        let fake = Fake::default();
        let cache = CachedAuthenticator::new(
            fake.clone(),
            CacheConfig::builder().time_to_live(Duration::ZERO).build(),
        );
        auth(&cache, "token").await.unwrap();
        auth(&cache, "token").await.unwrap();
        assert_eq!(fake.calls(), 2);
        assert_eq!(cache.stats(), CacheStats::default());
    }

    #[tokio::test]
    async fn test_the_cache_stays_within_max_bytes() {
        let fake = Fake::default();
        let cache = small(&fake);
        for i in 0..1000 {
            auth(&cache, &format!("token-{i}")).await.unwrap();
        }
        let stats = cache.stats();
        assert!(stats.bytes <= 256 * 1024, "{stats:?}");
        assert!(stats.entries < 1000, "{stats:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn test_a_verification_longer_than_the_time_to_live_is_not_stored() {
        let fake = Fake {
            delay: TTL,
            ..Fake::default()
        };
        let cache = cached(&fake);
        auth(&cache, "token").await.unwrap();
        assert_eq!(cache.stats().entries, 0);
    }

    /// Requests that miss at the same time each store their result; the later replaces the
    /// earlier, which is no eviction.
    #[tokio::test(start_paused = true)]
    async fn test_replacing_the_entry_of_the_same_token_is_no_eviction() {
        let fake = Fake {
            delay: Duration::from_secs(1),
            ..Fake::default()
        };
        let cache = cached(&fake);
        let mut requests = tokio::task::JoinSet::new();
        for _ in 0..10 {
            let cache = cache.clone();
            requests.spawn(async move { auth(&cache, "token").await.unwrap() });
        }
        requests.join_all().await;
        assert_eq!(fake.calls(), 10);
        let stats = cache.stats();
        assert_eq!((stats.entries, stats.evicted), (1, 0));
    }

    #[tokio::test]
    async fn test_evictions_of_tokens_used_again_are_counted() {
        let fake = Fake::default();
        let cache = small(&fake);
        for i in 0..1000 {
            auth(&cache, &format!("token-{i}")).await.unwrap();
            auth(&cache, &format!("token-{i}")).await.unwrap();
        }
        let stats = cache.stats();
        assert!(stats.evicted > 0, "{stats:?}");
        assert!(stats.evicted + stats.entries <= 1000, "{stats:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn test_evictions_of_expired_entries_are_not_counted() {
        let fake = Fake::default();
        let cache = small(&fake);
        for i in 0..1000 {
            auth(&cache, &format!("old-{i}")).await.unwrap();
            auth(&cache, &format!("old-{i}")).await.unwrap();
        }
        let evicted = cache.stats().evicted;
        tokio::time::advance(TTL).await;
        for i in 0..cache.stats().entries / 2 {
            auth(&cache, &format!("new-{i}")).await.unwrap();
            auth(&cache, &format!("new-{i}")).await.unwrap();
        }
        assert_eq!(cache.stats().evicted, evicted);
    }

    #[tokio::test(start_paused = true)]
    async fn test_remove_expired_removes_the_entries_that_ended() {
        let fake = Fake::default();
        let cache = cached(&fake);
        auth(&cache, "old").await.unwrap();
        tokio::time::advance(TTL / 2).await;
        auth(&cache, "new").await.unwrap();
        tokio::time::advance(TTL / 2).await;
        cache.remove_expired();
        assert_eq!(cache.stats().entries, 1);
        auth(&cache, "new").await.unwrap();
        assert_eq!(fake.calls(), 2);
    }

    #[tokio::test]
    async fn test_a_token_in_use_survives_a_flood_of_tokens_used_once() {
        let fake = Fake::default();
        let cache = small(&fake);
        auth(&cache, "in-use").await.unwrap();
        for i in 0..10_000 {
            auth(&cache, &format!("once-{i}")).await.unwrap();
            if i % 10 == 0 {
                auth(&cache, "in-use").await.unwrap();
            }
        }
        assert_eq!(fake.calls(), 10_001);
    }

    #[tokio::test]
    async fn test_an_entry_too_large_for_the_cache_is_not_stored() {
        let fake = Fake {
            claims: Some(serde_json::json!({ "groups": vec!["g".repeat(100); 10_000] })),
            ..Fake::default()
        };
        let cache = small(&fake);
        auth(&cache, "token").await.unwrap();
        let stats = cache.stats();
        assert_eq!((stats.entries, stats.evicted), (0, 0));
    }

    #[tokio::test]
    async fn test_routing_and_ids_are_those_of_the_wrapped_authenticator() {
        let fake = Fake::default();
        let chain = AuthenticatorChain::<Fake>::builder()
            .add_authenticator(fake.clone())
            .build();
        let cache =
            CachedAuthenticator::new(chain, CacheConfig::builder().time_to_live(TTL).build());
        assert!(cache.can_handle_token(&Token::new("handled")));
        assert!(!cache.can_handle_token(&Token::new("other")));
        assert_eq!(cache.idp_id(), Some("fake"));
        assert_eq!(cache.idp_ids(), [Some("fake")]);

        let error = cache.authenticate(&Token::new("other")).await.unwrap_err();
        assert!(
            matches!(error, Error::NoAuthenticatorCanHandleToken),
            "{error}"
        );
        cache.authenticate(&Token::new("handled")).await.unwrap();
        cache.authenticate(&Token::new("handled")).await.unwrap();
        assert_eq!(fake.calls(), 1);
    }
}
