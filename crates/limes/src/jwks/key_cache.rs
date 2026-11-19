//! The keys of one JWKS endpoint, fetched when tokens need them and shared by all requests.

use std::{
    sync::{Arc, PoisonError, RwLock},
    time::Duration,
};

use tokio::time::Instant;

use super::keys::{JwksDocument, KeySet, VerificationKey};
use crate::error::{Error, Result};

/// How long keys are used before they are fetched again, if no TTL is configured.
const DEFAULT_TTL: Duration = Duration::from_secs(60 * 60);

/// What the cache knows after its latest fetch attempt.
#[derive(Default)]
struct Snapshot {
    /// The keys of the latest successful fetch.
    keys: Arc<KeySet>,
    /// When the latest successful fetch started; `None` until a fetch succeeds.
    fetched_at: Option<Instant>,
    /// The latest fetch attempt, successful or not; `None` until the first one.
    attempt: Option<Attempt>,
}

impl Snapshot {
    /// The key for `kid`, if the keys are within the TTL and hold it.
    fn fresh_key(&self, kid: &str, ttl: Duration) -> Option<Arc<VerificationKey>> {
        let fresh = self.fetched_at.is_some_and(|at| at.elapsed() < ttl);
        if fresh { self.keys.get(kid) } else { None }
    }
}

struct Attempt {
    started_at: Instant,
    /// Why the attempt failed; `None` if it succeeded.
    error: Option<Arc<reqwest::Error>>,
}

/// The keys of one JWKS endpoint, fetched on demand.
pub(super) struct KeyCache {
    http: reqwest::Client,
    jwks_uri: url::Url,
    ttl: Duration,
    current: RwLock<Arc<Snapshot>>,
    /// Held while a fetch runs, so one fetch runs at a time.
    refresh: tokio::sync::Mutex<()>,
}

impl KeyCache {
    /// A cache that fetches its first keys when a token needs them. Without a `ttl`, keys
    /// are fetched again after one hour.
    pub(super) fn new(http: reqwest::Client, jwks_uri: url::Url, ttl: Option<Duration>) -> Self {
        Self {
            http,
            jwks_uri,
            ttl: ttl.unwrap_or(DEFAULT_TTL),
            current: RwLock::default(),
            refresh: tokio::sync::Mutex::new(()),
        }
    }

    /// The key a token names by its `kid`.
    ///
    /// Within the TTL, a key the cache holds is returned at once. Otherwise the request
    /// waits for a fetch, and requests that wait together share one. A fetch that finished
    /// while the request waited is used if it returned the key; else the request uses a
    /// fetch that started after it arrived. If that fetch fails, a key of an earlier fetch
    /// is still used.
    ///
    /// A `kid` the keys do not contain is the token's fault, unless no fetch has succeeded
    /// yet: then the keys are unavailable.
    pub(super) async fn get(&self, kid: &str) -> Result<Arc<VerificationKey>> {
        let arrived = Instant::now();
        if let Some(key) = self.current().fresh_key(kid, self.ttl) {
            return Ok(key);
        }
        let current = self.refresh(kid, arrived).await;
        if let Some(key) = current.keys.get(kid) {
            return Ok(key);
        }
        match current.attempt.as_ref().and_then(|a| a.error.as_ref()) {
            Some(error) if current.fetched_at.is_none() => Err(Error::FetchJwksError {
                url: self.jwks_uri.to_string(),
                source: Arc::clone(error),
            }),
            _ => Err(Error::unauthenticated("Token key id not found in JWKS.")),
        }
    }

    fn current(&self) -> Arc<Snapshot> {
        self.current
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The state to answer a request with, once no other fetch runs: the current one if it
    /// holds `kid` within the TTL or comes from an attempt that started at or after
    /// `arrived`, otherwise the state after a new fetch. An attempt that started earlier
    /// can miss a key the identity provider published just before the request arrived.
    async fn refresh(&self, kid: &str, arrived: Instant) -> Arc<Snapshot> {
        let _refreshing = self.refresh.lock().await;
        let current = self.current();
        if current.fresh_key(kid, self.ttl).is_some()
            || current
                .attempt
                .as_ref()
                .is_some_and(|attempt| attempt.started_at >= arrived)
        {
            return current;
        }
        let started_at = Instant::now();
        let next = Arc::new(match self.fetch().await {
            Ok(keys) => Snapshot {
                keys: Arc::new(keys),
                fetched_at: Some(started_at),
                attempt: Some(Attempt {
                    started_at,
                    error: None,
                }),
            },
            Err(error) => {
                tracing::debug!(url = %self.jwks_uri, "Failed to fetch the JWKS: {error}");
                Snapshot {
                    keys: Arc::clone(&current.keys),
                    fetched_at: current.fetched_at,
                    attempt: Some(Attempt {
                        started_at,
                        error: Some(Arc::new(error)),
                    }),
                }
            }
        });
        *self.current.write().unwrap_or_else(PoisonError::into_inner) = Arc::clone(&next);
        next
    }

    async fn fetch(&self) -> reqwest::Result<KeySet> {
        let jwks = self
            .http
            .get(self.jwks_uri.clone())
            .send()
            .await?
            .error_for_status()?
            .json::<JwksDocument>()
            .await?;
        Ok(KeySet::parse(jwks))
    }
}

impl std::fmt::Debug for KeyCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyCache")
            .field("jwks_uri", &self.jwks_uri.as_str())
            .field("ttl", &self.ttl)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::error::ErrorKind;
    use pretty_assertions::assert_eq;
    use std::sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    fn ed25519_jwk(kid: &str) -> serde_json::Value {
        use base64::Engine as _;
        let key_pair = aws_lc_rs::signature::Ed25519KeyPair::generate().unwrap();
        let x = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(aws_lc_rs::signature::KeyPair::public_key(&key_pair).as_ref());
        serde_json::json!({ "kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "kid": kid, "x": x })
    }

    fn jwks(kids: &[&str]) -> serde_json::Value {
        let keys: Vec<_> = kids.iter().map(|kid| ed25519_jwk(kid)).collect();
        serde_json::json!({ "keys": keys })
    }

    /// Serves a document that tests can replace, or 500 while it is `None`, after a delay
    /// tests can change. Counts the requests; the document is read when a request arrives.
    struct MockIdp {
        jwks: Arc<Mutex<Option<serde_json::Value>>>,
        delay: Arc<Mutex<Duration>>,
        fetches: Arc<AtomicUsize>,
        uri: url::Url,
        server: tokio::task::JoinHandle<()>,
    }

    impl MockIdp {
        async fn serve(jwks: Option<serde_json::Value>) -> Self {
            use axum::{Json, Router, http::StatusCode, routing::get};
            let jwks = Arc::new(Mutex::new(jwks));
            let delay = Arc::new(Mutex::new(Duration::ZERO));
            let fetches = Arc::new(AtomicUsize::new(0));
            let app = Router::new().route(
                "/jwks",
                get({
                    let jwks = Arc::clone(&jwks);
                    let delay = Arc::clone(&delay);
                    let fetches = Arc::clone(&fetches);
                    move || async move {
                        fetches.fetch_add(1, Ordering::SeqCst);
                        let body = jwks.lock().unwrap().clone();
                        let delay = *delay.lock().unwrap();
                        tokio::time::sleep(delay).await;
                        body.map(Json).ok_or(StatusCode::INTERNAL_SERVER_ERROR)
                    }
                }),
            );
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let uri = format!("http://{}/jwks", listener.local_addr().unwrap())
                .parse()
                .unwrap();
            let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            Self {
                jwks,
                delay,
                fetches,
                uri,
                server,
            }
        }

        fn publish(&self, jwks: Option<serde_json::Value>) {
            *self.jwks.lock().unwrap() = jwks;
        }

        fn delay(&self, delay: Duration) {
            *self.delay.lock().unwrap() = delay;
        }

        fn fetches(&self) -> usize {
            self.fetches.load(Ordering::SeqCst)
        }

        async fn wait_for_fetches(&self, fetches: usize) {
            tokio::time::timeout(Duration::from_secs(5), async {
                while self.fetches() < fetches {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            })
            .await
            .unwrap();
        }

        fn cache(&self, ttl: Option<Duration>) -> Arc<KeyCache> {
            Arc::new(KeyCache::new(reqwest::Client::new(), self.uri.clone(), ttl))
        }
    }

    impl Drop for MockIdp {
        fn drop(&mut self) {
            self.server.abort();
        }
    }

    /// Runs `get(kid)` for each of `kids` at the same time.
    async fn get_all(cache: &Arc<KeyCache>, kids: &[&str]) -> Vec<Result<Arc<VerificationKey>>> {
        let tasks: Vec<_> = kids
            .iter()
            .map(|kid| {
                let cache = Arc::clone(cache);
                let kid = kid.to_string();
                tokio::spawn(async move { cache.get(&kid).await })
            })
            .collect();
        let mut results = Vec::new();
        for task in tasks {
            results.push(task.await.unwrap());
        }
        results
    }

    #[tokio::test]
    async fn test_known_key_within_ttl_is_not_fetched_again() {
        let idp = MockIdp::serve(Some(jwks(&["k1"]))).await;
        let cache = idp.cache(None);
        cache.get("k1").await.unwrap();
        cache.get("k1").await.unwrap();
        assert_eq!(idp.fetches(), 1);
    }

    #[tokio::test]
    async fn test_unknown_key_fetches_the_jwks_again() {
        let idp = MockIdp::serve(Some(jwks(&["k1"]))).await;
        let cache = idp.cache(None);
        cache.get("k1").await.unwrap();

        idp.publish(Some(jwks(&["k2"])));
        cache.get("k2").await.unwrap();
        assert_eq!(idp.fetches(), 2);

        // The rotation removed `k1`.
        let err = cache.get("k1").await.unwrap_err();
        assert_eq!(
            err.to_string(),
            "Authentication failed: Token key id not found in JWKS."
        );
        assert_eq!(err.kind(), ErrorKind::Unauthenticated);
        assert_eq!(idp.fetches(), 3);
    }

    #[tokio::test]
    async fn test_failed_fetch_keeps_the_previous_keys() {
        let idp = MockIdp::serve(Some(jwks(&["k1"]))).await;
        let cache = idp.cache(Some(Duration::ZERO));
        cache.get("k1").await.unwrap();

        for failing in [None, Some(serde_json::json!({ "not": "a JWKS" }))] {
            idp.publish(failing);
            cache.get("k1").await.unwrap();
        }
        // Keys did load before, so an unknown key id is the token's fault.
        let err = cache.get("k2").await.unwrap_err();
        assert_eq!(
            err.to_string(),
            "Authentication failed: Token key id not found in JWKS."
        );
        assert_eq!(err.kind(), ErrorKind::Unauthenticated);
        assert_eq!(idp.fetches(), 4);
    }

    #[tokio::test]
    async fn test_failed_first_fetch_is_unavailable() {
        let idp = MockIdp::serve(None).await;
        let err = idp.cache(None).get("k1").await.unwrap_err();
        assert_eq!(
            err.to_string(),
            format!(
                "Failed to fetch the JWKS from {}: HTTP status server error (500 Internal Server Error) for url ({})",
                idp.uri, idp.uri
            )
        );
        assert_eq!(err.kind(), ErrorKind::Unavailable);
    }

    #[tokio::test]
    async fn test_timed_out_fetch_is_unavailable() {
        let idp = MockIdp::serve(Some(jwks(&["k1"]))).await;
        idp.delay(Duration::from_secs(60));
        let http = reqwest::Client::builder()
            .timeout(Duration::from_millis(100))
            .build()
            .unwrap();

        let err = KeyCache::new(http, idp.uri.clone(), None)
            .get("k1")
            .await
            .unwrap_err();
        let Error::FetchJwksError { source, .. } = &err else {
            panic!("expected a fetch error, got {err:?}");
        };
        assert!(source.is_timeout(), "{source:?}");
        assert_eq!(err.kind(), ErrorKind::Unavailable);
    }

    #[tokio::test]
    async fn test_requests_that_wait_together_share_one_fetch() {
        let idp = MockIdp::serve(Some(jwks(&["k1"]))).await;
        idp.delay(Duration::from_millis(50));
        let cache = idp.cache(None);

        let results = get_all(&cache, &["k1"; 20]).await;
        assert!(results.iter().all(Result::is_ok));
        assert_eq!(idp.fetches(), 1);
    }

    /// Requests that arrive during a fetch that does not return their key wait for one more
    /// fetch, which started after all of them arrived, and share it.
    #[tokio::test]
    async fn test_requests_for_a_key_the_fetch_missed_share_one_more_fetch() {
        let idp = MockIdp::serve(Some(jwks(&["k1"]))).await;
        idp.delay(Duration::from_millis(50));
        let cache = idp.cache(None);

        let results = get_all(&cache, &["k2"; 20]).await;
        assert!(
            results
                .iter()
                .all(|r| r.as_ref().unwrap_err().kind() == ErrorKind::Unauthenticated)
        );
        assert_eq!(idp.fetches(), 2);
    }

    #[tokio::test]
    async fn test_requests_that_wait_together_share_one_failed_fetch() {
        let idp = MockIdp::serve(None).await;
        idp.delay(Duration::from_millis(50));
        let cache = idp.cache(None);

        let results = get_all(&cache, &["k1"; 10]).await;
        assert!(
            results
                .iter()
                .all(|r| r.as_ref().unwrap_err().kind() == ErrorKind::Unavailable)
        );
        assert_eq!(idp.fetches(), 2);
    }

    /// A request does not use a fetch that started before it arrived: that fetch can miss a
    /// key the identity provider published since.
    #[tokio::test]
    async fn test_key_published_during_a_fetch_is_found() {
        let idp = MockIdp::serve(Some(jwks(&["k1"]))).await;
        let cache = idp.cache(None);
        cache.get("k1").await.unwrap();

        idp.delay(Duration::from_millis(100));
        let unknown = tokio::spawn({
            let cache = Arc::clone(&cache);
            async move { cache.get("unknown").await }
        });
        idp.wait_for_fetches(2).await;
        idp.publish(Some(jwks(&["k1", "k2"])));

        cache.get("k2").await.unwrap();
        assert_eq!(
            unknown.await.unwrap().unwrap_err().kind(),
            ErrorKind::Unauthenticated
        );
        assert_eq!(idp.fetches(), 3);
    }

    #[tokio::test]
    async fn test_known_key_does_not_wait_for_a_fetch() {
        let idp = MockIdp::serve(Some(jwks(&["k1"]))).await;
        let cache = idp.cache(None);
        cache.get("k1").await.unwrap();

        idp.delay(Duration::from_secs(60));
        let unknown = tokio::spawn({
            let cache = Arc::clone(&cache);
            async move { cache.get("unknown").await }
        });
        idp.wait_for_fetches(2).await;

        tokio::time::timeout(Duration::from_secs(1), cache.get("k1"))
            .await
            .unwrap()
            .unwrap();
        unknown.abort();
    }
}
