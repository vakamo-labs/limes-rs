//! The keys of one JWKS endpoint, shared by all requests.
//!
//! A request for a key the cache holds gets it without waiting, also after the TTL.
//! Fetches run in their own task, one at a time: when the cache is created, in the
//! background once the keys are older than the TTL, and when a token names a key id the
//! keys lack; requests for such a key id wait for that fetch. Once keys have loaded, at most
//! one fetch starts per [`MIN_INTERVAL`], so tokens cannot make the cache fetch on every
//! request, and a shorter TTL acts as the interval. Until keys have loaded, failed fetches
//! are retried sooner.

use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use tokio::{sync::watch, time::Instant};

use super::keys::{JwksDocument, KeySet, VerificationKey};
use crate::error::{Error, Result};

/// How long keys are used before they are fetched again, if no TTL is configured.
const DEFAULT_TTL: Duration = Duration::from_secs(60 * 60);
/// Once keys have loaded, the least time between the starts of two fetches.
const MIN_INTERVAL: Duration = Duration::from_secs(30);
/// Until keys have loaded, the wait after a failed fetch. It doubles with each further
/// failure, up to [`MIN_INTERVAL`].
const COLD_BACKOFF: Duration = Duration::from_millis(250);

/// Fetches the JWKS. Tests replace the HTTP request.
pub(super) type Fetch = Arc<dyn Fn() -> FetchFuture + Send + Sync>;
pub(super) type FetchFuture = Pin<Box<dyn Future<Output = reqwest::Result<KeySet>> + Send>>;

/// Fetches the JWKS at `jwks_uri` with `http`.
pub(super) fn http_fetch(http: reqwest::Client, jwks_uri: url::Url) -> Fetch {
    Arc::new(move || {
        let request = http.get(jwks_uri.clone());
        Box::pin(async move {
            let jwks = request
                .send()
                .await?
                .error_for_status()?
                .json::<JwksDocument>()
                .await?;
            Ok(KeySet::parse(jwks))
        })
    })
}

/// What the cache knows after its latest fetch.
#[derive(Default)]
struct Snapshot {
    /// The keys of the latest successful fetch.
    keys: Arc<KeySet>,
    /// When the latest successful fetch started; `None` until a fetch succeeds.
    fetched_at: Option<Instant>,
    /// The latest fetch, successful or not; `None` until the first one finishes.
    attempt: Option<Attempt>,
    /// Failed fetches since the latest successful one.
    failures: u32,
}

struct Attempt {
    /// Counts fetches: 1 for the first, one more for each next.
    id: u64,
    started_at: Instant,
    finished_at: Instant,
    /// `None` if the fetch succeeded.
    failure: Option<Failure>,
}

#[derive(Clone)]
enum Failure {
    Fetch(Arc<reqwest::Error>),
    /// The fetch ended before it finished: it panicked, or its runtime shut down.
    Interrupted,
}

impl Snapshot {
    fn is_expired(&self, ttl: Duration) -> bool {
        self.fetched_at.is_none_or(|at| at.elapsed() >= ttl)
    }

    /// Whether a new fetch may start at `now`.
    fn may_fetch(&self, now: Instant) -> bool {
        let Some(attempt) = &self.attempt else {
            return true;
        };
        if self.fetched_at.is_some() {
            return now.saturating_duration_since(attempt.started_at) >= MIN_INTERVAL;
        }
        let doublings = self.failures.saturating_sub(1).min(16);
        let backoff = COLD_BACKOFF
            .saturating_mul(1 << doublings)
            .min(MIN_INTERVAL);
        now.saturating_duration_since(attempt.finished_at) >= backoff
    }
}

/// Why a fetch starts. Logged with its outcome.
#[derive(Clone, Copy)]
enum Trigger {
    Startup,
    Expired,
    UnknownKeyId,
}

impl Trigger {
    fn as_str(self) -> &'static str {
        match self {
            Self::Startup => "startup",
            Self::Expired => "expired",
            Self::UnknownKeyId => "unknown_key_id",
        }
    }
}

/// The keys of one JWKS endpoint.
pub(super) struct KeyCache {
    fetch: Fetch,
    jwks_uri: url::Url,
    ttl: Duration,
    /// The current state. Requests wait on it for the outcome of a fetch.
    snapshot: watch::Sender<Arc<Snapshot>>,
    /// The id of the running fetch; `None` while no fetch runs.
    running: Mutex<Option<u64>>,
}

impl KeyCache {
    /// A cache without keys. Without a `ttl`, keys are fetched again after one hour.
    pub(super) fn new(fetch: Fetch, jwks_uri: url::Url, ttl: Option<Duration>) -> Self {
        Self {
            fetch,
            jwks_uri,
            ttl: ttl.unwrap_or(DEFAULT_TTL),
            snapshot: watch::Sender::new(Arc::default()),
            running: Mutex::new(None),
        }
    }

    /// Fetches the first keys. If that fails, the cache starts without keys and fetches
    /// again when a token needs a key.
    pub(super) async fn prefetch(self: &Arc<Self>) {
        if let Some(id) = self.join_or_start_fetch(Trigger::Startup) {
            self.outcome_of(id).await;
        }
    }

    /// The key a token names by its `kid`.
    ///
    /// A key the cache holds is returned at once; after the TTL, a fetch starts in the
    /// background. For a `kid` the keys lack, the request waits for the running fetch, or
    /// starts one unless the latest started less than [`MIN_INTERVAL`] ago.
    ///
    /// A `kid` the keys lack is the token's fault, unless keys have never loaded: then the
    /// keys are unavailable.
    pub(super) async fn get(self: &Arc<Self>, kid: &str) -> Result<Arc<VerificationKey>> {
        let current = self.current();
        if let Some(key) = current.keys.get(kid) {
            if current.is_expired(self.ttl) && current.may_fetch(Instant::now()) {
                self.join_or_start_fetch(Trigger::Expired);
            }
            return Ok(key);
        }
        let current = match self.join_or_start_fetch(Trigger::UnknownKeyId) {
            Some(id) => self.outcome_of(id).await,
            None => self.current(),
        };
        self.answer(&current, kid)
    }

    fn answer(&self, current: &Snapshot, kid: &str) -> Result<Arc<VerificationKey>> {
        if let Some(key) = current.keys.get(kid) {
            return Ok(key);
        }
        let failure = current.attempt.as_ref().and_then(|a| a.failure.clone());
        match failure {
            Some(Failure::Fetch(source)) if current.fetched_at.is_none() => {
                Err(Error::FetchJwksError {
                    url: self.jwks_uri.to_string(),
                    source,
                })
            }
            Some(Failure::Interrupted) if current.fetched_at.is_none() => Err(Error::internal(
                "Failed to fetch the JWKS",
                "the fetch stopped unexpectedly",
            )),
            _ => Err(Error::unauthenticated("Token key id not found in JWKS.")),
        }
    }

    fn current(&self) -> Arc<Snapshot> {
        Arc::clone(&self.snapshot.borrow())
    }

    /// The id of the running fetch, or of a new one if none runs and one may start; `None`
    /// otherwise.
    fn join_or_start_fetch(self: &Arc<Self>, trigger: Trigger) -> Option<u64> {
        let (id, started_at) = {
            let mut running = self.running.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some(id) = *running {
                return Some(id);
            }
            let current = self.current();
            let now = Instant::now();
            if !current.may_fetch(now) {
                tracing::trace!(
                    url = %self.jwks_uri,
                    trigger = trigger.as_str(),
                    "Not fetching the JWKS: the latest fetch is too recent."
                );
                return None;
            }
            let id = current.attempt.as_ref().map_or(1, |a| a.id + 1);
            *running = Some(id);
            (id, now)
        };
        let mut finish = Finish {
            cache: Arc::clone(self),
            id,
            started_at,
            trigger,
            finished: false,
        };
        let fetch = (self.fetch)();
        tokio::spawn(async move {
            let result = fetch.await;
            finish.finished = true;
            finish.cache.finish(
                id,
                started_at,
                trigger,
                result.map_err(|e| Failure::Fetch(Arc::new(e))),
            );
        });
        Some(id)
    }

    /// Publishes the outcome of fetch `id`.
    fn finish(
        &self,
        id: u64,
        started_at: Instant,
        trigger: Trigger,
        outcome: std::result::Result<KeySet, Failure>,
    ) {
        // Publish before clearing `running`: whoever finds no running fetch also finds its
        // outcome.
        let mut running = self.running.lock().unwrap_or_else(PoisonError::into_inner);
        let current = self.current();
        let url = &self.jwks_uri;
        let trigger = trigger.as_str();
        let (keys, fetched_at, failure) = match outcome {
            Ok(keys) => {
                tracing::debug!(%url, trigger, "Fetched the JWKS.");
                (Arc::new(keys), Some(started_at), None)
            }
            Err(failure) => {
                match &failure {
                    Failure::Fetch(error) => {
                        tracing::warn!(%url, trigger, "Failed to fetch the JWKS: {error}");
                    }
                    Failure::Interrupted if std::thread::panicking() => {
                        tracing::error!(%url, trigger, "The JWKS fetch panicked.");
                    }
                    Failure::Interrupted => {
                        tracing::debug!(%url, trigger, "The JWKS fetch stopped before it finished.");
                    }
                }
                (Arc::clone(&current.keys), current.fetched_at, Some(failure))
            }
        };
        let failures = if failure.is_some() {
            current.failures.saturating_add(1)
        } else {
            0
        };
        let next = Arc::new(Snapshot {
            keys,
            fetched_at,
            attempt: Some(Attempt {
                id,
                started_at,
                finished_at: Instant::now(),
                failure,
            }),
            failures,
        });
        self.snapshot.send_replace(next);
        *running = None;
    }

    /// The state once fetch `id` has finished.
    async fn outcome_of(&self, id: u64) -> Arc<Snapshot> {
        let mut receiver = self.snapshot.subscribe();
        let finished = receiver
            .wait_for(|s| s.attempt.as_ref().is_some_and(|a| a.id >= id))
            .await;
        match finished {
            Ok(snapshot) => Arc::clone(&snapshot),
            Err(_) => self.current(),
        }
    }
}

/// Owned by the task of a fetch. If the task ends before the fetch finished (the fetch
/// panicked, or the runtime shut down, also before the task ran), the fetch is recorded as
/// interrupted, so a later request can start the next one.
struct Finish {
    cache: Arc<KeyCache>,
    id: u64,
    started_at: Instant,
    trigger: Trigger,
    finished: bool,
}

impl Drop for Finish {
    fn drop(&mut self) {
        if !self.finished {
            let (id, started_at, trigger) = (self.id, self.started_at, self.trigger);
            self.cache
                .finish(id, started_at, trigger, Err(Failure::Interrupted));
        }
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
    use std::sync::atomic::{AtomicUsize, Ordering};

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

    const UNAUTHENTICATED: &str = "Authentication failed: Token key id not found in JWKS.";

    // ---- the refresh policy, against a fetch without HTTP and a paused clock ----

    #[derive(Clone)]
    enum Response {
        Keys(Vec<&'static str>),
        Fail,
        Panic,
    }

    /// Answers fetches with `response` after `latency`; both can change. The response is
    /// read when a fetch starts.
    struct FakeIdp {
        response: Mutex<Response>,
        latency: Mutex<Duration>,
        fetches: AtomicUsize,
    }

    impl FakeIdp {
        fn new(response: Response) -> Arc<Self> {
            Arc::new(Self {
                response: Mutex::new(response),
                latency: Mutex::new(Duration::ZERO),
                fetches: AtomicUsize::new(0),
            })
        }

        fn respond(&self, response: Response) {
            *self.response.lock().unwrap() = response;
        }

        fn latency(&self, latency: Duration) {
            *self.latency.lock().unwrap() = latency;
        }

        fn fetches(&self) -> usize {
            self.fetches.load(Ordering::SeqCst)
        }

        fn cache(self: &Arc<Self>, ttl: Duration) -> Arc<KeyCache> {
            let idp = Arc::clone(self);
            let fetch: Fetch = Arc::new(move || {
                let idp = Arc::clone(&idp);
                Box::pin(async move {
                    idp.fetches.fetch_add(1, Ordering::SeqCst);
                    let response = idp.response.lock().unwrap().clone();
                    let latency = *idp.latency.lock().unwrap();
                    tokio::time::sleep(latency).await;
                    match response {
                        Response::Keys(kids) => {
                            Ok(KeySet::parse(serde_json::from_value(jwks(&kids)).unwrap()))
                        }
                        Response::Fail => {
                            Err(reqwest::Client::new().get("not a url").build().unwrap_err())
                        }
                        Response::Panic => panic!("the fetch panicked"),
                    }
                })
            });
            let uri = "https://idp.example/jwks".parse().unwrap();
            Arc::new(KeyCache::new(fetch, uri, Some(ttl)))
        }
    }

    const TTL: Duration = Duration::from_secs(300);

    /// Runs `get(kid)` in a task of its own.
    fn spawn_get(
        cache: &Arc<KeyCache>,
        kid: &'static str,
    ) -> tokio::task::JoinHandle<Result<Arc<VerificationKey>>> {
        let cache = Arc::clone(cache);
        tokio::spawn(async move { cache.get(kid).await })
    }

    /// Lets spawned tasks run until all of them wait for the clock.
    async fn settle() {
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn test_prefetch_loads_the_keys() {
        let idp = FakeIdp::new(Response::Keys(vec!["k1"]));
        let cache = idp.cache(TTL);
        cache.prefetch().await;
        cache.get("k1").await.unwrap();
        assert_eq!(idp.fetches(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn test_failed_prefetch_starts_without_keys() {
        let idp = FakeIdp::new(Response::Fail);
        let cache = idp.cache(TTL);
        cache.prefetch().await;

        // Within the backoff, the latest failure is the answer.
        let err = cache.get("k1").await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Unavailable);
        assert_eq!(idp.fetches(), 1);

        idp.respond(Response::Keys(vec!["k1"]));
        tokio::time::advance(COLD_BACKOFF).await;
        cache.get("k1").await.unwrap();
        assert_eq!(idp.fetches(), 2);
    }

    #[test]
    fn test_fetches_are_limited_once_keys_have_loaded() {
        let now = Instant::now();
        let loaded = Snapshot {
            fetched_at: Some(now),
            attempt: Some(Attempt {
                id: 1,
                started_at: now,
                finished_at: now + Duration::from_secs(5),
                failure: None,
            }),
            ..Snapshot::default()
        };
        assert!(!loaded.may_fetch(now + MIN_INTERVAL.saturating_sub(Duration::from_millis(1))));
        assert!(loaded.may_fetch(now + MIN_INTERVAL));
    }

    #[test]
    fn test_backoff_without_keys_doubles_up_to_the_interval() {
        let now = Instant::now();
        let cold = |failures| Snapshot {
            attempt: Some(Attempt {
                id: 1,
                started_at: now,
                finished_at: now,
                failure: Some(Failure::Interrupted),
            }),
            failures,
            ..Snapshot::default()
        };
        for (failures, backoff_ms) in [(1, 250), (2, 500), (3, 1_000), (7, 16_000), (8, 30_000)] {
            let backoff = Duration::from_millis(backoff_ms);
            let snapshot = cold(failures);
            assert!(
                !snapshot.may_fetch(now + backoff.saturating_sub(Duration::from_millis(1))),
                "{failures} failures"
            );
            assert!(snapshot.may_fetch(now + backoff), "{failures} failures");
        }
        assert!(cold(1_000).may_fetch(now + MIN_INTERVAL));
    }

    #[tokio::test(start_paused = true)]
    async fn test_unknown_key_ids_fetch_at_most_once_per_interval() {
        let idp = FakeIdp::new(Response::Keys(vec!["k1"]));
        let cache = idp.cache(TTL);
        cache.prefetch().await;

        idp.latency(Duration::from_secs(1));
        let before = Instant::now();
        for kid in ["unknown-1", "unknown-2", "unknown-3"] {
            assert_eq!(
                cache.get(kid).await.unwrap_err().to_string(),
                UNAUTHENTICATED
            );
        }
        assert_eq!(Instant::now(), before);
        assert_eq!(idp.fetches(), 1);

        tokio::time::advance(MIN_INTERVAL).await;
        idp.respond(Response::Keys(vec!["k1", "k2"]));
        cache.get("k2").await.unwrap();
        assert_eq!(
            cache.get("unknown").await.unwrap_err().to_string(),
            UNAUTHENTICATED
        );
        assert_eq!(idp.fetches(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn test_requests_for_an_unknown_key_id_share_the_running_fetch() {
        let idp = FakeIdp::new(Response::Keys(vec!["k1"]));
        let cache = idp.cache(TTL);
        cache.prefetch().await;
        tokio::time::advance(MIN_INTERVAL).await;

        idp.respond(Response::Keys(vec!["k1", "k2"]));
        idp.latency(Duration::from_secs(1));
        let requests: Vec<_> = (0..10).map(|_| spawn_get(&cache, "k2")).collect();
        for request in requests {
            request.await.unwrap().unwrap();
        }
        assert_eq!(idp.fetches(), 2);
    }

    /// A key first used less than the interval after a fetch started (here: while that
    /// fetch runs) is found once the interval allows the next fetch.
    #[tokio::test(start_paused = true)]
    async fn test_key_published_during_a_fetch_is_found_after_the_interval() {
        let idp = FakeIdp::new(Response::Keys(vec!["k1"]));
        let cache = idp.cache(TTL);
        cache.prefetch().await;
        tokio::time::advance(MIN_INTERVAL).await;

        idp.latency(Duration::from_secs(1));
        let unknown = spawn_get(&cache, "unknown");
        settle().await;
        assert_eq!(idp.fetches(), 2);
        idp.respond(Response::Keys(vec!["k1", "k2"]));

        assert_eq!(
            cache.get("k2").await.unwrap_err().to_string(),
            UNAUTHENTICATED
        );
        assert_eq!(
            unknown.await.unwrap().unwrap_err().to_string(),
            UNAUTHENTICATED
        );

        tokio::time::advance(MIN_INTERVAL).await;
        cache.get("k2").await.unwrap();
        assert_eq!(idp.fetches(), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn test_known_key_after_the_ttl_is_returned_while_the_jwks_is_fetched() {
        let idp = FakeIdp::new(Response::Keys(vec!["k1"]));
        let cache = idp.cache(TTL);
        cache.prefetch().await;
        tokio::time::advance(TTL).await;

        idp.respond(Response::Keys(vec!["k1", "k2"]));
        idp.latency(Duration::from_secs(60));
        let before = Instant::now();
        cache.get("k1").await.unwrap();
        cache.get("k1").await.unwrap();
        assert_eq!(Instant::now(), before);
        settle().await;
        assert_eq!(idp.fetches(), 2);

        // Once the background fetch has finished, its keys are used.
        tokio::time::sleep(Duration::from_secs(60)).await;
        settle().await;
        cache.get("k2").await.unwrap();
        assert_eq!(idp.fetches(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn test_failed_fetch_keeps_the_previous_keys() {
        let idp = FakeIdp::new(Response::Keys(vec!["k1"]));
        let cache = idp.cache(TTL);
        cache.prefetch().await;
        tokio::time::advance(TTL).await;

        idp.respond(Response::Fail);
        cache.get("k1").await.unwrap();
        settle().await;
        cache.get("k1").await.unwrap();
        // Keys did load before, so an unknown key id is the token's fault.
        assert_eq!(
            cache.get("k2").await.unwrap_err().to_string(),
            UNAUTHENTICATED
        );
        assert_eq!(idp.fetches(), 2);

        // The next fetch waits for the interval.
        tokio::time::advance(MIN_INTERVAL.saturating_sub(Duration::from_millis(1))).await;
        cache.get("k1").await.unwrap();
        settle().await;
        assert_eq!(idp.fetches(), 2);
        tokio::time::advance(Duration::from_millis(1)).await;
        cache.get("k1").await.unwrap();
        settle().await;
        assert_eq!(idp.fetches(), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn test_cancelled_request_does_not_cancel_the_fetch() {
        let idp = FakeIdp::new(Response::Keys(vec!["k1"]));
        let cache = idp.cache(TTL);
        cache.prefetch().await;
        tokio::time::advance(MIN_INTERVAL).await;

        idp.respond(Response::Keys(vec!["k1", "k2"]));
        idp.latency(Duration::from_secs(1));
        let request = spawn_get(&cache, "k2");
        settle().await;
        request.abort();

        tokio::time::sleep(Duration::from_secs(1)).await;
        settle().await;
        cache.get("k2").await.unwrap();
        assert_eq!(idp.fetches(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn test_panicking_fetch_is_a_failed_fetch() {
        let idp = FakeIdp::new(Response::Panic);
        let cache = idp.cache(TTL);
        cache.prefetch().await;
        assert_eq!(
            cache.get("k1").await.unwrap_err().kind(),
            ErrorKind::Internal
        );

        idp.respond(Response::Keys(vec!["k1"]));
        tokio::time::advance(COLD_BACKOFF).await;
        cache.get("k1").await.unwrap();
        assert_eq!(idp.fetches(), 2);
    }

    /// A fetch whose runtime shuts down ends for the other runtimes too: a request that
    /// waits for it gets an error, and a later request can fetch again.
    #[test]
    fn test_fetch_stopped_by_a_runtime_shutdown_is_a_failed_fetch() {
        let runtime = || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
        };
        let idp = FakeIdp::new(Response::Keys(vec!["k1"]));
        idp.latency(Duration::from_secs(60));
        let cache = idp.cache(TTL);

        let first = runtime();
        first.block_on(async {
            cache.join_or_start_fetch(Trigger::Startup).unwrap();
            settle().await;
        });
        assert_eq!(idp.fetches(), 1);

        let waiting = std::thread::spawn({
            let cache = Arc::clone(&cache);
            move || runtime().block_on(async move { cache.get("k1").await })
        });
        // Long enough for the request to join the running fetch.
        std::thread::sleep(Duration::from_millis(100));
        drop(first);
        let err = waiting.join().unwrap().unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Internal);

        idp.latency(Duration::ZERO);
        runtime().block_on(async {
            tokio::time::sleep(COLD_BACKOFF).await;
            cache.get("k1").await.unwrap();
        });
        assert_eq!(idp.fetches(), 2);
    }

    // ---- the HTTP fetch, against a mock IdP ----

    /// Serves `body` at `/jwks` after `delay`, or 500 while `body` is `None`.
    async fn serve(body: Option<serde_json::Value>, delay: Duration) -> (url::Url, MockServer) {
        use axum::{Json, Router, http::StatusCode, routing::get};
        let app = Router::new().route(
            "/jwks",
            get(move || async move {
                tokio::time::sleep(delay).await;
                body.map(Json).ok_or(StatusCode::INTERNAL_SERVER_ERROR)
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let uri = format!("http://{}/jwks", listener.local_addr().unwrap())
            .parse()
            .unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (uri, MockServer(server))
    }

    struct MockServer(tokio::task::JoinHandle<()>);

    impl Drop for MockServer {
        fn drop(&mut self) {
            self.0.abort();
        }
    }

    async fn http_cache(http: reqwest::Client, uri: &url::Url) -> Arc<KeyCache> {
        let cache = Arc::new(KeyCache::new(
            http_fetch(http, uri.clone()),
            uri.clone(),
            None,
        ));
        cache.prefetch().await;
        cache
    }

    #[tokio::test]
    async fn test_http_fetch_reads_the_jwks() {
        let (uri, _server) = serve(Some(jwks(&["k1"])), Duration::ZERO).await;
        let cache = http_cache(reqwest::Client::new(), &uri).await;
        cache.get("k1").await.unwrap();
    }

    #[tokio::test]
    async fn test_failed_http_fetch_is_unavailable() {
        let (uri, _server) = serve(None, Duration::ZERO).await;
        let err = http_cache(reqwest::Client::new(), &uri)
            .await
            .get("k1")
            .await
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            format!(
                "Failed to fetch the JWKS from {uri}: HTTP status server error (500 Internal Server Error) for url ({uri})"
            )
        );
        assert_eq!(err.kind(), ErrorKind::Unavailable);
    }

    #[tokio::test]
    async fn test_http_response_that_is_not_a_jwks_is_unavailable() {
        let body = serde_json::json!({ "not": "a JWKS" });
        let (uri, _server) = serve(Some(body), Duration::ZERO).await;
        let err = http_cache(reqwest::Client::new(), &uri)
            .await
            .get("k1")
            .await
            .unwrap_err();
        let Error::FetchJwksError { source, .. } = &err else {
            panic!("expected a fetch error, got {err:?}");
        };
        assert!(source.is_decode(), "{source:?}");
        assert_eq!(err.kind(), ErrorKind::Unavailable);
    }

    #[tokio::test]
    async fn test_timed_out_http_fetch_is_unavailable() {
        let (uri, _server) = serve(Some(jwks(&["k1"])), Duration::from_secs(60)).await;
        let http = reqwest::Client::builder()
            .timeout(Duration::from_millis(100))
            .build()
            .unwrap();
        let err = http_cache(http, &uri).await.get("k1").await.unwrap_err();
        let Error::FetchJwksError { source, .. } = &err else {
            panic!("expected a fetch error, got {err:?}");
        };
        assert!(source.is_timeout(), "{source:?}");
        assert_eq!(err.kind(), ErrorKind::Unavailable);
    }
}
