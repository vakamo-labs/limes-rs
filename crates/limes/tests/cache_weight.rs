//! The cache bounds an estimate of the memory its entries hold. This compares the estimate
//! with what the allocator counts. It is the only test in this binary, so no other test
//! allocates while it measures.
#![cfg(feature = "cache")]

use std::{
    alloc::{GlobalAlloc, Layout, System},
    collections::{BTreeMap, HashSet},
    sync::atomic::{AtomicIsize, Ordering::Relaxed},
    time::Duration,
};

use limes::{
    Authentication, Authenticator, KubernetesUser, Subject, Token, VerifiedClaims,
    cache::{CacheConfig, CachedAuthenticator},
};

struct Counting;

static LIVE: AtomicIsize = AtomicIsize::new(0);

fn size(layout: Layout) -> isize {
    isize::try_from(layout.size()).unwrap()
}

// SAFETY: forwards every call to the system allocator unchanged and only counts sizes.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        LIVE.fetch_add(size(layout), Relaxed);
        // SAFETY: the caller upholds the contract of `GlobalAlloc::alloc`.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(size(layout), Relaxed);
        // SAFETY: the caller upholds the contract of `GlobalAlloc::dealloc`.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        LIVE.fetch_add(isize::try_from(new_size).unwrap() - size(layout), Relaxed);
        // SAFETY: the caller upholds the contract of `GlobalAlloc::realloc`.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// Builds a fresh authentication for every token, as a real authenticator does.
#[derive(Clone)]
enum Identities {
    Claims(&'static str),
    Kubernetes,
}

impl Authenticator for Identities {
    async fn authenticate(&self, token: &Token<'_>) -> limes::error::Result<Authentication> {
        let subject = Subject::new(Some("idp".into()), token.as_str().into());
        let builder = Authentication::builder()
            .subject(subject)
            .audiences(HashSet::from(["lakekeeper".to_string()]));
        Ok(match self {
            Self::Claims(payload) => builder
                .identity(
                    VerifiedClaims::try_from(
                        serde_json::from_str::<serde_json::Value>(payload).unwrap(),
                    )
                    .unwrap(),
                )
                .build(),
            Self::Kubernetes => builder
                .identity(
                    KubernetesUser::builder()
                        .username("system:serviceaccount:analytics:spark-driver")
                        .uid("0e79c2ec-32eb-4a46-ab9b-f075fbbfbd43")
                        .groups(vec![
                            "system:serviceaccounts".to_string(),
                            "system:serviceaccounts:analytics".to_string(),
                            "system:authenticated".to_string(),
                        ])
                        .extra(BTreeMap::from(
                            [
                                (
                                    "authentication.kubernetes.io/credential-id",
                                    "JTI=8f2c1d04-5b7e-4a3c-9d61-2e0f7a8b9c10",
                                ),
                                (
                                    "authentication.kubernetes.io/node-name",
                                    "ip-10-0-12-34.eu-central-1.compute.internal",
                                ),
                                (
                                    "authentication.kubernetes.io/node-uid",
                                    "7d3e9f12-6a4b-4c8d-b1e2-3f5a6b7c8d9e",
                                ),
                                (
                                    "authentication.kubernetes.io/pod-name",
                                    "spark-driver-7f9c8b6d5-x2k4p",
                                ),
                                (
                                    "authentication.kubernetes.io/pod-uid",
                                    "a1b2c3d4-e5f6-4789-a0b1-c2d3e4f5a6b7",
                                ),
                            ]
                            .map(|(key, value)| (key.to_string(), vec![value.to_string()])),
                        ))
                        .build(),
                )
                .build(),
        })
    }

    fn can_handle_token(&self, _: &Token<'_>) -> bool {
        true
    }

    fn idp_id(&self) -> Option<&str> {
        None
    }
}

const KEYCLOAK: &str = r#"{
    "exp": 1730052519, "iat": 1730048619, "auth_time": 1730048619,
    "jti": "d5b1f0a2-3c4e-4f6a-8b9c-0d1e2f3a4b5c", "iss": "https://keycloak.example.com/realms/iceberg",
    "aud": ["lakekeeper", "account"], "sub": "f1616ed0-18d8-48ea-9fb3-832f42db0b1b", "typ": "Bearer",
    "azp": "spark", "sid": "6f2ca33d-2513-43fe-ab53-4a945c78a66d", "acr": "1",
    "allowed-origins": ["*"],
    "realm_access": { "roles": ["offline_access", "uma_authorization", "default-roles-iceberg"] },
    "resource_access": { "account": { "roles": ["manage-account", "manage-account-links", "view-profile"] } },
    "scope": "openid email profile", "email_verified": true, "name": "Example User",
    "preferred_username": "example", "given_name": "Example", "family_name": "User", "email": "user@example.com"
}"#;

fn entra(groups: usize) -> &'static str {
    let groups: Vec<String> = (0..groups)
        .map(|i| format!("{i:08x}-0000-4000-8000-{i:012x}"))
        .collect();
    let payload = serde_json::json!({
        "aud": "00000003-0000-0000-c000-000000000000",
        "iss": "https://sts.windows.net/00000000-0000-4000-8000-000000000000/",
        "iat": 1_730_048_619, "nbf": 1_730_048_619, "exp": 1_730_052_519,
        "acct": 0, "acr": "1", "aio": "AVQAq/8YAAAA0000000000000000000000000000000000000000000000000000",
        "amr": ["pwd", "mfa"], "app_displayname": "Lakekeeper", "appid": "00000000-0000-4000-8000-000000000001",
        "appidacr": "0", "family_name": "User", "given_name": "Example", "groups": groups,
        "idtyp": "user", "ipaddr": "192.0.2.10", "name": "Example User",
        "oid": "00000000-0000-4000-8000-000000000002", "platf": "5", "puid": "10030000A0000000",
        "rh": "0.AAAA0000000000000000000000000000000000000000000.", "scp": "openid profile email",
        "sub": "0000000000000000000000000000000000000000000", "tenant_region_scope": "EU",
        "tid": "00000000-0000-4000-8000-000000000000", "unique_name": "user@example.com",
        "upn": "user@example.com", "uti": "AAAAAAAAAAAAAAAAAAAAAA", "ver": "1.0",
        "wids": ["b79fbf4d-3ef9-4689-8143-76b194e85509"], "xms_tcdt": 1_600_000_000
    });
    Box::leak(payload.to_string().into_boxed_str())
}

/// The memory `count` entries hold, as the allocator counts it and as the cache estimates it.
async fn measure(identities: Identities, count: usize) -> (i64, i64) {
    let cache = CachedAuthenticator::new(
        identities,
        CacheConfig::builder()
            .time_to_live(Duration::from_secs(3600))
            .build(),
    );
    let tokens: Vec<String> = (0..count).map(|i| format!("token-{i:06}")).collect();
    // Warm up the allocations made once, such as those of the runtime.
    cache.authenticate(&Token::new("warm-up")).await.unwrap();
    let before_live = LIVE.load(Relaxed);
    let before_bytes = cache.stats().bytes;
    for token in &tokens {
        drop(cache.authenticate(&Token::new(token)).await.unwrap());
    }
    let measured = i64::try_from(LIVE.load(Relaxed) - before_live).unwrap();
    let estimated = i64::try_from(cache.stats().bytes - before_bytes).unwrap();
    assert_eq!(cache.stats().entries, u64::try_from(count + 1).unwrap());
    (measured, estimated)
}

#[tokio::test(flavor = "current_thread")]
async fn test_estimate_is_close_to_what_the_allocator_counts() {
    let count = 1000;
    let mut report = Vec::new();
    for (name, identities) in [
        ("kubernetes", Identities::Kubernetes),
        ("keycloak", Identities::Claims(KEYCLOAK)),
        ("entra, 0 groups", Identities::Claims(entra(0))),
        ("entra, 200 groups", Identities::Claims(entra(200))),
    ] {
        let (measured, estimated) = measure(identities, count).await;
        let per_entry = |bytes: i64| bytes / i64::try_from(count).unwrap();
        #[allow(clippy::cast_precision_loss)] // a ratio for a report
        let ratio = estimated as f64 / measured as f64;
        report.push(format!(
            "{name}: measured {} B, estimated {} B per entry, ratio {ratio:.2}",
            per_entry(measured),
            per_entry(estimated)
        ));
        assert!((0.8..=1.05).contains(&ratio), "{}", report.join("\n"));
    }
    println!("{}", report.join("\n"));
}
