//! These run against a stub JWKS server, so they test the SDK rather than the
//! network.

use std::time::Duration;

use authsdk::{Client, Config};
use axum::{routing::get, Json, Router};
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

const ISS: &str = "https://auth.test";
const AUD: &str = "myapp";

struct Stub {
    url: String,
    key: SigningKey,
    hits: Arc<AtomicU64>,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Stub {
    async fn start() -> Self {
        let key = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
        let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes());
        let hits = Arc::new(AtomicU64::new(0));

        let h = hits.clone();
        let app = Router::new().route(
            "/.well-known/jwks.json",
            get(move || {
                let h = h.clone();
                let x = x.clone();
                async move {
                    h.fetch_add(1, Ordering::SeqCst);
                    Json(json!({"keys":[{"kty":"OKP","crv":"Ed25519","alg":"EdDSA","use":"sig","kid":"k1","x":x}]}))
                }
            }),
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            axum::serve(listener, app).with_graceful_shutdown(async { rx.await.ok(); }).await.ok();
        });

        Self { url: format!("http://{addr}"), key, hits, shutdown: Some(tx) }
    }

    fn mint(&self, aud: &str, iss: &str, exp_offset: i64) -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let b64 = |b: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);

        let header = b64(json!({"alg":"EdDSA","typ":"JWT","kid":"k1"}).to_string().as_bytes());
        let payload = b64(
            json!({
                "iss": iss, "sub": "user-1", "aud": aud, "sid": "sess-1",
                "email": "a@b.test", "email_verified": true, "roles": ["employee","admin"],
                "iat": now, "exp": now + exp_offset
            })
            .to_string()
            .as_bytes(),
        );
        let signing_input = format!("{header}.{payload}");
        let sig = self.key.sign(signing_input.as_bytes());
        format!("{signing_input}.{}", b64(&sig.to_bytes()))
    }

    fn jwks_hits(&self) -> u64 {
        self.hits.load(Ordering::SeqCst)
    }

    fn stop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            tx.send(()).ok();
        }
    }
}

async fn client_for(stub: &Stub) -> Client {
    let c = Client::new(Config::new(&stub.url, AUD).issuer(ISS)).unwrap();
    c.wait_ready(Duration::from_secs(5)).await.unwrap();
    c
}

#[tokio::test]
async fn verifies_a_valid_token() {
    let stub = Stub::start().await;
    let c = client_for(&stub).await;

    let u = c.verify(&stub.mint(AUD, ISS, 3600)).await.unwrap();
    assert_eq!(u.id, "user-1");
    assert_eq!(u.email, "a@b.test");
    assert!(u.email_verified);
    assert_eq!(u.session_id, "sess-1");
    assert!(u.has_role("admin"));
    assert!(!u.has_role("nope"));
    assert!(u.has_any_role(&["nope", "employee"]));
}

#[tokio::test]
async fn rejects_wrong_audience_issuer_and_expiry() {
    let stub = Stub::start().await;
    let c = client_for(&stub).await;

    assert!(c.verify(&stub.mint("someone-else", ISS, 3600)).await.is_err(), "wrong audience accepted");
    assert!(c.verify(&stub.mint(AUD, "https://evil.test", 3600)).await.is_err(), "wrong issuer accepted");
    assert!(c.verify(&stub.mint(AUD, ISS, -3600)).await.is_err(), "expired token accepted");
    assert!(c.verify("garbage").await.is_err(), "garbage accepted");
    assert!(c.verify("").await.is_err(), "empty accepted");
}

#[tokio::test]
async fn rejects_a_token_signed_by_another_key() {
    let stub = Stub::start().await;
    let other = Stub::start().await;
    let c = client_for(&stub).await;

    assert!(c.verify(&other.mint(AUD, ISS, 3600)).await.is_err(), "foreign key accepted");
}

#[tokio::test]
async fn rejects_alg_none_forgery() {
    let stub = Stub::start().await;
    let c = client_for(&stub).await;

    let b64 = |b: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
    let forged = format!(
        "{}.{}.",
        b64(br#"{"alg":"none","typ":"JWT"}"#),
        b64(format!(r#"{{"iss":"{ISS}","sub":"u1","aud":"{AUD}","exp":99999999999}}"#).as_bytes())
    );
    assert!(c.verify(&forged).await.is_err(), "alg=none accepted");
}

/// The property the whole SDK exists for.
#[tokio::test]
async fn verification_survives_an_outage_and_makes_no_request_path_calls() {
    let mut stub = Stub::start().await;
    let c = client_for(&stub).await;
    let token = stub.mint(AUD, ISS, 3600);

    let before = stub.jwks_hits();
    for _ in 0..50 {
        c.verify(&token).await.unwrap();
    }
    assert_eq!(stub.jwks_hits(), before, "JWKS was fetched on the request path");

    // authsvc falls over completely.
    stub.stop();
    tokio::time::sleep(Duration::from_millis(200)).await;

    for i in 0..50 {
        c.verify(&token).await.unwrap_or_else(|e| panic!("verify {i} failed during outage: {e}"));
    }
}

#[tokio::test]
async fn cold_cache_is_reported_as_a_key_problem_not_a_bad_token() {
    // Nothing listening at all.
    let c = Client::new(Config::new("http://127.0.0.1:1", AUD).issuer(ISS)).unwrap();
    let err = c.verify("anything").await.unwrap_err();
    assert!(err.is_key_problem(), "cold cache should be a key problem, got: {err}");
}

#[tokio::test]
async fn start_url_is_escaped() {
    let stub = Stub::start().await;
    let c = client_for(&stub).await;
    let u = c.start_url("google", "https://app.test/cb", "st&ate");
    assert!(u.contains("client_id=myapp"), "{u}");
    assert!(u.contains("redirect_uri=https%3A%2F%2Fapp.test%2Fcb"), "{u}");
    assert!(u.contains("state=st%26ate"), "{u}");
}

#[tokio::test]
async fn callback_errors_have_human_wording() {
    use authsdk::CallbackError;

    let e = CallbackError::parse("manual_link_required");
    assert_eq!(e, CallbackError::ManualLinkRequired);
    let (title, detail) = e.message();
    assert!(title.to_lowercase().contains("already have an account"), "{title}");
    assert!(detail.to_lowercase().contains("password"), "{detail}");
    assert!(!e.retryable(), "retrying manual_link_required fails identically");

    assert!(CallbackError::parse("access_denied").retryable());
    // Unknown codes must still produce something showable.
    let (t, d) = CallbackError::parse("something_new").message();
    assert!(!t.is_empty() && !d.is_empty());
}
