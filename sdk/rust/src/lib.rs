//! Client for [authsvc](https://github.com/zb8ne/authsvc).
//!
//! The design goal is that verifying a request costs nothing and depends on
//! nothing. [`Client::verify`] validates tokens locally against a cached JWKS
//! and never makes a network call on the request path — so an authsvc outage
//! cannot take down the apps that depend on it. Only the login, exchange, and
//! refresh paths, which are inherently interactive, talk to the service.
//!
//! ```no_run
//! # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
//! let auth = authsdk::Client::new(authsdk::Config::new("https://auth.grindlog.lol", "myapp"))?;
//! let user = auth.verify("eyJhbGciOi...").await?;
//! println!("{}", user.email);
//! # Ok(()) }
//! ```

use std::sync::Arc;
use std::time::Duration;

mod keys;
mod session;

pub use session::{CallbackError, Session, User};

use keys::KeyCache;

/// How long cached keys are trusted once refreshes start failing.
///
/// This bounds how long a compromised signing key stays trusted by an app that
/// can no longer reach authsvc. It has to be finite: without it, rotating a
/// leaked key out would mean redeploying every dependent app.
pub const DEFAULT_JWKS_MAX_STALE: Duration = Duration::from_secs(7 * 24 * 60 * 60);

type ErrorCallback = Arc<dyn Fn(&str) + Send + Sync>;

#[derive(Clone)]
pub struct Config {
    /// authsvc origin, e.g. `https://auth.grindlog.lol`.
    pub base_url: String,
    /// Tried when `base_url` fails to connect or returns 5xx.
    pub fallback_url: Option<String>,
    pub client_id: String,
    pub client_secret: Option<String>,
    /// Defaults to `client_id`. Tokens minted for any other audience are
    /// rejected, which is what stops one app's token working against another.
    pub audience: String,
    /// Defaults to `base_url`. Must match the `iss` claim exactly.
    pub issuer: String,
    /// How often keys refresh in the background. Keys are served from cache
    /// regardless.
    pub jwks_refresh: Duration,
    /// `None` disables expiry entirely — see [`DEFAULT_JWKS_MAX_STALE`].
    pub jwks_max_stale: Option<Duration>,
    /// Your app's sign-in page, offered as the way forward on a failed callback.
    pub sign_in_url: Option<String>,
    /// Receives background refresh failures.
    pub on_error: Option<ErrorCallback>,
}

impl Config {
    pub fn new(base_url: impl Into<String>, client_id: impl Into<String>) -> Self {
        let base_url = base_url.into().trim_end_matches('/').to_string();
        let client_id = client_id.into();
        Self {
            issuer: base_url.clone(),
            audience: client_id.clone(),
            base_url,
            client_id,
            fallback_url: None,
            client_secret: None,
            jwks_refresh: Duration::from_secs(15 * 60),
            jwks_max_stale: Some(DEFAULT_JWKS_MAX_STALE),
            sign_in_url: None,
            on_error: None,
        }
    }

    pub fn client_secret(mut self, s: impl Into<String>) -> Self {
        self.client_secret = Some(s.into());
        self
    }
    pub fn fallback_url(mut self, s: impl Into<String>) -> Self {
        self.fallback_url = Some(s.into().trim_end_matches('/').to_string());
        self
    }
    pub fn audience(mut self, s: impl Into<String>) -> Self {
        self.audience = s.into();
        self
    }
    pub fn issuer(mut self, s: impl Into<String>) -> Self {
        self.issuer = s.into().trim_end_matches('/').to_string();
        self
    }
    pub fn sign_in_url(mut self, s: impl Into<String>) -> Self {
        self.sign_in_url = Some(s.into());
        self
    }
    pub fn jwks_max_stale(mut self, d: Option<Duration>) -> Self {
        self.jwks_max_stale = d;
        self
    }
    pub fn on_error(mut self, f: impl Fn(&str) + Send + Sync + 'static) -> Self {
        self.on_error = Some(Arc::new(f));
        self
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("authsdk: no verification keys available yet: {0}")]
    NoKeys(String),
    #[error("authsdk: cached keys are {age:?} stale, limit is {limit:?}")]
    KeysTooStale { age: Duration, limit: Duration },
    #[error("authsdk: jwks: {0}")]
    Jwks(String),
    #[error("authsdk: token invalid: {0}")]
    Token(String),
    #[error("authsdk: transport: {0}")]
    Transport(String),
    #[error("authsdk: server returned {status}: {body}")]
    Status { status: u16, body: String },
    #[error("authsdk: client_secret is required for this call")]
    MissingSecret,
}

impl Error {
    /// Whether this failure justifies retrying against the fallback host.
    /// A 4xx is a real answer from a healthy server, so it does not.
    pub(crate) fn should_fail_over(&self) -> bool {
        match self {
            Error::Status { status, .. } => *status >= 500,
            Error::Transport(_) => true,
            _ => false,
        }
    }

    /// True when verification failed because we have no trustworthy keys,
    /// rather than because the token was bad. Callers should answer 503, not
    /// 401 — neither case is the caller's fault.
    pub fn is_key_problem(&self) -> bool {
        matches!(self, Error::NoKeys(_) | Error::KeysTooStale { .. })
    }
}

#[derive(Clone)]
pub struct Client {
    pub(crate) cfg: Config,
    pub(crate) http: reqwest::Client,
    pub(crate) keys: Arc<KeyCache>,
}

impl Client {
    /// Builds a client and starts the background key refresher.
    ///
    /// A failure to warm the cache is not fatal: making startup depend on
    /// authsvc being reachable is exactly the coupling this SDK avoids.
    pub fn new(cfg: Config) -> Result<Self, Error> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(|e| Error::Transport(e.to_string()))?;

        let keys = Arc::new(KeyCache::new(cfg.clone(), http.clone()));

        // Warm in the background; never block construction on the network.
        {
            let k = Arc::clone(&keys);
            let every = cfg.jwks_refresh;
            tokio::spawn(async move {
                k.refresh().await;
                let mut tick = tokio::time::interval(every);
                tick.tick().await; // consume the immediate first tick
                loop {
                    tick.tick().await;
                    k.refresh().await;
                }
            });
        }

        Ok(Self { cfg, http, keys })
    }

    /// Blocks until keys are available or the timeout elapses. Optional —
    /// useful in tests and at startup when you would rather fail fast.
    pub async fn wait_ready(&self, timeout: Duration) -> Result<(), Error> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if self.keys.get().await.is_ok() {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                return self.keys.get().await.map(|_| ());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// Where to send a browser to begin an OAuth login.
    pub fn start_url(&self, provider: &str, redirect_uri: &str, state: &str) -> String {
        format!(
            "{}/v1/oauth/{}/start?client_id={}&redirect_uri={}&state={}",
            self.cfg.base_url,
            urlencode(provider),
            urlencode(&self.cfg.client_id),
            urlencode(redirect_uri),
            urlencode(state)
        )
    }
}

pub(crate) fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
