use std::sync::Arc;
use std::time::{Duration, Instant};

use jsonwebtoken::{Algorithm, DecodingKey};
use serde::Deserialize;
use tokio::sync::RwLock;

use crate::{Config, Error};

/// One key from the JWKS. authsvc publishes Ed25519 (OKP) keys only.
#[derive(Debug, Deserialize, Clone)]
pub(crate) struct Jwk {
    pub kid: String,
    /// Key type; authsvc publishes OKP. Kept for completeness even though the
    /// curve check below is what actually gates usability.
    #[serde(default)]
    #[allow(dead_code)]
    pub kty: String,
    #[serde(default)]
    pub crv: String,
    /// Base64url public key material.
    pub x: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct JwkSet {
    pub keys: Vec<Jwk>,
}

#[derive(Clone)]
pub(crate) struct CachedKey {
    pub kid: String,
    pub key: Arc<DecodingKey>,
}

struct Inner {
    keys: Vec<CachedKey>,
    fetched_at: Option<Instant>,
    last_err: Option<String>,
}

/// Holds the JWKS and refreshes it in the background.
///
/// Reads never block on the network. That is the whole point: verifying a
/// request must not wait on, or fail because of, an HTTP call to authsvc.
pub(crate) struct KeyCache {
    inner: RwLock<Inner>,
    refreshing: tokio::sync::Mutex<()>,
    cfg: Config,
    http: reqwest::Client,
}

impl KeyCache {
    pub(crate) fn new(cfg: Config, http: reqwest::Client) -> Self {
        Self {
            inner: RwLock::new(Inner { keys: Vec::new(), fetched_at: None, last_err: None }),
            refreshing: tokio::sync::Mutex::new(()),
            cfg,
            http,
        }
    }

    /// Returns the cached keys. Never fetches inline; a stale set is returned
    /// as-is because a stale key still verifies a valid token correctly.
    pub(crate) async fn get(self: &Arc<Self>) -> Result<Vec<CachedKey>, Error> {
        let (keys, fetched_at, last_err) = {
            let g = self.inner.read().await;
            (g.keys.clone(), g.fetched_at, g.last_err.clone())
        };

        let Some(at) = fetched_at else {
            // Cold and never successfully fetched. Kick off a refresh but do
            // not wait for it.
            self.spawn_refresh();
            return Err(Error::NoKeys(last_err.unwrap_or_default()));
        };

        let age = at.elapsed();
        if age > self.cfg.jwks_refresh {
            self.spawn_refresh(); // stale-while-revalidate
        }
        if let Some(max) = self.cfg.jwks_max_stale {
            if age > max {
                return Err(Error::KeysTooStale { age, limit: max });
            }
        }
        Ok(keys)
    }

    fn spawn_refresh(self: &Arc<Self>) {
        let me = Arc::clone(self);
        tokio::spawn(async move { me.refresh().await });
    }

    pub(crate) async fn refresh(self: &Arc<Self>) {
        // Only one refresh at a time; the rest simply return.
        let Ok(_guard) = self.refreshing.try_lock() else { return };
        if let Err(e) = self.fetch().await {
            let msg = e.to_string();
            self.inner.write().await.last_err = Some(msg.clone());
            if let Some(cb) = &self.cfg.on_error {
                cb(&msg);
            }
        }
    }

    pub(crate) async fn fetch(&self) -> Result<(), Error> {
        let body = self.get_with_fallback("/.well-known/jwks.json").await?;
        let set: JwkSet = serde_json::from_slice(&body).map_err(|e| Error::Jwks(e.to_string()))?;

        if set.keys.is_empty() {
            // Never replace a working key set with an empty one.
            return Err(Error::Jwks("jwks contained no keys".into()));
        }

        let mut out = Vec::with_capacity(set.keys.len());
        for k in set.keys {
            if !k.crv.is_empty() && k.crv != "Ed25519" {
                continue; // authsvc signs with EdDSA only
            }
            let key = DecodingKey::from_ed_components(&k.x)
                .map_err(|e| Error::Jwks(format!("key {}: {e}", k.kid)))?;
            out.push(CachedKey { kid: k.kid, key: Arc::new(key) });
        }
        if out.is_empty() {
            return Err(Error::Jwks("no usable Ed25519 keys in jwks".into()));
        }

        let mut g = self.inner.write().await;
        g.keys = out;
        g.fetched_at = Some(Instant::now());
        g.last_err = None;
        Ok(())
    }

    /// Tries base_url, then fallback_url on a connection error or 5xx.
    /// A 4xx is a real answer and is not retried against the fallback.
    async fn get_with_fallback(&self, path: &str) -> Result<Vec<u8>, Error> {
        let primary = self.get_once(&format!("{}{}", self.cfg.base_url, path)).await;
        match primary {
            Ok(b) => Ok(b),
            Err(e) => {
                let Some(fb) = &self.cfg.fallback_url else { return Err(e) };
                if !e.should_fail_over() {
                    return Err(e);
                }
                self.get_once(&format!("{fb}{path}")).await
            }
        }
    }

    async fn get_once(&self, url: &str) -> Result<Vec<u8>, Error> {
        let resp = self
            .http
            .get(url)
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .map_err(|e| Error::Transport(e.to_string()))?;

        let status = resp.status();
        let body = resp.bytes().await.map_err(|e| Error::Transport(e.to_string()))?;
        if !status.is_success() {
            return Err(Error::Status { status: status.as_u16(), body: String::from_utf8_lossy(&body).into_owned() });
        }
        Ok(body.to_vec())
    }
}

/// Algorithm authsvc signs with.
pub(crate) const ALG: Algorithm = Algorithm::EdDSA;
