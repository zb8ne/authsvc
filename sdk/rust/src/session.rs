use std::collections::HashSet;
use std::time::Duration;

use jsonwebtoken::{decode, decode_header, Validation};
use serde::{Deserialize, Serialize};

use crate::{keys::ALG, Client, Error};

/// What an app receives after a successful login or refresh. The refresh token
/// is the app's to store — typically in its own httpOnly cookie.
#[derive(Debug, Clone, Deserialize)]
pub struct Session {
    pub access_token: String,
    pub refresh_token: String,
    #[serde(default)]
    pub token_type: String,
    #[serde(default)]
    pub expires_in: i64,
    pub user: UserInfo,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UserInfo {
    pub id: String,
    pub email: String,
    #[serde(default)]
    pub email_verified: bool,
}

/// The verified caller, decoded from an access token.
#[derive(Debug, Clone)]
pub struct User {
    pub id: String,
    pub email: String,
    pub email_verified: bool,
    pub roles: Vec<String>,
    pub session_id: String,
    pub expires_at: i64,
}

impl User {
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|r| r == role)
    }
    /// True when the user holds any of the named roles.
    pub fn has_any_role(&self, roles: &[&str]) -> bool {
        roles.iter().any(|r| self.has_role(r))
    }
}

#[derive(Debug, Deserialize)]
struct Claims {
    sub: String,
    #[serde(default)]
    email: String,
    #[serde(default)]
    email_verified: bool,
    #[serde(default)]
    sid: String,
    #[serde(default)]
    roles: Vec<String>,
    exp: i64,
}

#[derive(Serialize)]
struct ExchangeReq<'a> {
    code: &'a str,
    client_id: &'a str,
    client_secret: &'a str,
}

#[derive(Serialize)]
struct RefreshReq<'a> {
    refresh_token: &'a str,
}

#[derive(Serialize)]
struct LoginReq<'a> {
    client_id: &'a str,
    email: &'a str,
    password: &'a str,
}

impl Client {
    /// Validates an access token locally and returns the user it describes.
    ///
    /// No network call. Signature, issuer, audience, and expiry are all checked
    /// against the cached JWKS.
    pub async fn verify(&self, raw: &str) -> Result<User, Error> {
        let keys = self.keys.get().await?;

        let header = decode_header(raw).map_err(|e| Error::Token(e.to_string()))?;

        let mut validation = Validation::new(ALG);
        validation.set_issuer(&[self.cfg.issuer.as_str()]);
        validation.set_audience(&[self.cfg.audience.as_str()]);
        validation.required_spec_claims = HashSet::from(["exp".to_string(), "aud".to_string(), "iss".to_string()]);

        // Prefer the key the token names; fall back to trying all published
        // keys, which is what makes rotation seamless.
        let ordered: Vec<_> = match &header.kid {
            Some(kid) => keys.iter().filter(|k| &k.kid == kid).chain(keys.iter().filter(|k| &k.kid != kid)).collect(),
            None => keys.iter().collect(),
        };

        let mut last = String::from("no keys tried");
        for k in ordered {
            match decode::<Claims>(raw, &k.key, &validation) {
                Ok(t) => {
                    let c = t.claims;
                    return Ok(User {
                        id: c.sub,
                        email: c.email,
                        email_verified: c.email_verified,
                        roles: c.roles,
                        session_id: c.sid,
                        expires_at: c.exp,
                    });
                }
                Err(e) => last = e.to_string(),
            }
        }
        Err(Error::Token(last))
    }

    /// Trades an OAuth authorization code for a session. Must run on your
    /// backend: it presents the client secret.
    pub async fn exchange(&self, code: &str) -> Result<Session, Error> {
        let secret = self.cfg.client_secret.as_deref().ok_or(Error::MissingSecret)?;
        self.post(
            "/v1/token/exchange",
            &ExchangeReq { code, client_id: &self.cfg.client_id, client_secret: secret },
        )
        .await
    }

    /// Rotates a refresh token. The returned token replaces the old one:
    /// authsvc revokes the whole session family if a spent token is presented
    /// again.
    pub async fn refresh(&self, refresh_token: &str) -> Result<Session, Error> {
        self.post("/v1/token/refresh", &RefreshReq { refresh_token }).await
    }

    /// Authenticates with email and password.
    pub async fn login(&self, email: &str, password: &str) -> Result<Session, Error> {
        self.post("/v1/auth/login", &LoginReq { client_id: &self.cfg.client_id, email, password }).await
    }

    async fn post<T: Serialize, R: for<'de> Deserialize<'de>>(&self, path: &str, body: &T) -> Result<R, Error> {
        let primary = self.post_once(&format!("{}{}", self.cfg.base_url, path), body).await;
        let bytes = match primary {
            Ok(b) => b,
            Err(e) => match (&self.cfg.fallback_url, e.should_fail_over()) {
                (Some(fb), true) => self.post_once(&format!("{fb}{path}"), body).await?,
                _ => return Err(e),
            },
        };
        serde_json::from_slice(&bytes).map_err(|e| Error::Transport(e.to_string()))
    }

    async fn post_once<T: Serialize>(&self, url: &str, body: &T) -> Result<Vec<u8>, Error> {
        let resp = self
            .http
            .post(url)
            .json(body)
            .timeout(Duration::from_secs(15))
            .send()
            .await
            .map_err(|e| Error::Transport(e.to_string()))?;

        let status = resp.status();
        let bytes = resp.bytes().await.map_err(|e| Error::Transport(e.to_string()))?;
        if !status.is_success() {
            return Err(Error::Status { status: status.as_u16(), body: String::from_utf8_lossy(&bytes).into_owned() });
        }
        Ok(bytes.to_vec())
    }
}

/// An error code authsvc returns to your `redirect_uri`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallbackError {
    /// The email on the provider account already belongs to a user and linking
    /// automatically would not be safe. A normal thing for real users to hit:
    /// they registered with a password, then clicked "Sign in with Google".
    ManualLinkRequired,
    AlreadyLinked,
    AccessDenied,
    AccountDisabled,
    ExchangeFailed,
    MissingCode,
    LoginFailed,
    Other(String),
}

impl CallbackError {
    pub fn parse(code: &str) -> Self {
        match code {
            "manual_link_required" => Self::ManualLinkRequired,
            "already_linked" => Self::AlreadyLinked,
            "access_denied" => Self::AccessDenied,
            "account_disabled" => Self::AccountDisabled,
            "exchange_failed" => Self::ExchangeFailed,
            "missing_code" => Self::MissingCode,
            "login_failed" => Self::LoginFailed,
            other => Self::Other(other.to_string()),
        }
    }

    /// Wording suitable for showing to the person who hit it: what happened,
    /// then what to do next.
    pub fn message(&self) -> (&'static str, &'static str) {
        match self {
            Self::ManualLinkRequired => (
                "You already have an account with this email",
                "Sign in with your password, then connect this account from your settings. \
                 We don't link them automatically because we can't yet confirm both accounts belong to you.",
            ),
            Self::AlreadyLinked => (
                "That account is already connected to someone else",
                "This provider account is linked to a different user. Sign in with that account, \
                 or disconnect it there first.",
            ),
            Self::AccessDenied => (
                "Sign-in was cancelled",
                "You can try again, or sign in with your email and password instead.",
            ),
            Self::AccountDisabled => ("This account is disabled", "Get in touch if you think that's a mistake."),
            _ => ("Sign-in didn't complete", "Something went wrong on our end. Please try again."),
        }
    }

    /// False when retrying the same login would fail identically — looping the
    /// user through it is the dead end worth avoiding.
    pub fn retryable(&self) -> bool {
        !matches!(self, Self::ManualLinkRequired | Self::AlreadyLinked | Self::AccountDisabled)
    }
}
