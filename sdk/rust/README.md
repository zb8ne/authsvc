# authsdk (Rust)

Client for [authsvc](https://github.com/zb8ne/authsvc).

```toml
[dependencies]
authsdk = { git = "https://github.com/zb8ne/authsvc", tag = "sdk/rust/v0.1.0" }
```

```rust
let auth = authsdk::Client::new(
    authsdk::Config::new("https://auth.grindlog.lol", "myapp")
        .client_secret(std::env::var("AUTH_CLIENT_SECRET")?)
        .sign_in_url("https://myapp.test/signin"),
)?;

// Local verification — no network call, no dependency on authsvc being up.
let user = auth.verify(bearer_token).await?;
if user.has_role("admin") { /* ... */ }

// OAuth: send the browser here, then exchange the code server-side.
let url = auth.start_url("google", "https://myapp.test/auth/callback", &state);
let session = auth.exchange(&code).await?;
```

`verify` never touches the network: keys come from a JWKS cached in the
background with stale-while-revalidate. An authsvc outage cannot take your app
down. `Error::is_key_problem()` distinguishes "we can't verify anything right
now" (answer 503) from "this token is bad" (answer 401).

Cached keys are trusted for at most `DEFAULT_JWKS_MAX_STALE` (7 days) once
refreshes start failing, which bounds how long a compromised signing key stays
trusted. Pass `.jwks_max_stale(None)` to disable that.

`CallbackError::message()` gives showable wording for a failed OAuth callback —
notably `manual_link_required`, which real users hit when they registered with a
password and later click "Sign in with Google".
