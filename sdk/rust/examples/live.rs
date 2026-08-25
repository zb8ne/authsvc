//! Verifies a real token from the live service, end to end.
//!
//!   cargo run --example live -- "<access_token>"

use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let token = std::env::args().nth(1).expect("usage: live <access_token>");

    let auth = authsdk::Client::new(
        authsdk::Config::new("https://auth.grindlog.lol", "demoapp").sign_in_url("https://demoapp.test/signin"),
    )?;
    auth.wait_ready(Duration::from_secs(10)).await?;

    match auth.verify(&token).await {
        Ok(u) => println!("OK  id={} email={} verified={} roles={:?}", u.id, u.email, u.email_verified, u.roles),
        Err(e) => println!("REJECTED  {e}"),
    }

    // A token for another audience must not verify here.
    let other = authsdk::Client::new(authsdk::Config::new("https://auth.grindlog.lol", "smoketest"))?;
    other.wait_ready(Duration::from_secs(10)).await?;
    match other.verify(&token).await {
        Ok(_) => println!("BAD: verified against the wrong audience"),
        Err(_) => println!("OK  correctly rejected for a different audience"),
    }
    Ok(())
}
