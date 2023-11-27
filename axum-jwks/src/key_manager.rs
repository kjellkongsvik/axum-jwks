use std::sync::Arc;

use crate::key_store::JwksError;
use crate::{KeyStore, TokenError};
use jsonwebtoken::{decode, decode_header, TokenData};
use serde::de::DeserializeOwned;

use tokio::sync::RwLock;

use tokio::time::{sleep, Duration, Instant};
use tracing::{debug, error, info};

#[derive(Clone)]
pub struct KeyManager {
    authority: String,
    audience: String,
    minimal_interval: Option<Duration>,
    key_store: Arc<RwLock<KeyStore>>,
    client: reqwest::Client,
}

impl KeyManager {
    /// Create a new KeyManager that can fetch jwks from an authority
    /// `authority`: either url of an openid_configuration or a jwks_url
    /// `audience`: to be checked against the `aud` claim
    ///
    /// jwks is not initially fetched: Please see `update_now` function
    pub fn builder() -> KeyManagerBuilder {
        KeyManagerBuilder::default()
    }

    async fn update(&self) -> Result<(), JwksError> {
        let mut ks = self.key_store.write().await;
        *ks = KeyStore::new(&self.client, &self.authority, &self.audience).await?;
        info!("Updated jwks from: {}", &self.authority);
        Ok(())
    }
    /// Validate the token, require claims in `T` to be present
    ///
    /// Verify correct `aud` and `exp`
    pub async fn validate_claims<T>(&self, token: &str) -> Result<TokenData<T>, TokenError>
    where
        T: DeserializeOwned,
    {
        let header = decode_header(token).map_err(|error| {
            debug!(?error, "Received token with invalid header.");
            TokenError::InvalidHeader(error)
        })?;
        let kid = header.kid.as_ref().ok_or_else(|| {
            debug!(?header, "Header is missing the `kid` attribute.");
            TokenError::MissingKeyId
        })?;

        self.ensure_updated_keystore(kid).await?;

        let ks = self.key_store.read().await;
        let key = ks.keys.get(kid).ok_or_else(|| {
            debug!(%kid, "Token refers to an unknown key.");
            TokenError::UnknownKeyId(kid.to_owned())
        })?;

        decode(token, &key.decoding, &key.validation).map_err(|error| {
            debug!(?error, "Token is malformed or does not pass validation.");
            TokenError::Invalid(error)
        })
    }

    /// Update `self.key_store` if `kid` is missing
    /// Only update if it has not been updated within `self.minimal_interval`
    ///
    /// Requires internal lock on `self.key_store`:
    /// Take care to not create dead locks
    async fn ensure_updated_keystore(&self, kid: &str) -> Result<(), TokenError> {
        let mut outdated_ks = false;
        if let Some(minimal_interval) = self.minimal_interval {
            let ks = self.key_store.read().await;
            outdated_ks = ks.last_updated.is_none();
            // Assume `Instant::now` is more expensive than `keys.contains_key`
            if ks.keys.contains_key(kid) {
                if let Some(last_updated) = ks.last_updated {
                    if last_updated + minimal_interval < Instant::now() {
                        outdated_ks = true;
                    }
                }
            }
        }

        if outdated_ks {
            self.update().await?;
        }
        Ok(())
    }
}

#[derive(Clone, Default)]
pub struct KeyManagerBuilder {
    authority: String,
    audience: String,
    minimal_interval: Option<Duration>,
    key_store: Arc<RwLock<KeyStore>>,
    client: reqwest::Client,
}

impl KeyManagerBuilder {
    /// Create a new KeyManager that can fetch jwks from an authority
    /// `authority`: either url of an openid_configuration or a jwks_url
    /// `audience`: to be checked against the `aud` claim
    ///
    /// jwks is not initially fetched: Please see `update_now` function
    pub fn new(authority: String, audience: String) -> Self {
        Self {
            authority,
            audience,
            minimal_interval: None,
            key_store: Arc::new(RwLock::new(KeyStore::default())),
            client: reqwest::Client::default(),
        }
    }

    /// When validating a token: fetch updated jwks if kid not found
    ///
    /// Do not update more often than `interval`
    pub fn minimal_update_interval(mut self, interval: u64) -> Self {
        self.minimal_interval = Some(Duration::from_secs(interval));
        self
    }

    /// Periodically update the jwks every `interval`, including immediately
    pub fn periodical_update(self, interval: u64) -> Self {
        let key_store = self.key_store.clone();
        let url = self.authority.clone();
        let audience = self.audience.clone();
        let client = self.client.clone();
        tokio::spawn(async move {
            let duration = Duration::from_secs(interval);
            loop {
                match KeyStore::new(&client, &url, &audience).await {
                    Ok(new_ks) => {
                        let mut ks = key_store.write().await;
                        info!("Periodically updated jwks");
                        *ks = new_ks
                    }
                    Err(e) => error!(?e, "Could not update jwks from: {}", url),
                }
                sleep(duration).await;
            }
        });
        self
    }

    /// Enables usage with externally provided `client`
    pub fn client(mut self, client: reqwest::Client) -> Self {
        self.client = client;
        self
    }

    /// Fetch updated jwks now
    /// Required only if `with_periodical_update` or `with_minimal_update_interval` is not used
    pub async fn build(self) -> Result<KeyManager, JwksError> {
        let km = KeyManager {
            authority: self.authority,
            audience: self.audience,
            minimal_interval: self.minimal_interval,
            key_store: self.key_store,
            client: self.client,
        };
        km.update().await?;
        Ok(km)
    }
}
