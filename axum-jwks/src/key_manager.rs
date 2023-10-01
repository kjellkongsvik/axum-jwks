use std::sync::Arc;

use crate::key_store::{Jwk, JwksError};
use crate::{KeyStore, TokenError};
use jsonwebtoken::{decode, decode_header, TokenData};
use serde::de::DeserializeOwned;

use tokio::sync::RwLock;
use tokio::time::Instant;
use tokio::time::{sleep, Duration};
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
    /// Create a new KeyManager that fetches jwks into a KeyStore from an authority
    ///
    /// authority: either url of an openid_configuration or a jwks_url
    ///
    /// audience: to be check against the `aud` claim
    ///
    /// By default it only fetches jwks once
    pub fn new(authority: String, audience: String) -> Self {
        Self {
            authority,
            audience,
            minimal_interval: None,
            key_store: Arc::new(RwLock::new(KeyStore::default())),
            client: reqwest::Client::default(),
        }
    }

    /// When validating a token, update the KeyStore if kid not found
    ///
    /// Do not update more often than `interval`
    ///
    pub fn with_minimal_update_interval(mut self, interval: u64) -> Self {
        self.minimal_interval = Some(Duration::from_secs(interval));
        self
    }

    /// Periodically update the KeyStore every `interval`
    ///
    pub fn with_periodical_update(self, interval: u64) -> Self {
        let key_store = self.key_store.clone();
        let url = self.authority.clone();
        let audience = self.audience.clone();
        let client = self.client.clone();
        tokio::spawn(async move {
            let duration = Duration::from_secs(interval);
            loop {
                sleep(duration).await;
                {
                    let mut ks = key_store.write().await;
                    match KeyStore::new(&client, &url, &audience).await {
                        Ok(new_ks) => {
                            info!("Periodically updated jwks");
                            *ks = new_ks
                        }
                        Err(e) => error!(?e, "Could not update jwks from: {}", url),
                    }
                }
            }
        });
        self
    }

    pub fn with_client(mut self, client: reqwest::Client) -> Self {
        self.client = client;
        self
    }

    pub async fn update(self) -> Result<Self, JwksError> {
        {
            let mut ks = self.key_store.write().await;
            *ks = KeyStore::new(&self.client, &self.authority, &self.audience).await?;
        }
        Ok(self)
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

        let key = self.get_key(kid).await?;

        let decoded_token: TokenData<T> =
            decode(token, &key.decoding, &key.validation).map_err(|error| {
                debug!(?error, "Token is malformed or does not pass validation.");
                TokenError::Invalid(error)
            })?;

        Ok(decoded_token)
    }

    async fn get_key(&self, kid: &str) -> Result<Jwk, TokenError> {
        let mut key = None;
        {
            let ks = self.key_store.read().await;
            key = ks.keys.get(kid);
        }
        if key.is_none() {
            let mut ks = self.key_store.write().await;
            if let Some(minimal_interval) = self.minimal_interval {
                if ks.last_updated + minimal_interval < Instant::now() {
                    match KeyStore::new(&self.client, &self.authority, &self.audience).await {
                        Ok(new_ks) => {
                            info!("Updated jwks from: {}", &self.authority);
                            *ks = new_ks
                        }
                        Err(e) => error!(?e, "Could not update jwks from: {}", self.authority),
                    }
                }
            }
            key = ks.keys.get(kid);
        }
        match key {
            Some(k) => Ok(k.clone()),
            _ => {
                debug!(%kid, "Token refers to an unknown key.");
                Err(TokenError::UnknownKeyId(kid.to_owned()))
            }
        }
    }
}
