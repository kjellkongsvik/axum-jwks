use std::sync::Arc;

use crate::jwks::JwksError;
use crate::{Jwks, TokenError};
use jsonwebtoken::TokenData;
use serde::de::DeserializeOwned;

use tokio::sync::RwLock;

use tokio::time::{Duration, Instant};
use tracing::{debug, info};

#[derive(Clone, Default)]
struct KeyStore {
    last_updated: Option<Instant>,
    jwks: Jwks,
}

#[derive(Clone)]
pub struct KeyManager {
    authority: String,
    audience: Option<String>,
    update_interval: Duration,
    key_store: Arc<RwLock<KeyStore>>,
    client: reqwest::Client,
}

impl KeyManager {
    pub fn builder() -> KeyManagerBuilder {
        KeyManagerBuilder::default()
    }

    /// Validate the token, require claims in `T` to be present
    ///
    /// Updates `key_store` if empty or kid from token not present in `key_store`
    /// The `key_store`is only updated once every `update_interval`
    ///
    /// Verify correct `aud` and `exp`
    pub async fn validate_claims<T>(&self, token: &str) -> Result<TokenData<T>, TokenError>
    where
        T: DeserializeOwned,
    {
        match self.key_store.read().await.jwks.validate_claims(token) {
            Err(TokenError::UnknownKeyId(id)) => {
                info!("kid={id}, not found, might update jwks")
            }
            Err(e) => return Err(e),
            Ok(d) => return Ok(d),
        }
        self.ensure_updated().await?;
        self.key_store.read().await.jwks.validate_claims(token)
    }

    async fn ensure_updated(&self) -> Result<(), TokenError> {
        {
            let key_store = self.key_store.read().await;
            if let Some(last_updated) = key_store.last_updated {
                if last_updated + self.update_interval > Instant::now() {
                    debug!("Not updating jwks yet");
                    return Ok(());
                } else {
                    debug!("jwks has not been updated in a while");
                }
            } else {
                debug!("Initial jwks update");
            }
        }
        self.update().await?;
        Ok(())
    }

    async fn update(&self) -> Result<(), JwksError> {
        let mut key_store = self.key_store.write().await;
        let jwks =
            Jwks::from_oidc_url_with_client(&self.client, &self.authority, self.audience.clone())
                .await?;

        let last_updated = Some(Instant::now());
        *key_store = KeyStore { last_updated, jwks };

        info!("Updated jwks from: {}", &self.authority);
        Ok(())
    }
}

#[derive(Clone, Default)]
pub struct KeyManagerBuilder {
    authority: String,
    audience: Option<String>,
    update_interval: Duration,
    key_store: Arc<RwLock<KeyStore>>,
    client: reqwest::Client,
}

impl KeyManagerBuilder {
    /// Create a new KeyManager that can fetch jwks from an authority
    /// `authority`: either url of an openid_configuration or a jwks_url
    /// `audience`: to be checked against the `aud` claim
    pub fn new(authority: String, audience: Option<String>) -> Self {
        Self {
            authority,
            audience,
            update_interval: Duration::from_secs(3600),
            key_store: Arc::new(RwLock::new(KeyStore::default())),
            client: reqwest::Client::default(),
        }
    }

    /// Do not update more often than `interval`
    pub fn update_interval(mut self, interval: Duration) -> Self {
        self.update_interval = interval;
        self
    }

    /// Enables usage with externally provided `client`
    pub fn client(mut self, client: reqwest::Client) -> Self {
        self.client = client;
        self
    }

    /// build KeyManager with empty key_store
    pub async fn build(self) -> KeyManager {
        KeyManager {
            authority: self.authority,
            audience: self.audience,
            update_interval: self.update_interval,
            key_store: self.key_store,
            client: self.client,
        }
    }
}
