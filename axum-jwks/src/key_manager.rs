use std::str::FromStr;
use std::sync::Arc;

use crate::jwks::JwksError;
use crate::{Jwks, TokenError};
use jsonwebtoken::TokenData;
use serde::de::DeserializeOwned;

use serde::Deserialize;
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
    url: String,
    audience: Option<String>,
    alg: Option<jsonwebtoken::Algorithm>,
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
                debug!("kid={id}, not found, should jwks be updated?")
            }
            Err(e) => return Err(e),
            Ok(d) => return Ok(d),
        }
        self.ensure_jwks_is_updated().await?;
        self.key_store.read().await.jwks.validate_claims(token)
    }

    async fn ensure_jwks_is_updated(&self) -> Result<(), TokenError> {
        {
            let key_store = self.key_store.read().await;
            if let Some(last_updated) = key_store.last_updated {
                if last_updated + self.update_interval > Instant::now() {
                    debug!("Will not be updating jwks yet");
                    return Ok(());
                } else {
                    debug!("jwks will be updated now");
                }
            } else {
                debug!("Initial jwks update");
            }
        }
        self.update_jwks().await?;
        Ok(())
    }

    pub async fn update_jwks(&self) -> Result<(), JwksError> {
        let jwks =
            Jwks::from_jwks_url(&self.client, &self.url, self.audience.clone(), self.alg).await?;

        let last_updated = Some(Instant::now());
        let mut key_store = self.key_store.write().await;
        *key_store = KeyStore { last_updated, jwks };

        info!("Updated jwks from: {}", &self.url);
        Ok(())
    }
}

#[derive(Clone, Default)]
pub struct KeyManagerBuilder {
    url: String,
    audience: Option<String>,
    update_interval: Duration,
    client: reqwest::Client,
}

#[derive(Deserialize)]
struct Oid {
    jwks_uri: String,
    id_token_signing_alg_values_supported: Option<Vec<String>>,
}

impl KeyManagerBuilder {
    /// Create a new KeyManager that can fetch jwks from an authority
    /// `url`: either url of an openid_configuration or a jwks_url
    /// `audience`: to be checked against the `aud` claim
    pub fn new(url: String, audience: Option<String>) -> Self {
        Self {
            url,
            audience,
            update_interval: Duration::from_secs(3600),
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

    async fn from_url(
        &self,
        url: &str,
    ) -> Result<(String, Option<jsonwebtoken::Algorithm>), JwksError> {
        if let Ok(oidc) = self.client.get(url).send().await?.json::<Oid>().await {
            let alg = match &oidc.id_token_signing_alg_values_supported {
                Some(algs) => match algs.first() {
                    Some(s) => Some(jsonwebtoken::Algorithm::from_str(s)?),
                    _ => None,
                },
                _ => None,
            };
            return Ok((oidc.jwks_uri, alg));
        } else {
            return Ok((url.to_owned(), None));
        }
    }

    /// Build KeyManager with empty key_store
    pub async fn build(self) -> KeyManager {
        let (url, alg) = self.from_url(&self.url).await.unwrap();
        KeyManager {
            url,
            audience: self.audience,
            alg,
            update_interval: self.update_interval,
            key_store: Arc::new(RwLock::new(KeyStore::default())),
            client: self.client,
        }
    }
}
