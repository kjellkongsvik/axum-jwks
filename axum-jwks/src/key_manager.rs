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
    jwks_uri: String,
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
        let jwks = Jwks::from_jwks_url(
            &self.jwks_uri,
            self.audience.clone(),
            self.alg,
            &self.client,
        )
        .await?;

        let last_updated = Some(Instant::now());
        let mut key_store = self.key_store.write().await;
        *key_store = KeyStore { last_updated, jwks };

        info!("Updated jwks from: {}", &self.jwks_uri);
        Ok(())
    }
}

#[derive(Clone, Default)]
pub struct KeyManagerBuilder {
    url: String,
    audience: Option<String>,
    alg: Option<jsonwebtoken::Algorithm>,
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
            alg: None,
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

    pub fn algorithm(mut self, alg: jsonwebtoken::Algorithm) -> Self {
        self.alg = Some(alg);
        self
    }

    /// Build KeyManager with empty key_store
    pub async fn build(self) -> KeyManager {
        let mut alg = self.alg;
        let mut jwks_uri = self.url.clone();
        let r = self
            .client
            .get(&self.url)
            .send()
            .await
            .expect("Valid url for either jwks_uri or well_known oidc");

        if let Ok(oidc) = r.json::<Oid>().await {
            alg = oidc.id_token_signing_alg_values_supported.and_then(|a| {
                a.first()
                    .and_then(|s| jsonwebtoken::Algorithm::from_str(s).ok())
            });
            jwks_uri = oidc.jwks_uri;
        };

        KeyManager {
            jwks_uri,
            audience: self.audience,
            alg,
            update_interval: self.update_interval,
            key_store: Arc::new(RwLock::new(KeyStore::default())),
            client: self.client,
        }
    }
}
