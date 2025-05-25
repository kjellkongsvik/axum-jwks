use std::{collections::HashMap, str::FromStr};

use jsonwebtoken::{
    decode, decode_header,
    jwk::{self, AlgorithmParameters, KeyAlgorithm},
    DecodingKey, TokenData, Validation,
};
use serde::de::DeserializeOwned;
use thiserror::Error;
use tracing::{debug, info, warn};

use crate::TokenError;

/// A container for a set of JWT decoding keys.
///
/// The container can be used to validate any JWT that identifies a known key
/// through the `kid` attribute in the token's header.
#[derive(Clone, Default)]
pub struct Jwks {
    keys: HashMap<String, Jwk>,
}

impl Jwks {
    pub async fn from_jwks_url(
        jwks_uri: &str,
        audience: Option<String>,
        alg: Option<jsonwebtoken::Algorithm>,
        client: &reqwest::Client,
    ) -> Result<Self, JwksError> {
        debug!(%jwks_uri, "Fetching JSON Web Key Set.");
        let jwks: jwk::JwkSet = client.get(jwks_uri).send().await?.json().await?;
        info!(
            %jwks_uri,
            count = jwks.keys.len(),
            "Successfully pulled JSON Web Key Set."
        );

        Self::from_jwk_set(jwks, audience, alg)
    }

    ///
    /// # Arguments
    /// * `jwk_set` - The pre-fetched JWKs
    /// * `audience` - The identifier of the consumer of the JWT. This will be
    ///   matched against the `aud` claim from the token.
    /// * `alg` - The alg to use if not specified in JWK
    ///
    /// # Return Value
    /// The information needed to decode JWTs using any of the keys specified in
    /// the authority's JWKS.
    fn from_jwk_set(
        jwk_set: jwk::JwkSet,
        audience: Option<String>,
        alg: Option<jsonwebtoken::Algorithm>,
    ) -> Result<Self, JwksError> {
        let mut keys = HashMap::new();
        let to_supported_alg = |key_algorithm: Option<KeyAlgorithm>| match key_algorithm {
            Some(key_alg) => jsonwebtoken::Algorithm::from_str(key_alg.to_string().as_str()).ok(),
            _ => None,
        };

        for jwk in jwk_set.keys {
            if let Some(key_alg) = to_supported_alg(jwk.common.key_algorithm).or(alg) {
                let kid = jwk.common.key_id.ok_or(JwkError::MissingKeyId)?;
                match &jwk.algorithm {
                    AlgorithmParameters::RSA(rsa) => {
                        let decoding_key = DecodingKey::from_rsa_components(&rsa.n, &rsa.e)
                            .map_err(|err| JwkError::DecodingError {
                                key_id: kid.clone(),
                                error: err,
                            })?;
                        let mut validation = Validation::new(key_alg);
                        if let Some(ref audience) = audience {
                            validation.set_audience(&[audience.to_string()]);
                        } else {
                            validation.validate_aud = false;
                        }
                        keys.insert(
                            kid,
                            Jwk {
                                decoding: decoding_key,
                                validation,
                            },
                        );
                    }
                    other => {
                        return Err(JwkError::UnexpectedAlgorithm {
                            key_id: kid,
                            algorithm: other.to_owned(),
                        }
                        .into())
                    }
                }
            } else {
                warn!(
                    "JWK key algorithm {:?} is not supported. Tokens signed by that key will not be accepted.",
                    jwk.common.key_algorithm
                )
            }
        }

        Ok(Self { keys })
    }

    pub fn validate_claims<T>(&self, token: &str) -> Result<TokenData<T>, TokenError>
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

        let key = self.keys.get(kid).ok_or_else(|| {
            debug!(%kid, "Token refers to an unknown key.");

            TokenError::UnknownKeyId(kid.to_owned())
        })?;

        let decoded_token: TokenData<T> =
            decode(token, &key.decoding, &key.validation).map_err(|error| {
                debug!(?error, "Token is malformed or does not pass validation.");

                TokenError::Invalid(error)
            })?;

        Ok(decoded_token)
    }
}

#[derive(Clone)]
struct Jwk {
    decoding: DecodingKey,
    validation: Validation,
}

/// An error with the overall set of JSON Web Keys.
#[derive(Debug, Error)]
pub enum JwksError {
    /// There was an error fetching the OIDC or JWKS config from
    /// the specified authority.
    #[error("could not fetch config from authority: {0}")]
    FetchError(#[from] reqwest::Error),

    /// An error with an individual key caused the processing of the JWKS to
    /// fail.
    #[error("there was an error with an individual key: {0}")]
    KeyError(#[from] JwkError),

    #[error("the provided algorithm from oidc is invalid or empty: {0}")]
    InvalidAlgorithm(#[from] jsonwebtoken::errors::Error),
}

/// An error with a specific key from a JWKS.
#[derive(Debug, Error)]
pub enum JwkError {
    /// There was an error constructing the decoding key from the RSA components
    /// provided by the key.
    #[error("could not construct a decoding key for {key_id:?}: {error:?}")]
    DecodingError {
        key_id: String,
        error: jsonwebtoken::errors::Error,
    },

    /// The key does not specify an algorithm to use.
    #[error("the key {key_id:?} does not specify an algorithm")]
    MissingAlgorithm { key_id: String },

    /// The key is missing the `kid` attribute.
    #[error("the key is missing the `kid` attribute")]
    MissingKeyId,

    /// The key uses an unexpected algorithm type.
    #[error("the key {key_id:?} uses a non-RSA algorithm {algorithm:?}")]
    UnexpectedAlgorithm {
        algorithm: AlgorithmParameters,
        key_id: String,
    },
}
