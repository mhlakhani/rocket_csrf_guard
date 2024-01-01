use crate::token::WithUserProvidedCsrfToken;
use anyhow::Result;

/// A type that can verify whether a [`WithUserProvidedCsrfToken`] actually has a valid csrf token
/// Lets us be generic over session based or other csrf tokens
/// This trait is async, but we recommend you keep DB fetches out (use rocket request caching as in the examples)
/// or other mechanisms to keep things quick
/// The returned `Proof` will be set in the request local cache for other request guards to query
#[async_trait::async_trait]
pub trait CsrfTokenVerifier {
    type Proof: Send + Sync + 'static;
    type Error: Send + Sync;

    async fn verify(
        &self,
        token: &(dyn WithUserProvidedCsrfToken + Send + Sync),
    ) -> Result<Self::Proof, Self::Error>;
}

/// Trait for easily implementing a verifier when you know the expected token.
pub trait VerifierWithKnownExpectedToken {
    type Proof: Default + Send + Sync + 'static;

    fn expected_token(&self) -> &str;
}

/// Errors which can happen when verifying a CSRF token
#[derive(thiserror::Error, Debug)]
pub enum CsrfTokenVerificationError {
    /// The CSRF token did not match the expected token
    /// NOTE: The error message intentionally does not include what was expected
    /// to avoid bugs where the token gets returned to users.
    #[error("CSRF token did not match!")]
    CsrfTokenMismatch,
    /// For extensibility
    #[error("Unknown error: {0:?}")]
    Unknown(Box<dyn std::error::Error + Send + Sync>),
}

/// Implements [`CsrfTokenVerifier`] for any type implementing [`VerifierWithKnownExpectedToken`]
#[async_trait::async_trait]
impl<Proof, T> CsrfTokenVerifier for T
where
    Proof: Default + Send + Sync + 'static,
    T: VerifierWithKnownExpectedToken<Proof = Proof> + Send + Sync + 'static,
{
    type Proof = Proof;
    type Error = CsrfTokenVerificationError;

    async fn verify(
        &self,
        token: &(dyn WithUserProvidedCsrfToken + Send + Sync),
    ) -> Result<Self::Proof, Self::Error> {
        if token.csrf_token() == self.expected_token() {
            Ok(Self::Proof::default())
        } else {
            Err(CsrfTokenVerificationError::CsrfTokenMismatch)
        }
    }
}
