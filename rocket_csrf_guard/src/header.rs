use crate::{
    token::WithUserProvidedCsrfToken, util::set_proof_in_cache, verifier::CsrfTokenVerifier,
};

use rocket::{
    http::Status,
    request::{self, FromRequest, Request},
};
use serde::Serialize;

const CSRF_HEADER_NAME: &str = "X-CSRF-Token";

// Errors when doing csrf checks
#[derive(Debug)]
pub enum CheckCsrfProtectionHeaderError {
    NoVerifierFound,
    NoHeaderPresent,
    CsrfTokenVerificationError,
}

// Wrapper type to enable csrf protection from header values
pub struct CsrfTokenSourcedFromHeader<'r>(&'r str);

impl<'r> WithUserProvidedCsrfToken for CsrfTokenSourcedFromHeader<'r> {
    fn csrf_token(&self) -> &str {
        self.0
    }
}

// A wrapper which verifies that a request has passed CSRF checks via checking for the headers
#[derive(Debug, Serialize)]
pub struct CheckCsrfProtectionHeader<V>(std::marker::PhantomData<V>);

#[async_trait::async_trait]
impl<'r, V> FromRequest<'r> for CheckCsrfProtectionHeader<V>
where
    V: CsrfTokenVerifier + FromRequest<'r> + Send + Sync,
{
    type Error = CheckCsrfProtectionHeaderError;

    async fn from_request(request: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        let verifier = match request.guard::<V>().await {
            request::Outcome::Success(verifier) => verifier,
            request::Outcome::Failure((status, _)) => {
                return request::Outcome::Failure((
                    status,
                    CheckCsrfProtectionHeaderError::NoVerifierFound,
                ))
            }
            request::Outcome::Forward(f) => return request::Outcome::Forward(f),
        };
        let token = request.headers().get_one(CSRF_HEADER_NAME);
        match token {
            Some(token) => (verifier.verify(&CsrfTokenSourcedFromHeader(token)).await).map_or(
                request::Outcome::Failure((
                    Status::Forbidden,
                    CheckCsrfProtectionHeaderError::CsrfTokenVerificationError,
                )),
                |proof| {
                    set_proof_in_cache(request, proof);
                    request::Outcome::Success(Self(std::marker::PhantomData))
                },
            ),
            None => request::Outcome::Failure((
                Status::Forbidden,
                CheckCsrfProtectionHeaderError::NoHeaderPresent,
            )),
        }
    }
}
