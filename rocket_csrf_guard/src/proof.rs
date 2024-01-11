use rocket::request::{FromRequest, Outcome, Request};

/// A proof that a request has passed CSRF checks.
/// Useful for constructing secure by default frameworks, [as seen in this blogpost](https://mhlakhani.com/blog/2024/01/on-secure-by-default-frameworks/)
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CsrfCheckProof {
    /// The request has passed CSRF checks.
    /// This is the only valid value for this type.
    PassedCsrfChecks,
}

impl Default for CsrfCheckProof {
    fn default() -> Self {
        Self::PassedCsrfChecks
    }
}

/// By default, consider this an unauthorized web request
/// Users, if desired, need to run CSRF checks *before* this one and populate the cache
#[async_trait::async_trait]
impl<'r> FromRequest<'r> for CsrfCheckProof {
    type Error = std::convert::Infallible;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let cached: &Option<Self> = request.local_cache(|| None);

        cached
            .as_ref()
            .cloned()
            .map(Outcome::Success)
            .unwrap_or_else(|| Outcome::Forward(rocket::http::Status::InternalServerError))
    }
}
