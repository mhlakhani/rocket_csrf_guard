use rocket::request::{FromRequest, Outcome, Request};

// Used for security checks etc.
// TODO: Document
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CsrfCheckProof {
    // This should ideally be tied to a request with a lifetime
    // but we don't want to carry around lifetimes everywhere
    // TODO: Try this out though at some point, maybe it's fine
    PassedCsrfChecks,
}

impl Default for CsrfCheckProof {
    fn default() -> Self {
        Self::PassedCsrfChecks
    }
}

// By default, consider this an unauthorized web request
// Users, if desired, need to run CSRF checks *before* this one and populate the cache
// TODO: Have an option which returns a forbidden instead of a Forward?
#[async_trait::async_trait]
impl<'r> FromRequest<'r> for CsrfCheckProof {
    type Error = std::convert::Infallible;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let cached: &Option<Self> = request.local_cache(|| None);

        cached
            .as_ref()
            .cloned()
            .map(Outcome::Success)
            .unwrap_or_else(|| Outcome::Forward(()))
    }
}
