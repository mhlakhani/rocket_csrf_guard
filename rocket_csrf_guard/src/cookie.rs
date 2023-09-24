use crate::{
    util::secure_id, CsrfCheckProof, CsrfTokenVerificationError, CsrfTokenVerifier,
    WithUserProvidedCsrfToken,
};

use rocket::{
    http::{Cookie, CookieJar, SameSite},
    request::{self, FromRequest, Request},
};
use serde::{Serialize, Serializer};

pub const DOUBLE_SUBMIT_CSRF_TOKEN_COOKIE_NAME: &str = "__Host-csrf-token";
pub const DOUBLE_SUBMIT_CSRF_TOKEN_EXPIRY_SECONDS: i64 = 600;
pub const DOUBLE_SUBMIT_CSRF_TOKEN_NONE_EXPIRY_SECONDS: i64 = 20;

// A stateless csrf token used for double submit cookies.
// Prefer using session ones where possible
// Note this does NOT implement serialize - you should set a new one each request
#[derive(Debug)]
pub struct DoubleSubmitCookieCsrfToken(String);

impl WithUserProvidedCsrfToken for DoubleSubmitCookieCsrfToken {
    fn csrf_token(&self) -> &str {
        &self.0
    }
}

#[async_trait::async_trait]
impl CsrfTokenVerifier for DoubleSubmitCookieCsrfToken {
    type Proof = CsrfCheckProof;
    type Error = CsrfTokenVerificationError;

    async fn verify(
        &self,
        token: &(dyn WithUserProvidedCsrfToken + Send + Sync),
    ) -> Result<Self::Proof, Self::Error> {
        if token.csrf_token() == self.0 {
            Ok(CsrfCheckProof::PassedCsrfChecks)
        } else {
            Err(CsrfTokenVerificationError::CsrfTokenMismatch)
        }
    }
}

#[async_trait::async_trait]
impl<'r> FromRequest<'r> for DoubleSubmitCookieCsrfToken {
    type Error = std::convert::Infallible;

    async fn from_request(request: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        let maybe_csrf_token = request
            .cookies()
            .get_private(DOUBLE_SUBMIT_CSRF_TOKEN_COOKIE_NAME)
            .map(|cookie| {
                let value = cookie.value().to_owned();
                // Drop cookie so we don't reuse it
                request.cookies().remove(cookie);
                value
            });
        maybe_csrf_token.map_or(request::Outcome::Forward(()), |csrf_token| {
            request::Outcome::Success(Self(csrf_token))
        })
    }
}

// Allows setting a double submit cookie and returning the value to set in a form.
#[derive(Debug)]
pub struct SetDoubleSubmitCookieCsrfTokenImpl<'r, const SS: i8, const EXPIRY: i64> {
    // Keep a reference to the cookie jar so we can create the cookie if this gets
    // serialized into a form
    cookies: &'r CookieJar<'r>,
    csrf_token: String,
}

const SAME_SITE_STRICT: i8 = 0;
const SAME_SITE_LAX: i8 = 1;
const SAME_SITE_NONE_DO_NOT_USE_UNLESS_YOU_ARE_SURE: i8 = 2;

impl<'r, const SS: i8, const EXPIRY: i64> SetDoubleSubmitCookieCsrfTokenImpl<'r, SS, EXPIRY> {
    pub fn set(&self) -> &str {
        let ss = match SS {
            SAME_SITE_LAX => SameSite::Lax,
            SAME_SITE_NONE_DO_NOT_USE_UNLESS_YOU_ARE_SURE => SameSite::None,
            _ => SameSite::Strict,
        };
        let cookie = Cookie::build(
            DOUBLE_SUBMIT_CSRF_TOKEN_COOKIE_NAME,
            self.csrf_token.clone(),
        )
        .max_age(rocket::time::Duration::seconds(EXPIRY))
        .same_site(ss)
        .secure(true)
        .finish();
        self.cookies.add_private(cookie);
        &self.csrf_token
    }
}

impl<'r, const SS: i8, const EXPIRY: i64> Serialize
    for SetDoubleSubmitCookieCsrfTokenImpl<'r, SS, EXPIRY>
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.set())
    }
}

#[async_trait::async_trait]
impl<'r, const SS: i8, const EXPIRY: i64> FromRequest<'r>
    for SetDoubleSubmitCookieCsrfTokenImpl<'r, SS, EXPIRY>
{
    type Error = std::convert::Infallible;

    async fn from_request(request: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        let maybe_csrf_token = secure_id(16);
        maybe_csrf_token.map_or(request::Outcome::Forward(()), |csrf_token| {
            request::Outcome::Success(Self {
                cookies: request.cookies(),
                csrf_token,
            })
        })
    }
}

pub type SetDoubleSubmitCookieCsrfToken<'r> = SetDoubleSubmitCookieCsrfTokenImpl<
    'r,
    SAME_SITE_STRICT,
    DOUBLE_SUBMIT_CSRF_TOKEN_EXPIRY_SECONDS,
>;
pub type SetLaxDoubleSubmitCookieCsrfToken<'r> =
    SetDoubleSubmitCookieCsrfTokenImpl<'r, SAME_SITE_LAX, DOUBLE_SUBMIT_CSRF_TOKEN_EXPIRY_SECONDS>;

#[allow(non_camel_case_types)]
pub type SetNoneDoubleSubmitCookieCsrfToken_DO_NOT_USE_UNLESS_YOU_ARE_SURE<'r> =
    SetDoubleSubmitCookieCsrfTokenImpl<
        'r,
        SAME_SITE_NONE_DO_NOT_USE_UNLESS_YOU_ARE_SURE,
        DOUBLE_SUBMIT_CSRF_TOKEN_NONE_EXPIRY_SECONDS,
    >;
