use crate::{
    util::random_id, CsrfCheckProof, CsrfTokenVerificationError, CsrfTokenVerifier,
    WithUserProvidedCsrfToken,
};

use rocket::{
    http::{Cookie, CookieJar, SameSite},
    request::{FromRequest, Outcome, Request},
};
use serde::{Serialize, Serializer};

/// Default double submit cookie name.
pub const DOUBLE_SUBMIT_CSRF_TOKEN_COOKIE_NAME: &str = "__Host-csrf-token";

/// Default double submit cookie expiry time.
pub const DOUBLE_SUBMIT_CSRF_TOKEN_EXPIRY_SECONDS: i64 = 600;

/// Default expiry time for a double submit cookie set with [`rocket::http::SameSite::None`]
pub const DOUBLE_SUBMIT_CSRF_TOKEN_NONE_EXPIRY_SECONDS: i64 = 20;

/// CSRF protection using Double Submit cookies.
///
/// Provides a verifier to check a provided CSRF token against an expected value present in
/// a cookie which was previously set using [`SetDoubleSubmitCookieCsrfToken`]
///
/// Prefer using session based CSRF protection where possible.
#[derive(Debug)]
pub struct DoubleSubmitCookieCsrfToken(String);

/// Verifies that the received token matches the cookie.
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

/// Extracts the cookie from the request and drops it so it doesn't get reused.
#[async_trait::async_trait]
impl<'r> FromRequest<'r> for DoubleSubmitCookieCsrfToken {
    type Error = std::convert::Infallible;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let maybe_csrf_token = request
            .cookies()
            .get_private(DOUBLE_SUBMIT_CSRF_TOKEN_COOKIE_NAME)
            .map(|cookie| {
                let value = cookie.value().to_owned();
                // Drop cookie so we don't reuse it
                request.cookies().remove(cookie);
                value
            });
        maybe_csrf_token.map_or(Outcome::Forward(()), |csrf_token| {
            Outcome::Success(Self(csrf_token))
        })
    }
}

/// Sets a Double Submit cookie with the given expiry and SameSite setting.
///
/// Use this as a request guard so it sets the cookie in the returned response.
/// This type implements [`serde::Serialize`] so you can extract the value to display
/// it in a form or some other location so the client can pass it along in the request.
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
    /// Creates a cookie with the value of the token, and returns the value.
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

/// Sets the cookie and serializes the value into the output form.
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

/// Creates a random token which can be set as a cookie.
#[async_trait::async_trait]
impl<'r, const SS: i8, const EXPIRY: i64> FromRequest<'r>
    for SetDoubleSubmitCookieCsrfTokenImpl<'r, SS, EXPIRY>
{
    type Error = std::convert::Infallible;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let maybe_csrf_token = random_id(16);
        maybe_csrf_token.map_or(Outcome::Forward(()), |csrf_token| {
            Outcome::Success(Self {
                cookies: request.cookies(),
                csrf_token,
            })
        })
    }
}

/// Default [`DoubleSubmitCookieCsrfToken`] setting, using [`rocket::http::SameSite::Strict`] and an expiry of 10 minutes.
pub type SetDoubleSubmitCookieCsrfToken<'r> = SetDoubleSubmitCookieCsrfTokenImpl<
    'r,
    SAME_SITE_STRICT,
    DOUBLE_SUBMIT_CSRF_TOKEN_EXPIRY_SECONDS,
>;

/// Lax [`DoubleSubmitCookieCsrfToken`] setting, using [`rocket::http::SameSite::Lax`] and an expiry of 10 minutes.
pub type SetLaxDoubleSubmitCookieCsrfToken<'r> =
    SetDoubleSubmitCookieCsrfTokenImpl<'r, SAME_SITE_LAX, DOUBLE_SUBMIT_CSRF_TOKEN_EXPIRY_SECONDS>;

/// Insecure [`DoubleSubmitCookieCsrfToken`] setting, using [`rocket::http::SameSite::None`] and an expiry of 20 seconds.
/// Avoid this as much as possible.
#[allow(non_camel_case_types)]
pub type SetNoneDoubleSubmitCookieCsrfToken_DO_NOT_USE_UNLESS_YOU_ARE_SURE<'r> =
    SetDoubleSubmitCookieCsrfTokenImpl<
        'r,
        SAME_SITE_NONE_DO_NOT_USE_UNLESS_YOU_ARE_SURE,
        DOUBLE_SUBMIT_CSRF_TOKEN_NONE_EXPIRY_SECONDS,
    >;
