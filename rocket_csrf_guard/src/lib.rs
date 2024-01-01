//! Ergonomic CSRF protection for Rocket applications.
//!
//! The main macro [`with_csrf_token`] enables CSRF protection for a given [`rocket::form::Form`].
//! Slap on a double submit cookie or a session based CSRF token and you're good to go.
//! Look at the examples/ folder for more detailed examples of all the functionality in a test app.

mod cookie;
mod form;
mod header;
mod proof;
mod token;
mod util;
mod verifier;

#[cfg(test)]
extern crate rocket;
#[cfg(test)]
mod example_app;
#[cfg(test)]
mod tests;

/// Macro to enable CSRF protection for a given [`rocket::form::Form`].
///
/// By default, it will add a String field called `csrf_token` and implement
/// [`WithUserProvidedCsrfToken`] so that the form can integrate
/// with the rest of the `rocket_csrf_guard` ecosystem for CSRF checks.
///
/// The behavior of this macro can be customized a little:
///
/// 1. If the form has a singular lifetime `'a`, the generated `csrf_token` field
///    will be of type `&'a str`
/// 2. If you would like to use a different name for the field, pass it as an argument,
///    like `#[with_csrf_token("field_name")]`
/// 3. If there is a pre-existing field with the specified (or default) name, no field
///    will be added - it will just implement the [`WithUserProvidedCsrfToken`] trait.
///
/// For more detailed examples, look at the `derive_` examples in the examples/ folder.
pub use rocket_csrf_guard_derive::with_csrf_token;

pub use cookie::{
    DoubleSubmitCookieCsrfToken, SetDoubleSubmitCookieCsrfToken, SetLaxDoubleSubmitCookieCsrfToken,
    SetNoneDoubleSubmitCookieCsrfToken_DO_NOT_USE_UNLESS_YOU_ARE_SURE,
    DOUBLE_SUBMIT_CSRF_TOKEN_COOKIE_NAME,
};
pub use form::{CsrfProtectedForm, CsrfProtectedFormError, CsrfProtectedFormWithGuard};
pub use header::{
    CheckCsrfProtectionHeader, CheckCsrfProtectionHeaderError, CsrfTokenSourcedFromHeader,
};
pub use proof::CsrfCheckProof;
pub use token::{
    ManuallySourcedCsrfToken_DO_NOT_USE_UNLESS_YOU_ARE_SURE, WithUserProvidedCsrfToken,
};
pub use verifier::{CsrfTokenVerificationError, CsrfTokenVerifier, VerifierWithKnownExpectedToken};

pub type DoubleSubmitCookieCsrfProtectedForm<F> = CsrfProtectedForm<DoubleSubmitCookieCsrfToken, F>;
