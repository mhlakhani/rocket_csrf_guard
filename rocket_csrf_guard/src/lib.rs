mod cookie;
mod form;
mod header;
mod proof;
mod token;
mod util;
mod verifier;

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
pub use util::Error;
pub use verifier::{CsrfTokenVerificationError, CsrfTokenVerifier, VerifierWithKnownExpectedToken};

pub type DoubleSubmitCookieCsrfProtectedForm<F> = CsrfProtectedForm<DoubleSubmitCookieCsrfToken, F>;
