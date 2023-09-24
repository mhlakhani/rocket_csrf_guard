use std::ops::Deref;

use rocket::form::Form;

// A thing that has a csrf token provided from user input
pub trait WithUserProvidedCsrfToken {
    fn csrf_token(&self) -> &str;
}

impl<T> WithUserProvidedCsrfToken for Form<T>
where
    T: WithUserProvidedCsrfToken,
{
    fn csrf_token(&self) -> &str {
        self.deref().csrf_token()
    }
}

// Use this in extremely sparing circumstances: e.g. you have no choice
// but to send a csrf token embedded somewhere random and just have the string.
// This can cause all sorts of security problems.
#[allow(non_camel_case_types)]
pub struct ManuallySourcedCsrfToken_DO_NOT_USE_UNLESS_YOU_ARE_SURE(String);

impl ManuallySourcedCsrfToken_DO_NOT_USE_UNLESS_YOU_ARE_SURE {
    pub const fn new(csrf_token: String) -> Self {
        Self(csrf_token)
    }
}

impl WithUserProvidedCsrfToken for ManuallySourcedCsrfToken_DO_NOT_USE_UNLESS_YOU_ARE_SURE {
    fn csrf_token(&self) -> &str {
        &self.0
    }
}
