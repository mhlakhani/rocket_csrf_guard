use crate::{
    token::WithUserProvidedCsrfToken, util::set_proof_in_cache, verifier::CsrfTokenVerifier,
};

use std::ops::{Deref, DerefMut};

use rocket::{
    data::{self, Data, FromData},
    form::Form,
    http::Status,
    request::{self, FromRequest, Request},
};

/// Errors when validating a [`CsrfProtectedForm`]
#[derive(Debug)]
pub enum CsrfProtectedFormError<T> {
    /// There was no valid instance of a [`CsrfTokenVerifier`] to validate the provided token against.
    NoVerifierFound,
    /// There was an error verifying the token itself, perhaps because it was incorrect.
    /// Intentionally an opaque type so error messages cannot contain the token.
    CsrfTokenVerificationError,
    /// An error occurred while parsing the form.
    FormParsing(T),
}

/// Errors when validating a [`CsrfProtectedFormWithGuard`]
#[derive(Debug)]
pub enum CsrfProtectedFormWithGuardError<T, E> {
    /// There wwas an error validating the underlying [`CsrfProtectedForm`]
    CsrfProtection(CsrfProtectedFormError<T>),
    /// The [`FromRequest`] guard forwarded the request.
    FromRequestForwarded,
    /// The [`FromRequest`] guard failed.
    FromRequestFailed(Status, E),
}

/// A wrapper form which parses the initial form, dereferences to it, and ensures CSRF checks pass
pub struct CsrfProtectedForm<V, F>
where
    V: CsrfTokenVerifier,
{
    form: F,
    proof: V::Proof,
    _marker: std::marker::PhantomData<V>,
}

impl<V, F> CsrfProtectedForm<V, F>
where
    V: CsrfTokenVerifier,
{
    #[allow(clippy::missing_const_for_fn)]
    pub fn into_inner(self) -> F {
        self.form
    }
}

impl<V, F> CsrfProtectedForm<V, Form<F>>
where
    V: CsrfTokenVerifier,
{
    /// Extracts the inner form, throwing away the proof.
    pub fn into_innermost(self) -> F {
        self.form.into_inner()
    }

    /// Extracts the inner form and proof.
    pub fn into_parts(self) -> (V::Proof, F) {
        (self.proof, self.form.into_inner())
    }
}

#[async_trait::async_trait]
impl<'r, V, F> FromData<'r> for CsrfProtectedForm<V, F>
where
    V: CsrfTokenVerifier + FromRequest<'r> + Send + Sync,
    V::Proof: Clone,
    F: WithUserProvidedCsrfToken + FromData<'r> + Sized + Send + Sync,
{
    type Error = CsrfProtectedFormError<<F as FromData<'r>>::Error>;

    async fn from_data(request: &'r Request<'_>, data: Data<'r>) -> data::Outcome<'r, Self> {
        let verifier = match request.guard::<V>().await {
            request::Outcome::Success(verifier) => verifier,
            request::Outcome::Error((status, _)) => {
                return data::Outcome::Error((status, CsrfProtectedFormError::NoVerifierFound))
            }
            request::Outcome::Forward(status) => return data::Outcome::Forward((data, status)),
        };
        let inner = match F::from_data(request, data).await {
            data::Outcome::Success(inner) => inner,
            data::Outcome::Error((status, e)) => {
                return data::Outcome::Error((status, CsrfProtectedFormError::FormParsing(e)))
            }
            data::Outcome::Forward(f) => return data::Outcome::Forward(f),
        };
        (verifier.verify(&inner).await).map_or(
            data::Outcome::Error((
                Status::Forbidden,
                CsrfProtectedFormError::CsrfTokenVerificationError,
            )),
            |proof| {
                set_proof_in_cache(request, proof.clone());
                data::Outcome::Success(Self {
                    form: inner,
                    proof,
                    _marker: std::marker::PhantomData,
                })
            },
        )
    }
}

impl<V, F> Deref for CsrfProtectedForm<V, F>
where
    V: CsrfTokenVerifier,
{
    type Target = F;

    fn deref(&self) -> &Self::Target {
        &self.form
    }
}

impl<V, F> DerefMut for CsrfProtectedForm<V, F>
where
    V: CsrfTokenVerifier,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.form
    }
}

/// A wrapper for a CsrfProtectedForm which also runs a guard.
/// This is useful in scenarios when you want to run some code that requires a CSRF
/// check to have passed (e.g. in a secure by default framework).
pub struct CsrfProtectedFormWithGuard<'r, V, F, G>
where
    V: CsrfTokenVerifier,
    G: FromRequest<'r>,
{
    form: F,
    proof: V::Proof,
    guard: G,
    _marker: std::marker::PhantomData<&'r V>,
}

impl<'r, V, F, G> CsrfProtectedFormWithGuard<'r, V, Form<F>, G>
where
    V: CsrfTokenVerifier,
    G: FromRequest<'r>,
{
    /// Extracts the inner form, guard, and proof.
    pub fn into_parts_with_proof(self) -> (V::Proof, G, F) {
        (self.proof, self.guard, self.form.into_inner())
    }

    /// Extracts the inner form and guard, throwing away the proof.
    pub fn into_parts(self) -> (G, F) {
        (self.guard, self.form.into_inner())
    }
}

#[async_trait::async_trait]
impl<'r, V, F, G> FromData<'r> for CsrfProtectedFormWithGuard<'r, V, F, G>
where
    V: CsrfTokenVerifier + FromRequest<'r> + Send + Sync,
    V::Proof: Clone,
    F: WithUserProvidedCsrfToken + FromData<'r> + Sized + Send + Sync,
    G: FromRequest<'r> + Send + Sync,
    G::Error: Send,
{
    type Error =
        CsrfProtectedFormWithGuardError<<F as FromData<'r>>::Error, <G as FromRequest<'r>>::Error>;

    async fn from_data(request: &'r Request<'_>, data: Data<'r>) -> data::Outcome<'r, Self> {
        let verifier = match request.guard::<V>().await {
            request::Outcome::Success(verifier) => verifier,
            request::Outcome::Error((status, _)) => {
                return data::Outcome::Error((
                    status,
                    CsrfProtectedFormWithGuardError::CsrfProtection(
                        CsrfProtectedFormError::NoVerifierFound,
                    ),
                ))
            }
            request::Outcome::Forward(status) => return data::Outcome::Forward((data, status)),
        };
        let form = match F::from_data(request, data).await {
            data::Outcome::Success(form) => form,
            data::Outcome::Error((status, e)) => {
                return data::Outcome::Error((
                    status,
                    CsrfProtectedFormWithGuardError::CsrfProtection(
                        CsrfProtectedFormError::FormParsing(e),
                    ),
                ))
            }
            data::Outcome::Forward(f) => return data::Outcome::Forward(f),
        };
        match verifier.verify(&form).await {
            Ok(proof) => {
                set_proof_in_cache(request, proof.clone());
                match request.guard::<G>().await {
                    request::Outcome::Success(guard) => data::Outcome::Success(Self {
                        form,
                        proof,
                        guard,
                        _marker: std::marker::PhantomData,
                    }),
                    request::Outcome::Error((status, error)) => data::Outcome::Error((
                        status,
                        CsrfProtectedFormWithGuardError::FromRequestFailed(status, error),
                    )),
                    request::Outcome::Forward(_) => data::Outcome::Error((
                        Status::InternalServerError,
                        CsrfProtectedFormWithGuardError::FromRequestForwarded,
                    )),
                }
            }
            Err(_) => data::Outcome::Error((
                Status::Forbidden,
                CsrfProtectedFormWithGuardError::CsrfProtection(
                    CsrfProtectedFormError::CsrfTokenVerificationError,
                ),
            )),
        }
    }
}
