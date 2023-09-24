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

// Errors when doing csrf checks
#[derive(Debug)]
pub enum CsrfProtectedFormError<T> {
    NoVerifierFound,
    CsrfTokenVerificationError,
    FormParsing(T),
}

#[derive(Debug)]
pub enum CsrfProtectedFormWithGuardError<T, E> {
    CsrfProtection(CsrfProtectedFormError<T>),
    FromRequestForwarded,
    FromRequestFailed(Status, E),
}

// A wrapper form which parses the initial form, derefs to it, and ensures CSRF checks pass
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
    pub fn into_innermost(self) -> F {
        self.form.into_inner()
    }

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
            request::Outcome::Failure((status, _)) => {
                return data::Outcome::Failure((status, CsrfProtectedFormError::NoVerifierFound))
            }
            request::Outcome::Forward(_) => return data::Outcome::Forward(data),
        };
        let inner = match F::from_data(request, data).await {
            data::Outcome::Success(inner) => inner,
            data::Outcome::Failure((status, e)) => {
                return data::Outcome::Failure((status, CsrfProtectedFormError::FormParsing(e)))
            }
            data::Outcome::Forward(f) => return data::Outcome::Forward(f),
        };
        (verifier.verify(&inner).await).map_or(
            data::Outcome::Failure((
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

// A wrapper for a CsrfProtectedForm which also runs a guard
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
    pub fn into_parts_with_proof(self) -> (V::Proof, G, F) {
        (self.proof, self.guard, self.form.into_inner())
    }

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
            request::Outcome::Failure((status, _)) => {
                return data::Outcome::Failure((
                    status,
                    CsrfProtectedFormWithGuardError::CsrfProtection(
                        CsrfProtectedFormError::NoVerifierFound,
                    ),
                ))
            }
            request::Outcome::Forward(_) => return data::Outcome::Forward(data),
        };
        let form = match F::from_data(request, data).await {
            data::Outcome::Success(form) => form,
            data::Outcome::Failure((status, e)) => {
                return data::Outcome::Failure((
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
                    request::Outcome::Failure((status, error)) => data::Outcome::Failure((
                        status,
                        CsrfProtectedFormWithGuardError::FromRequestFailed(status, error),
                    )),
                    request::Outcome::Forward(_) => data::Outcome::Failure((
                        Status::InternalServerError,
                        CsrfProtectedFormWithGuardError::FromRequestForwarded,
                    )),
                }
            }
            Err(_) => data::Outcome::Failure((
                Status::Forbidden,
                CsrfProtectedFormWithGuardError::CsrfProtection(
                    CsrfProtectedFormError::CsrfTokenVerificationError,
                ),
            )),
        }
    }
}
