#![feature(prelude_import)]
#![allow(unused)]
#[prelude_import]
use std::prelude::rust_2021::*;
#[macro_use]
extern crate std;
use rocket_csrf_guard_derive::with_csrf_token;
/// By default, generate a String field called csrf_token
struct SomeFormWithoutLifetimes {
    name: String,
    csrf_token: String,
}
impl rocket_csrf_guard::WithUserProvidedCsrfToken for SomeFormWithoutLifetimes {
    fn csrf_token(&self) -> &str {
        &self.csrf_token
    }
}
fn main() {}
