#![feature(prelude_import)]
#![allow(unused)]
#[prelude_import]
use std::prelude::rust_2021::*;
#[macro_use]
extern crate std;
use rocket_csrf_guard_derive::with_csrf_token;
/// If there are multiple lifetime parameters, fall back to a String
struct SomeFormWithMultipleLifetimes<'a, 'b> {
    name: &'a str,
    something: &'b str,
    csrf_token: String,
}
impl<'a, 'b> rocket_csrf_guard::WithUserProvidedCsrfToken
for SomeFormWithMultipleLifetimes<'a, 'b> {
    fn csrf_token(&self) -> &str {
        &self.csrf_token
    }
}
fn main() {}
