#![feature(prelude_import)]
#![allow(unused)]
#[prelude_import]
use std::prelude::rust_2021::*;
#[macro_use]
extern crate std;
use rocket_csrf_guard_derive::with_csrf_token;
/// If the struct has a single lifetime parameter, generate a &str
struct SomeFormWithLifetimes<'a> {
    name: &'a str,
    csrf_token: &'a str,
}
impl<'a> rocket_csrf_guard::WithUserProvidedCsrfToken for SomeFormWithLifetimes<'a> {
    fn csrf_token(&self) -> &str {
        &self.csrf_token
    }
}
fn main() {}
