#![allow(unused)]

use rocket_csrf_guard_derive::with_csrf_token;

/// If the struct has a single lifetime parameter, generate a &str
#[with_csrf_token]
struct SomeFormWithLifetimes<'a> {
    name: &'a str,
}

fn main() {}
