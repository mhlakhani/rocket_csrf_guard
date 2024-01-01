#![allow(unused)]

use rocket_csrf_guard_derive::with_csrf_token;

/// By default, generate a String field called csrf_token
#[with_csrf_token]
struct SomeFormWithoutLifetimes {
    name: String,
}

fn main() {}
