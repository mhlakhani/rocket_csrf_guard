use super::example_app::build_rocket;

use std::path::PathBuf;
use std::process::Command;

use console::Style;
use rocket::{
    http::{ContentType, Header, Status},
    local::blocking::Client,
};
use similar::{ChangeTag, TextDiff};

macro_rules! fetch_login_page {
    () => {{
        let client = Client::tracked(build_rocket()).unwrap();
        let (cookie, csrf_token) = {
            let response = client.get("/").dispatch();
            assert_eq!(response.status(), Status::Ok);
            let cookies = response.cookies();
            let cookie = cookies.get_private("__Host-csrf-token").unwrap().clone();
            let csrf_token = cookie.value().to_owned();
            (cookie, csrf_token)
        };
        (client, cookie, csrf_token)
    }};
}

#[test]
fn test_fetch_login_sets_double_submit_cookie() {
    let client = Client::tracked(build_rocket()).unwrap();
    let response = client.get("/").dispatch();

    // Validate it's OK
    assert_eq!(response.status(), Status::Ok);

    // ... and that we get a cookie
    let cookies = response.cookies();
    assert!(cookies.get_private("__Host-csrf-token").is_some());

    // ... and that the html content looks right
    let text = response.into_string();
    assert!(text.is_some());
    assert!(text.unwrap().contains("example"));
}

#[test]
fn test_login_works_with_correct_cookie() {
    let (client, _, csrf_token) = fetch_login_page!();

    // Now try to login, ensure it works
    let response = client
        .post("/")
        .header(ContentType::Form)
        .body(format!("name=Hasnain&csrf_token={csrf_token}"))
        .dispatch();
    assert_eq!(response.status(), Status::SeeOther);

    // Should now have a session cookie
    let cookies = response.cookies();
    let cookie = cookies.get_private("__Host-session").unwrap();

    // And we can use this to access the main page.
    let response = client.get("/").private_cookie(cookie).dispatch();
    assert_eq!(response.status(), Status::Ok);

    let text = response.into_string();
    assert!(text.is_some());
    assert!(text.unwrap().contains("passed the right csrf token"));
}

#[test]
fn test_login_fails_with_incorrect_csrf_token() {
    let (client, _, _) = fetch_login_page!();

    // Now try to login, ensure it does not work
    let response = client
        .post("/")
        .header(ContentType::Form)
        .body("name=Hasnain&csrf_token=i_am_wrong")
        .dispatch();
    assert_eq!(response.status(), Status::Forbidden);
}

#[test]
fn test_login_fails_with_incorrect_cookie() {
    let (client, mut cookie, csrf_token) = fetch_login_page!();

    // Make the cookie wrong
    cookie.set_value("i_am_wrong");

    // Now try to login, ensure it does not work
    let response = client
        .post("/")
        .private_cookie(cookie)
        .header(ContentType::Form)
        .body(format!("name=Hasnain&csrf_token={csrf_token}"))
        .dispatch();
    assert_eq!(response.status(), Status::Forbidden);
}

#[test]
fn test_login_fails_without_cookie() {
    // Use an untracked client so the following request has no cookies
    let (client, csrf_token) = {
        let client = Client::untracked(build_rocket()).unwrap();
        let csrf_token = {
            let response = client.get("/").dispatch();
            assert_eq!(response.status(), Status::Ok);
            let cookies = response.cookies();
            let cookie = cookies.get_private("__Host-csrf-token").unwrap().clone();
            let csrf_token = cookie.value().to_owned();
            csrf_token
        };
        (client, csrf_token)
    };

    // Now try to login, ensure it does not work
    let response = client
        .post("/")
        .header(ContentType::Form)
        .body(format!("name=Hasnain&csrf_token={csrf_token}"))
        .dispatch();

    // TODO: Make this 403 after rocket upgrade
    assert_eq!(response.status(), Status::NotFound);
}

#[test]
fn test_login_fails_without_csrf_token_in_form() {
    let (client, _, _) = fetch_login_page!();

    // Now try to login, ensure it does not work
    let response = client
        .post("/")
        .header(ContentType::Form)
        .body("name=Hasnain")
        .dispatch();
    assert_eq!(response.status(), Status::UnprocessableEntity);
}

#[test]
fn test_header_works_for_passing_token() {
    let (client, _, csrf_token) = fetch_login_page!();

    // Login, fetch the page, extract CSRF token
    let response = client
        .post("/")
        .header(ContentType::Form)
        .body(format!("name=Hasnain&csrf_token={csrf_token}"))
        .dispatch();
    assert_eq!(response.status(), Status::SeeOther);

    // And we can use this to access the main page.
    let response = client.get("/").dispatch();
    assert_eq!(response.status(), Status::Ok);

    // Now extract the session csrf token
    let text = response.into_string().unwrap();
    let session_csrf_token = {
        let mut lines = text.lines();
        lines.find(|l| l.contains("<!--"));
        lines.next().unwrap().to_string()
    };

    // Now get the endpoint passing the right csrf token via a header
    let response = client
        .get("/header")
        .header(Header::new("X-Csrf-Token", session_csrf_token))
        .dispatch();
    assert_eq!(response.status(), Status::Ok);

    // And verify that it doesn't work without
    let response = client
        .get("/header")
        .header(Header::new("X-Csrf-Token", "wrong_token"))
        .dispatch();
    assert_eq!(response.status(), Status::Forbidden)
}

#[test]
fn test_session_based_tokens_work() {
    let (client, _, csrf_token) = fetch_login_page!();

    // Login, fetch the page, extract CSRF token
    let response = client
        .post("/")
        .header(ContentType::Form)
        .body(format!("name=Hasnain&csrf_token={csrf_token}"))
        .dispatch();
    assert_eq!(response.status(), Status::SeeOther);

    // And we can use this to access the main page.
    let response = client.get("/").dispatch();
    assert_eq!(response.status(), Status::Ok);

    // Now extract the session csrf token so we can put it in the form
    let text = response.into_string().unwrap();
    let session_csrf_token = {
        let mut lines = text.lines();
        lines.find(|l| l.contains("<!--"));
        lines.next().unwrap().to_string()
    };

    // Now try to log out with the wrong CSRF token, it should fail!
    let response = client
        .post("/logout")
        .header(ContentType::Form)
        .body(format!("name=Hasnain&csrf_token={csrf_token}"))
        .dispatch();
    assert_eq!(response.status(), Status::Forbidden);

    // And verify that it works with the right one
    let response = client
        .post("/logout")
        .header(ContentType::Form)
        .body(format!("name=Hasnain&csrf_token={session_csrf_token}"))
        .dispatch();
    assert_eq!(response.status(), Status::SeeOther);

    // And that we were actually logged out
    let response = client.get("/").dispatch();
    assert_eq!(response.status(), Status::Ok);
    let text = response.into_string();
    assert!(text.is_some());
    assert!(!text.unwrap().contains("passed the right csrf token"));
}

// Poor man's macrotest, since that doesn't work with our workspace setup.
fn verify_expansion_case(name: &str) {
    println!("Running expansion test case {name}...");
    let actual = String::from_utf8_lossy(
        Command::new("cargo")
            .arg("expand")
            .arg("--example")
            .arg(name)
            .output()
            .expect("failed to execute process")
            .stdout
            .as_slice(),
    )
    .to_string();
    let mut expected_path =
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("Couldn't get manifest dir"));
    expected_path.push(format!("src/expand_snapshots/{name}.rs"));
    let expected =
        std::fs::read_to_string(expected_path.clone()).expect("Unable to read snapshot file!");
    if actual != expected {
        if let Ok(value) = std::env::var("UPDATE_EXPANSIONS") {
            if value == "1" {
                std::fs::write(expected_path, actual.into_bytes())
                    .expect("Unable to write snapshot file");
                return;
            }
        }
        let diff = TextDiff::from_lines(&expected, &actual);
        for op in diff.ops() {
            for change in diff.iter_changes(op) {
                let (sign, style) = match change.tag() {
                    ChangeTag::Delete => ("-", Style::new().red()),
                    ChangeTag::Insert => ("+", Style::new().green()),
                    ChangeTag::Equal => (" ", Style::new()),
                };
                print!("{}{}", style.apply_to(sign).bold(), style.apply_to(change));
            }
        }
        panic!("Expected output did not match! Set UPDATE_EXPANSIONS=1 and rerun if desired.")
    }
}

#[test]
pub fn verify_derive_simple() {
    verify_expansion_case("derive_simple");
}

#[test]
pub fn verify_derive_single_lifetime() {
    verify_expansion_case("derive_single_lifetime");
}

#[test]
pub fn verify_derive_multiple_lifetimes() {
    verify_expansion_case("derive_multiple_lifetimes");
}

#[test]
pub fn verify_derive_specify_field() {
    verify_expansion_case("derive_specify_field");
}

#[test]
pub fn verify_derive_custom_field_name() {
    verify_expansion_case("derive_custom_field_name");
}

#[test]
pub fn verify_derive_custom_specified_field_name() {
    verify_expansion_case("derive_custom_specified_field_name");
}
