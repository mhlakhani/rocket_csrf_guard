#![deny(missing_docs)]
// TODO: Figure out a way to code share with the test app.

//! This example demonstrates how to use this library in an end to end scenario.
//!
//! We start off by showing how to use CSRF protection for forms: by simply
//! using [`with_csrf_token`] to derive [`rocket_csrf_guard::WithUserProvidedCsrfToken`].
//!
//! We then show how to use that with sessions. By defining a [`Session`] type
//! which has a CSRF token and implements [`VerifierWithKnownExpectedToken`], forms
//! for routes which require a valid user session can be checked against CSRF,
//! by wrapping them with [`SessionCsrfProtectedForm`], and then using the wrapped
//! version in your route. You can look at [`do_logout`] for an example.
//! You are responsible for extracting the CSRF token from the session and providing it
//! on any forms that need it - [`show_loggedin_page`] has an example of this.
//!
//! For forms which need CSRF protection but do not have a valid session (e.g. for login),
//! we support the [Double Submit Cookie](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#double-submit-cookie) pattern.
//! Just wrap your form in [`DoubleSubmitCookieCsrfProtectedForm`] and you are good to go,
//! as you can see in [`do_login`].
//! You are responsible for generating a CSRF token and providing it both in the form
//! as well as the cookie that's set. [`show_login_page`] has an example of this.
//!
//! Lastly, we also support checking CSRF tokens for API requests through the use of a header.
//! Simply use [`CheckCsrfProtectionHeader`] with your appropriate session type as done here.
//! You can find an example of this in [`check_csrf_header`]

use mini_moka::sync::Cache;
use rand::RngCore;
use rocket::{
    form::{Form, FromForm},
    get,
    http::{Cookie, CookieJar, SameSite, Status},
    outcome::IntoOutcome,
    post,
    request::{FromRequest, Outcome, Request},
    response::Redirect,
    routes, uri, State,
};
use rocket_dyn_templates::{context, Template};
use sha3::{Digest, Sha3_256};

use rocket_csrf_guard::{
    with_csrf_token, CheckCsrfProtectionHeader, CsrfCheckProof, CsrfProtectedForm,
    DoubleSubmitCookieCsrfProtectedForm, SetDoubleSubmitCookieCsrfToken,
    VerifierWithKnownExpectedToken,
};

const SESSION_COOKIE_NAME: &str = "__Host-session";
const SESSION_HEADER_NAME: &str = "Authorization";

/// Generate a random ID of the appropriate length
fn random_id(len: usize) -> String {
    let mut buf = vec![0; len];
    rand::thread_rng()
        .try_fill_bytes(&mut buf)
        .expect("Couldn't generate random number");
    base64::encode_config(buf, base64::URL_SAFE)
}

/// Hash a string
fn hash(id: &str) -> String {
    let digest = Sha3_256::digest(id.as_bytes());
    hex::encode(digest)
}

/// A session for logged in users.
#[derive(Clone, Debug)]
pub struct Session {
    /// A hash of the session ID, so we don't leak the raw ID by accident
    session_id_hash: String,
    /// The username
    username: String,
    /// The csrf token to authenticate requests
    csrf_token: String,
}

#[async_trait::async_trait]
impl<'r> FromRequest<'r> for Session {
    type Error = std::convert::Infallible;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        // Use rocket's caching so that if we request a Session multiple times,
        // we don't do multiple database fetches. In this case our Session Manager
        // is purely in-memory but in a real application fetching a session likely
        // involves a DB call
        let session_result = request
            .local_cache_async(async {
                // Extract a session ID, preferring the headers over the cookies
                // so that callers which set both prefer the explicitly set headers
                let session_info: Option<String> = {
                    request
                        .headers()
                        .get_one(SESSION_HEADER_NAME)
                        .and_then(|value| value.strip_prefix("Bearer ").map(hash))
                        .or_else(|| {
                            request
                                .cookies()
                                .get_private(SESSION_COOKIE_NAME)
                                .map(|c| hash(c.value()))
                        })
                };
                let Some(session_id_hash) = session_info else {
                    return None;
                };
                let manager = request
                    .guard::<&State<SessionManager>>()
                    .await
                    .succeeded()?;
                manager.fetch_session(&session_id_hash)
            })
            .await;

        session_result
            .clone()
            .or_forward(Status::InternalServerError)
    }
}

impl VerifierWithKnownExpectedToken for Session {
    type Proof = CsrfCheckProof;
    fn expected_token(&self) -> &str {
        &self.csrf_token
    }
}

/// Manager for sessions
#[derive(Debug)]
pub struct SessionManager {
    sessions: Cache<String, Session>,
}

impl SessionManager {
    fn new() -> Self {
        let sessions = Cache::builder()
            .max_capacity(16)
            .initial_capacity(16)
            .build();
        Self { sessions }
    }

    fn create_session(&self, username: String, cookies: &CookieJar<'_>) -> Session {
        let session_id = random_id(16);
        let csrf_token = random_id(16);
        let session_id_hash = hash(&session_id);
        let session = Session {
            session_id_hash: session_id_hash.clone(),
            username,
            csrf_token,
        };
        let session_cookie = Cookie::build((SESSION_COOKIE_NAME, session_id.clone()))
            .max_age(rocket::time::Duration::days(1))
            .same_site(SameSite::Strict)
            .secure(true);
        cookies.add_private(session_cookie);
        self.sessions
            .insert(session.session_id_hash.clone(), session.clone());
        session
    }

    fn fetch_session(&self, session_id_hash: &String) -> Option<Session> {
        self.sessions.get(session_id_hash)
    }

    /// Require a proof that we've passed CSRF checks, to avoid logout CSRF
    /// attacks. This is a contrived example, but the functionality in this library can
    /// be used to provide safe-by-default APIs which are resistant to CSRF attacks.
    fn logout(&self, _proof: CsrfCheckProof, session_id_hash: &String, cookies: &CookieJar<'_>) {
        if let Some(cookie) = cookies.get(SESSION_COOKIE_NAME).cloned() {
            cookies.remove_private(cookie)
        }
        self.sessions.invalidate(session_id_hash)
    }
}

type VerifyCsrfTokenViaHeaders = CheckCsrfProtectionHeader<Session>;
type SessionCsrfProtectedForm<F> = CsrfProtectedForm<Session, F>;

#[get("/header")]
fn check_csrf_header(_csrf_check: VerifyCsrfTokenViaHeaders) -> String {
    "You successfully passed the right CSRF token, congrats!".to_string()
}

#[with_csrf_token]
#[derive(Debug, FromForm)]
struct LoginForm<'r> {
    name: String,
}

#[with_csrf_token]
#[derive(Debug, FromForm)]
struct LogoutForm<'r> {}

#[get("/", rank = 2)]
fn show_login_page(csrf_token: SetDoubleSubmitCookieCsrfToken) -> Template {
    Template::render(
        "login",
        context! {
            csrf_token
        },
    )
}

#[post("/", data = "<form>")]
fn do_login(
    form: DoubleSubmitCookieCsrfProtectedForm<Form<LoginForm>>,
    manager: &State<SessionManager>,
    cookies: &CookieJar<'_>,
) -> Redirect {
    // In a real application, we'd check for passwords or something.
    let _ = manager.create_session(form.name.clone(), cookies);
    Redirect::to(uri!(show_loggedin_page))
}

#[get("/", rank = 1)]
fn show_loggedin_page(cookies: &CookieJar<'_>, session: Session) -> Template {
    let session_id = cookies
        .get_private(SESSION_COOKIE_NAME)
        .map(|c| c.value().to_string())
        .expect("have session id");
    Template::render(
        "loggedin",
        context! {
            csrf_token: session.csrf_token,
            name: session.username,
            session_id
        },
    )
}

#[post("/logout", data = "<form>")]
fn do_logout(
    session: Session,
    form: SessionCsrfProtectedForm<Form<LogoutForm>>,
    manager: &State<SessionManager>,
    cookies: &CookieJar<'_>,
) -> Redirect {
    // In a real application, we'd check for passwords or something.
    let (proof, _) = form.into_parts();
    manager.logout(proof, &session.session_id_hash, cookies);
    Redirect::to(uri!(show_login_page))
}

#[rocket::launch]
fn rocket() -> _ {
    rocket::build()
        .mount(
            "/",
            routes![
                check_csrf_header,
                show_login_page,
                show_loggedin_page,
                do_login,
                do_logout
            ],
        )
        .manage(SessionManager::new())
        .attach(Template::fairing())
}
