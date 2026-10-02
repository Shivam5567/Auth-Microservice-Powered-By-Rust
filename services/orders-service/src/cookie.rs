//! The refresh token lives here, and nowhere else.
//!
//! Two properties matter, and both are the reason this is a cookie rather than
//! a field on the JSON response:
//!
//!   * `http_only`, so no script on the page can read it. A refresh token is
//!     long lived; anything JavaScript can reach, injected script can steal.
//!   * `path=/api/auth`, so it is not attached to ordinary order requests. It
//!     only travels on the two endpoints that actually need it.

use std::time::Duration;

use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use time::Duration as CookieDuration;

use crate::error::{AppError, AppResult};

pub const REFRESH_COOKIE: &str = "refresh_token";
const COOKIE_PATH: &str = "/api/auth";

/// Whether to mark the cookie `Secure`.
///
/// Must be `false` for the local demo, which is served over plain HTTP. Chrome
/// and Firefox do treat `http://localhost` as trustworthy and will keep a
/// `Secure` cookie there, but other browsers and non-localhost setups will
/// silently drop it, which looks like a broken login.
pub fn secure_cookies() -> bool {
    std::env::var("COOKIE_SECURE")
        .map(|v| !matches!(v.trim().to_ascii_lowercase().as_str(), "false" | "0" | "no"))
        .unwrap_or(true)
}

pub fn refresh_cookie<'c>(token: &str, ttl: Duration) -> Cookie<'c> {
    Cookie::build((REFRESH_COOKIE, token.to_owned()))
        .http_only(true)
        .secure(secure_cookies())
        // Lax rather than Strict: Strict would withhold the cookie when the
        // user arrives from an external link, which breaks a shared checkout
        // link.
        .same_site(SameSite::Lax)
        .path(COOKIE_PATH)
        .max_age(CookieDuration::seconds(ttl.as_secs() as i64))
        .build()
}

pub fn clear_refresh_cookie<'c>() -> Cookie<'c> {
    Cookie::build((REFRESH_COOKIE, ""))
        .http_only(true)
        .secure(secure_cookies())
        .same_site(SameSite::Lax)
        .path(COOKIE_PATH)
        .max_age(CookieDuration::ZERO)
        .build()
}

pub fn jar_with_refresh(token: &str, ttl: Duration) -> CookieJar {
    CookieJar::new().add(refresh_cookie(token, ttl))
}

pub fn jar_without_refresh() -> CookieJar {
    CookieJar::new().add(clear_refresh_cookie())
}

pub fn read_refresh(jar: &CookieJar) -> AppResult<String> {
    jar.get(REFRESH_COOKIE)
        .map(|c| c.value().to_owned())
        .filter(|v| !v.is_empty())
        .ok_or_else(|| AppError::unauthorized("no session, sign in again"))
}
