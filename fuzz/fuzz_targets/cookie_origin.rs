//! Fuzz the two header parsers that read untrusted text.
//!
//! [`navault_server::cookie`] reads a `Cookie` header and
//! [`navault_server::origin_matches`] compares an `Origin` header against a
//! loopback name. Neither may panic on any input. No secret, key, or passphrase
//! appears in this target.

#![no_main]

use axum::body::Body;
use axum::http::{Request, header};
use libfuzzer_sys::fuzz_target;

/// The loopback names the origin check is built for.
const HOSTS: [&str; 3] = ["http://localhost", "http://127.0.0.1", "http://[::1]"];

fuzz_target!(|data: &[u8]| {
    // A header value only exists for bytes the HTTP parser accepts; the cookie
    // parser itself must handle every value that survives that check.
    if let Ok(value) = header::HeaderValue::from_bytes(data) {
        let request = Request::builder()
            .header(header::COOKIE, value)
            .body(Body::empty())
            .expect("a request with a valid header value");
        let _ = navault_server::cookie(&request, "neotales.session");
    }

    // The origin parser takes the header text directly, so every UTF-8 input
    // reaches it.
    if let Ok(text) = std::str::from_utf8(data) {
        for host in HOSTS {
            let _ = navault_server::origin_matches(host, text);
        }
    }
});
