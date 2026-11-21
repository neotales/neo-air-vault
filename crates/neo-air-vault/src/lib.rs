//! Placeholder for neo-air-vault.
//!
//! This crate does not store, encrypt, wrap, or return secrets. A call that
//! appears to succeed here has not protected anything.

/// Crate version from the package metadata.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::VERSION;

    #[test]
    fn version_matches_the_workspace() {
        assert_eq!(VERSION, "0.1.0");
    }
}
