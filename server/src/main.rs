//! Process entry for the loopback health listener and auth routes.
//!
//! Starting this binary does not create a vault. It does open the auth store and
//! ensure a tenant and administrator exist.

use std::process::ExitCode;

use navault_server::{LISTEN_ADDR, serve};

#[tokio::main]
async fn main() -> ExitCode {
    eprintln!("navault-server listening on {LISTEN_ADDR}");
    eprintln!("this process is not a vault and does not store secrets");
    match serve().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("navault-server failed: {error}");
            ExitCode::FAILURE
        }
    }
}
