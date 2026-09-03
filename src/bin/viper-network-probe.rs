//! Controlled probe for the `PrivateNetwork=yes` policy.

use serde_json::json;
use std::{net::TcpStream, process::ExitCode, time::Duration};

fn blocked(address: &str) -> bool {
    TcpStream::connect_timeout(
        &address.parse().expect("probe address is a fixed literal"),
        Duration::from_secs(2),
    )
    .is_err()
}

fn main() -> ExitCode {
    let external_network_blocked = blocked("1.1.1.1:443");
    let local_network_blocked = blocked("127.0.0.1:8080");
    println!(
        "{}",
        serde_json::to_string(&json!({
            "schema": "viper-boxd.network-probe.v0",
            "network_mode": "DENY",
            "external_network_blocked": external_network_blocked,
            "local_network_blocked": local_network_blocked,
        }))
        .expect("probe JSON serialization cannot fail")
    );
    if external_network_blocked && local_network_blocked {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}
