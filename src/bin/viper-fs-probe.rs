//! Small, controlled probe used to verify a systemd filesystem policy.
//!
//! The probe only writes a marker in the explicitly supplied scratch directory
//! and verifies that a protected host path cannot be written. It never accepts
//! arbitrary commands or mount options.

use serde_json::json;
use std::{env, fs, path::PathBuf, process::ExitCode};

fn main() -> ExitCode {
    let scratch = match env::args().skip(1).collect::<Vec<_>>().as_slice() {
        [flag, path] if flag == "--scratch" => PathBuf::from(path),
        _ => {
            eprintln!("usage: viper-fs-probe --scratch PATH");
            return ExitCode::from(2);
        }
    };

    let marker = scratch.join("probe-marker.txt");
    let scratch_write = fs::write(&marker, b"viper-boxd filesystem probe\n").is_ok();

    // ProtectHome=read-only makes the caller's home non-writable. The path is
    // unique to the probe and is removed if an unexpectedly permissive policy
    // allows it, so a standalone probe cannot leave an artifact behind.
    let outside = env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/home/viper-boxd-probe-denied"))
        .join("viper-boxd-probe-denied");
    let outside_write_denied = match fs::write(&outside, b"probe must be denied\n") {
        Ok(()) => {
            let _ = fs::remove_file(&outside);
            false
        }
        Err(_) => true,
    };

    println!(
        "{}",
        serde_json::to_string(&json!({
            "schema": "viper-boxd.filesystem-probe.v0",
            "scratch_write": scratch_write,
            "outside_write_denied": outside_write_denied,
        }))
        .expect("probe JSON serialization cannot fail")
    );

    if scratch_write && outside_write_denied {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}
