//! Controlled probe verifying a Box cannot send a signal to a process
//! outside its own scope. No systemd property applied to the transient
//! unit isolates signal delivery the way `PrivateNetwork=yes` isolates the
//! network - every process in the unit still runs under the caller's UID,
//! so this probe checks the boundary directly instead of assuming it.
//!
//! It uses signal 0 (`kill -0`), which runs the kernel's full `kill(2)`
//! path without delivering a signal.  The unit's `SystemCallFilter=` denies
//! every signal-sending syscall: that is enforceable for a `systemd --user`
//! helper, unlike relying on different UIDs (which it cannot provide).

use serde_json::json;
use std::{
    env,
    process::{Command, ExitCode},
};

fn can_signal(pid: u32) -> Option<bool> {
    Command::new("kill")
        .args(["-0", &pid.to_string()])
        .output()
        .ok()
        .map(|output| output.status.success())
}

fn main() -> ExitCode {
    let target_pid: u32 = match env::args().skip(1).collect::<Vec<_>>().as_slice() {
        [flag, pid] if flag == "--target-pid" => match pid.parse() {
            Ok(pid) => pid,
            Err(_) => {
                eprintln!("viper-signal-probe: --target-pid must be a PID");
                return ExitCode::from(2);
            }
        },
        _ => {
            eprintln!("usage: viper-signal-probe --target-pid PID");
            return ExitCode::from(2);
        }
    };

    // Both self and external delivery must be denied.  This proves that the
    // syscall filter, rather than a fragile same-UID permission distinction,
    // is active for the complete signal family used by normal processes.
    let self_signal_denied = match can_signal(std::process::id()) {
        Some(allowed) => !allowed,
        None => {
            eprintln!("viper-signal-probe: failed to execute kill(1)");
            return ExitCode::from(2);
        }
    };
    let target_signal_denied = match can_signal(target_pid) {
        Some(allowed) => !allowed,
        None => {
            eprintln!("viper-signal-probe: failed to execute kill(1) for target");
            return ExitCode::from(2);
        }
    };

    println!(
        "{}",
        serde_json::to_string(&json!({
            "schema": "viper-boxd.signal-probe.v0",
            "target_pid": target_pid,
            "self_signal_denied": self_signal_denied,
            "target_signal_denied": target_signal_denied,
        }))
        .expect("probe JSON serialization cannot fail")
    );

    if self_signal_denied && target_signal_denied {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}
