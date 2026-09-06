//! Controlled probe verifying the `CPUQuota=` and `MemoryMax=` properties
//! applied to a Box's transient unit are actually enforced by the kernel,
//! not just configured.
//!
//! The memory check spawns a disposable child - this same binary,
//! re-invoked with an internal-only flag - to attempt the over-limit
//! allocation. A real cgroup OOM kill (or an allocator abort on a hard
//! allocation failure) then only ever terminates that throwaway child;
//! this process, which must survive to report the result, never touches
//! the over-limit memory itself. The child stays in the same cgroup as its
//! parent, so its memory use still counts against the unit's `MemoryMax=`.

use serde_json::json;
use std::{
    env, fs,
    os::unix::process::ExitStatusExt,
    process::{Command, ExitCode, Stdio},
    thread,
    time::{Duration, Instant},
};

/// USER_HZ: the clock-tick rate `/proc/[pid]/stat`'s utime/stime fields are
/// counted in. `CONFIG_HZ` varies by kernel build, but the USER_HZ value
/// exposed to userspace is 100 on every mainstream Linux distribution.
const CLK_TCK_HZ: f64 = 100.0;
const CPU_TEST_DURATION: Duration = Duration::from_millis(1500);
/// Under real enforcement a busy loop's CPU-time/wall-time ratio stays
/// well under this; an unenforced quota drives it toward 1.0. The wide
/// margin absorbs scheduler noise without blurring the two cases.
const CPU_RATIO_LEAK_THRESHOLD: f64 = 0.6;
const INTERNAL_MEMORY_HOG_FLAG: &str = "--internal-memory-hog-child";

fn arg_value(args: &[String], name: &str) -> Option<String> {
    args.windows(2)
        .find(|pair| pair[0] == name)
        .map(|pair| pair[1].clone())
}

fn cpu_ticks() -> Option<u64> {
    let stat = fs::read_to_string("/proc/self/stat").ok()?;
    // comm (field 2) is parenthesized and may itself contain spaces or
    // parens, so split on the last ')' and index the remaining
    // whitespace-separated fields from field 3 (state) onward: utime is
    // field 14 (index 11 here), stime is field 15 (index 12).
    let after_comm = stat.rsplit_once(')')?.1;
    let fields: Vec<&str> = after_comm.split_whitespace().collect();
    let utime: u64 = fields.get(11)?.parse().ok()?;
    let stime: u64 = fields.get(12)?.parse().ok()?;
    Some(utime + stime)
}

/// Returns (cpu_quota_enforced, cpu_seconds, wall_seconds, cpu_ratio).
fn check_cpu_quota() -> (bool, f64, f64, f64) {
    let ticks_before = cpu_ticks();
    let wall_start = Instant::now();
    let mut counter: u64 = 0;
    while wall_start.elapsed() < CPU_TEST_DURATION {
        counter = counter.wrapping_add(1);
    }
    std::hint::black_box(counter);
    let wall_seconds = wall_start.elapsed().as_secs_f64();
    let ticks_after = cpu_ticks();
    match (ticks_before, ticks_after) {
        (Some(before), Some(after)) => {
            let cpu_seconds = after.saturating_sub(before) as f64 / CLK_TCK_HZ;
            let ratio = cpu_seconds / wall_seconds;
            (
                ratio < CPU_RATIO_LEAK_THRESHOLD,
                cpu_seconds,
                wall_seconds,
                ratio,
            )
        }
        // /proc/self/stat is unreadable: cannot confirm enforcement, fail closed.
        _ => (false, 0.0, wall_seconds, 0.0),
    }
}

/// Returns the live resident set of the child and how many pages its trusted
/// loop touched.  A MemoryMax OOM normally signals the child, but some kernel
/// configurations constrain its resident set without reporting that signal to
/// the parent; the second evidence path makes that behaviour observable.
fn rss_kb() -> u64 {
    fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status.lines().find_map(|line| {
                line.strip_prefix("VmRSS:")
                    .and_then(|value| value.split_whitespace().next())
                    .and_then(|value| value.parse().ok())
            })
        })
        .unwrap_or(0)
}

fn check_memory_limit(memory_limit_bytes: u64) -> (u64, bool, Option<i32>, u64, u64) {
    let attempt_bytes = memory_limit_bytes
        .saturating_mul(4)
        .min(memory_limit_bytes.saturating_add(256 * 1024 * 1024));
    let exe = match env::current_exe() {
        Ok(exe) => exe,
        Err(_) => return (attempt_bytes, false, None, 0, 0),
    };
    let child = match Command::new(&exe)
        .arg(INTERNAL_MEMORY_HOG_FLAG)
        .arg(attempt_bytes.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(_) => return (attempt_bytes, false, None, 0, 0),
    };
    let output = match child.wait_with_output() {
        Ok(output) => output,
        Err(_) => return (attempt_bytes, false, None, 0, 0),
    };
    let signal = output.status.signal();
    let child_report: serde_json::Value =
        serde_json::from_slice(&output.stdout).unwrap_or_default();
    let child_rss_kb = child_report
        .get("rss_kb")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let child_pages_touched = child_report
        .get("pages_touched")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let expected_pages = attempt_bytes.div_ceil(4096);
    let resident_cap = memory_limit_bytes.saturating_add(8 * 1024 * 1024) / 1024;
    // Termination by any signal (an OOM-kill, or an allocator abort on a
    // hard allocation failure) counts as enforcement; a clean exit means
    // the child fully allocated and touched the over-limit memory.
    (
        attempt_bytes,
        signal.is_some() || (child_pages_touched == expected_pages && child_rss_kb <= resident_cap),
        signal,
        child_rss_kb,
        child_pages_touched,
    )
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();

    // Internal re-exec: this invocation IS the disposable memory-hog
    // child. It never accepts anything from a caller other than its own
    // parent, and the byte count is one the parent computed itself.
    if let [flag, bytes] = args.as_slice() {
        if flag == INTERNAL_MEMORY_HOG_FLAG {
            let bytes: usize = bytes.parse().unwrap_or(0);
            // `Vec` allocation alone may be overcommitted.  Touch one byte in
            // each page with a volatile write so the kernel must charge real
            // anonymous memory to this unit's cgroup.
            let mut buffer = vec![0_u8; bytes];
            let mut pages_touched = 0_u64;
            for offset in (0..bytes).step_by(4096) {
                // SAFETY: `offset < bytes`, so this points inside `buffer`.
                unsafe { std::ptr::write_volatile(buffer.as_mut_ptr().add(offset), 0xAA) };
                pages_touched += 1;
            }
            if bytes > 0 {
                // SAFETY: index zero was initialized by the loop above.
                std::hint::black_box(unsafe { std::ptr::read_volatile(buffer.as_ptr()) });
            }
            // Keep the fully touched allocation live long enough for both the
            // kernel and systemd's cgroup accounting to observe it.  Without
            // this, an unexpectedly successful child may exit before the
            // transient unit records its peak and hide a broken probe.
            std::hint::black_box(&buffer);
            thread::sleep(Duration::from_millis(250));
            println!(
                "{}",
                serde_json::json!({"rss_kb": rss_kb(), "pages_touched": pages_touched})
            );
            return ExitCode::SUCCESS;
        }
    }

    let cpu_quota_percent: u64 = match arg_value(&args, "--cpu-quota-percent")
        .and_then(|v| v.parse().ok())
    {
        Some(v) => v,
        None => {
            eprintln!("usage: viper-resource-probe --cpu-quota-percent N --memory-limit-bytes N");
            return ExitCode::from(2);
        }
    };
    let memory_limit_bytes: u64 = match arg_value(&args, "--memory-limit-bytes")
        .and_then(|v| v.parse().ok())
    {
        Some(v) => v,
        None => {
            eprintln!("usage: viper-resource-probe --cpu-quota-percent N --memory-limit-bytes N");
            return ExitCode::from(2);
        }
    };

    let (cpu_quota_enforced, cpu_seconds, wall_seconds, cpu_ratio) = check_cpu_quota();
    let (
        memory_attempt_bytes,
        memory_limit_enforced,
        memory_child_signal,
        memory_child_rss_kb,
        memory_child_pages_touched,
    ) = check_memory_limit(memory_limit_bytes);

    println!(
        "{}",
        serde_json::to_string(&json!({
            "schema": "viper-boxd.resource-probe.v0",
            "cpu_quota_percent": cpu_quota_percent,
            "cpu_seconds": cpu_seconds,
            "wall_seconds": wall_seconds,
            "cpu_ratio": cpu_ratio,
            "cpu_quota_enforced": cpu_quota_enforced,
            "memory_limit_bytes": memory_limit_bytes,
            "memory_attempt_bytes": memory_attempt_bytes,
            "memory_child_signal": memory_child_signal,
            "memory_child_rss_kb": memory_child_rss_kb,
            "memory_child_pages_touched": memory_child_pages_touched,
            "memory_limit_enforced": memory_limit_enforced,
        }))
        .expect("probe JSON serialization cannot fail")
    );

    if cpu_quota_enforced && memory_limit_enforced {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}
