//! Minimal JSONL audit sink and Prometheus exposition formatter.

use serde::Serialize;
use std::{
    fs::OpenOptions,
    io::Write,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

/// Runtime counters exported without prompts, credentials or host paths.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Metrics {
    /// Active Box count.
    pub active_boxes: u64,
    /// Queued Box count.
    pub queued_boxes: u64,
    /// Sum of CPU quota percentages for active Boxes.
    pub cpu_quota_percent: u64,
    /// Sum of memory limits for active Boxes.
    pub memory_limit_bytes: u64,
    /// Cost in micro-USD reserved by configured model gateways.
    pub model_cost_micro_usd: u64,
}

impl Metrics {
    /// Renders the stable Prometheus text exposition payload.
    pub fn prometheus(&self) -> String {
        format!(
            "# TYPE viper_boxes_active gauge\nviper_boxes_active {}\n# TYPE viper_boxes_queued gauge\nviper_boxes_queued {}\n# TYPE viper_boxes_cpu_quota_percent gauge\nviper_boxes_cpu_quota_percent {}\n# TYPE viper_boxes_memory_limit_bytes gauge\nviper_boxes_memory_limit_bytes {}\n# TYPE viper_model_cost_micro_usd counter\nviper_model_cost_micro_usd {}\n",
            self.active_boxes, self.queued_boxes, self.cpu_quota_percent, self.memory_limit_bytes, self.model_cost_micro_usd
        )
    }
}

#[derive(Serialize)]
struct Event<'a, T: Serialize> {
    schema: &'static str,
    timestamp: String,
    timestamp_unix_ms: u128,
    duration_ms: u128,
    event: &'a str,
    fields: &'a T,
}

/// Formats the wall clock in UTC without trusting the host timezone.
pub fn utc_timestamp(now: std::time::SystemTime) -> String {
    let elapsed = now.duration_since(UNIX_EPOCH).unwrap_or_default();
    let seconds = elapsed.as_secs() as i64;
    let days = seconds.div_euclid(86_400);
    let day_seconds = seconds.rem_euclid(86_400);
    let z = days + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }).div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096).div_euclid(365);
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let month_prime = (5 * doy + 2).div_euclid(153);
    let day = doy - (153 * month_prime + 2).div_euclid(5) + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    let year = year + if month <= 2 { 1 } else { 0 };
    let hour = day_seconds / 3_600;
    let minute = (day_seconds % 3_600) / 60;
    let second = day_seconds % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Appends one JSON event with a `0600` owner-only file mode on Unix.
pub fn append_jsonl<T: Serialize>(
    path: &Path,
    event: &str,
    fields: &T,
    duration_ms: u128,
) -> std::io::Result<()> {
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(path)?;
    let now = SystemTime::now();
    let timestamp_unix_ms = now
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    serde_json::to_writer(
        &mut file,
        &Event {
            schema: "viper-boxd.audit.v0",
            timestamp: utc_timestamp(now),
            timestamp_unix_ms,
            duration_ms,
            event,
            fields,
        },
    )
    .map_err(std::io::Error::other)?;
    file.write_all(b"\n")?;
    file.flush()
}

#[cfg(test)]
mod tests {
    use super::{append_jsonl, utc_timestamp, Metrics};
    use serde_json::json;
    use std::time::UNIX_EPOCH;

    #[test]
    fn prometheus_contains_runtime_gauges() {
        let metrics = Metrics {
            active_boxes: 50,
            queued_boxes: 10,
            ..Metrics::default()
        };
        let text = metrics.prometheus();
        assert!(text.contains("viper_boxes_active 50"));
        assert!(text.contains("viper_boxes_queued 10"));
    }

    #[test]
    fn jsonl_event_is_parseable() {
        let path =
            std::env::temp_dir().join(format!("viper-observability-{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&path);
        append_jsonl(&path, "box_queued", &json!({"box_id":"BOX_1"}), 7).unwrap();
        let line = std::fs::read_to_string(&path).unwrap();
        let event = serde_json::from_str::<serde_json::Value>(line.trim()).unwrap();
        assert_eq!(event["event"], "box_queued");
        assert_eq!(event["duration_ms"], 7);
        assert!(event["timestamp"].as_str().unwrap().ends_with('Z'));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn utc_timestamp_is_stable_for_epoch() {
        assert_eq!(utc_timestamp(UNIX_EPOCH), "1970-01-01T00:00:00Z");
    }
}
