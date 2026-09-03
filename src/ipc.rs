use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    fmt,
    io::{BufRead, BufReader, Write},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub const IPC_VERSION: &str = "1.0";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub version: String,
    pub request_id: String,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub version: String,
    pub request_id: String,
    pub audit_trace_id: String,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<IpcErrorBody>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcErrorBody {
    pub code: String,
    pub message: String,
}

static AUDIT_TRACE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Process-unique audit trace id for one gateway request/response pair.
/// Derived from a monotonic counter, PID, and timestamp instead of an
/// external randomness source, keeping the dependency tree unchanged.
pub fn generate_audit_trace_id() -> String {
    let sequence = AUDIT_TRACE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let seed = format!("{}-{nanos}-{sequence}", std::process::id());
    format!("trace_{}", &jfp_box::sha256_hex(seed.as_bytes())[..16])
}

pub fn ipc_error(code: &str, message: impl Into<String>) -> IpcErrorBody {
    IpcErrorBody {
        code: code.into(),
        message: message.into(),
    }
}

/// Builds a versioned, audit-traced response from a gateway or helper
/// handler result. Shared so every backend stamps responses the same way.
pub fn respond(request_id: String, result: Result<Value, IpcErrorBody>) -> Response {
    let audit_trace_id = generate_audit_trace_id();
    match result {
        Ok(result) => Response {
            version: IPC_VERSION.into(),
            request_id,
            audit_trace_id,
            ok: true,
            result: Some(result),
            error: None,
        },
        Err(error) => Response {
            version: IPC_VERSION.into(),
            request_id,
            audit_trace_id,
            ok: false,
            result: None,
            error: Some(error),
        },
    }
}

#[derive(Debug)]
pub enum ClientError {
    Io(std::io::Error),
    Json(serde_json::Error),
    InvalidResponse(String),
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "IPC I/O error: {e}"),
            Self::Json(e) => write!(f, "IPC JSON error: {e}"),
            Self::InvalidResponse(e) => write!(f, "invalid IPC response: {e}"),
        }
    }
}

impl std::error::Error for ClientError {}

#[cfg(unix)]
pub fn send_request(socket_path: &str, request: &Request) -> Result<Response, ClientError> {
    use std::os::unix::net::UnixStream;
    let mut stream = UnixStream::connect(socket_path).map_err(ClientError::Io)?;
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(ClientError::Io)?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(ClientError::Io)?;
    let encoded = serde_json::to_vec(request).map_err(ClientError::Json)?;
    stream.write_all(&encoded).map_err(ClientError::Io)?;
    stream.write_all(b"\n").map_err(ClientError::Io)?;
    stream.flush().map_err(ClientError::Io)?;
    let mut line = String::new();
    BufReader::new(stream)
        .read_line(&mut line)
        .map_err(ClientError::Io)?;
    if line.trim().is_empty() {
        return Err(ClientError::InvalidResponse("empty response".into()));
    }
    serde_json::from_str(&line).map_err(ClientError::Json)
}

#[cfg(not(unix))]
pub fn send_request(_socket_path: &str, _request: &Request) -> Result<Response, ClientError> {
    Err(ClientError::InvalidResponse(
        "Unix sockets are required".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::{generate_audit_trace_id, ipc_error, respond, Request, IPC_VERSION};
    use serde_json::json;

    #[test]
    fn request_has_versioned_json_lines_shape() {
        let request = Request {
            version: IPC_VERSION.into(),
            request_id: "req-1".into(),
            method: "status".into(),
            params: json!({"handle": "mock:BOX_1"}),
        };
        let encoded = serde_json::to_string(&request).expect("request serializes");
        assert!(encoded.contains("\"version\":\"1.0\""));
        assert!(encoded.contains("\"request_id\":\"req-1\""));
        assert!(encoded.contains("\"method\":\"status\""));
        assert!(encoded.contains("\"params\""));
    }

    #[test]
    fn audit_trace_ids_are_unique_per_call() {
        let first = generate_audit_trace_id();
        let second = generate_audit_trace_id();
        assert_ne!(first, second);
        assert!(first.starts_with("trace_"));
        assert_eq!(first.len(), "trace_".len() + 16);
    }

    #[test]
    fn responses_carry_an_audit_trace_id() {
        let ok = respond("req-1".into(), Ok(json!({"k": "v"})));
        assert!(!ok.audit_trace_id.is_empty());
        assert!(ok.audit_trace_id.starts_with("trace_"));

        let err = respond("req-2".into(), Err(ipc_error("ERR_X", "bad")));
        assert!(!err.audit_trace_id.is_empty());
        assert_ne!(ok.audit_trace_id, err.audit_trace_id);
    }
}
