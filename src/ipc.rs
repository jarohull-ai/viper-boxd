use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    fmt,
    io::{BufRead, BufReader, Read, Write},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub const IPC_VERSION: &str = "1.0";

/// Bound on any single JSON-line read (request, response, or stream
/// chunk), on both the server and client side. Generous relative to real
/// payloads (prompts are capped far below this by each gateway's own
/// `max_prompt_chars`), but finite: an unbounded `read_line` lets a
/// malformed or hostile peer grow a buffer without limit. Hitting the
/// limit mid-line yields a truncated, non-JSON line, which the existing
/// parse-error handling on both sides already rejects — no separate
/// error path is needed for it.
pub const MAX_LINE_BYTES: u64 = 1024 * 1024;

/// How long a single blocking read or write on an accepted server
/// connection may take before it is abandoned. Bounds the damage a peer
/// that stops reading (or never finishes sending) can do: without this,
/// `serve`'s blocking writes have no upper bound, and every gateway here
/// accepts connections on a single thread, so one stuck peer would stall
/// every other caller, not just itself.
#[cfg(unix)]
pub const SERVER_IO_TIMEOUT: Duration = Duration::from_secs(30);

/// Removes any stale socket at `path`, binds a fresh one, and restricts it
/// to the owning user (`0600`) rather than leaving it at the process's
/// umask — a Unix socket file's default permissions are not something
/// this code should depend on an external, per-deployment setting for,
/// especially for a gateway holding a real provider API key.
#[cfg(unix)]
pub fn bind_unix_socket(path: &str) -> std::io::Result<std::os::unix::net::UnixListener> {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::remove_file(path);
    let listener = std::os::unix::net::UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

/// Applies `SERVER_IO_TIMEOUT` to a freshly accepted connection. Every
/// gateway and the helper should call this immediately after `accept`,
/// before doing anything else with the stream.
#[cfg(unix)]
pub fn configure_server_stream(stream: &std::os::unix::net::UnixStream) -> std::io::Result<()> {
    stream.set_read_timeout(Some(SERVER_IO_TIMEOUT))?;
    stream.set_write_timeout(Some(SERVER_IO_TIMEOUT))?;
    Ok(())
}

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

/// One frame of a streaming `MODEL_GENERATE` reply (`params.stream: true`).
/// A stream is a sequence of these on the same connection, ending in
/// exactly one frame with `done: true`; a mid-stream failure still ends
/// with a `done: true` frame, carrying `error` instead of further `delta`.
/// See STREAM_PLAN.md. `Response` and `send_request` are unrelated to this
/// and unchanged: every non-streaming call keeps using them exactly as
/// before.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamChunk {
    pub version: String,
    pub request_id: String,
    pub audit_trace_id: String,
    pub sequence: u64,
    pub delta: String,
    pub done: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<IpcErrorBody>,
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

/// Builds one streaming frame. Mirrors `respond` for the non-streaming
/// case: every frame gets its own audit trace id.
pub fn stream_chunk(
    request_id: String,
    sequence: u64,
    delta: String,
    done: bool,
    error: Option<IpcErrorBody>,
) -> StreamChunk {
    StreamChunk {
        version: IPC_VERSION.into(),
        request_id,
        audit_trace_id: generate_audit_trace_id(),
        sequence,
        delta,
        done,
        error,
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
        .take(MAX_LINE_BYTES)
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

/// Sends one request and dispatches each `StreamChunk` frame in order to
/// `on_chunk` as it arrives, returning once a `done: true` frame is seen.
/// Unlike `send_request`, the read side has no fixed timeout: the gateway
/// enforces its own idle-chunk and max-stream-duration caps (STREAM_PLAN.md)
/// and closes the connection when they trip, which ends the client's
/// blocking read with EOF rather than requiring the client to guess a
/// timeout long enough for a legitimate long generation.
#[cfg(unix)]
pub fn send_streaming_request(
    socket_path: &str,
    request: &Request,
    mut on_chunk: impl FnMut(&StreamChunk),
) -> Result<(), ClientError> {
    use std::os::unix::net::UnixStream;
    let stream = UnixStream::connect(socket_path).map_err(ClientError::Io)?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(ClientError::Io)?;
    let encoded = serde_json::to_vec(request).map_err(ClientError::Json)?;
    {
        let mut writer = &stream;
        writer.write_all(&encoded).map_err(ClientError::Io)?;
        writer.write_all(b"\n").map_err(ClientError::Io)?;
        writer.flush().map_err(ClientError::Io)?;
    }
    // The per-line cap is reset before every read: a legitimate stream may
    // have many chunks in total, but each individual line must still be
    // bounded.
    let mut reader = BufReader::new(stream).take(MAX_LINE_BYTES);
    loop {
        reader.set_limit(MAX_LINE_BYTES);
        let mut line = String::new();
        let bytes_read = reader.read_line(&mut line).map_err(ClientError::Io)?;
        if bytes_read == 0 {
            return Err(ClientError::InvalidResponse(
                "connection closed before a done chunk".into(),
            ));
        }
        if line.trim().is_empty() {
            continue;
        }
        let chunk: StreamChunk = serde_json::from_str(&line).map_err(ClientError::Json)?;
        let done = chunk.done;
        on_chunk(&chunk);
        if done {
            return Ok(());
        }
    }
}

#[cfg(not(unix))]
pub fn send_streaming_request(
    _socket_path: &str,
    _request: &Request,
    _on_chunk: impl FnMut(&StreamChunk),
) -> Result<(), ClientError> {
    Err(ClientError::InvalidResponse(
        "Unix sockets are required".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::{
        generate_audit_trace_id, ipc_error, respond, send_request, send_streaming_request,
        stream_chunk, Request, IPC_VERSION, MAX_LINE_BYTES,
    };
    use serde_json::json;
    use std::{
        io::{BufRead, BufReader, Write},
        os::unix::net::UnixListener,
        thread,
    };

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

    fn temp_socket(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "viper-boxd-ipc-test-{name}-{}.sock",
            std::process::id()
        ))
    }

    #[test]
    fn send_request_stops_reading_at_the_line_size_cap_instead_of_growing_unbounded() {
        let path = temp_socket("oversized-response");
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).expect("bind test socket");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept test connection");
            let mut line = String::new();
            BufReader::new(stream.try_clone().expect("clone stream"))
                .read_line(&mut line)
                .expect("read request line");
            // No newline, far more than the cap: a hostile or broken peer
            // trying to make the reader grow without bound. Written in
            // chunks and stopped as soon as a write fails, which happens
            // once the client disconnects after hitting the cap - if the
            // cap were broken and the client tried to read all of this,
            // the loop completes anyway (100 MiB, not truly infinite), it
            // would just take far longer than the elapsed-time assertion
            // below allows.
            let chunk = vec![b'x'; 65536];
            for _ in 0..1600 {
                if stream.write_all(&chunk).is_err() {
                    break;
                }
            }
        });

        let request = Request {
            version: IPC_VERSION.into(),
            request_id: "req-1".into(),
            method: "status".into(),
            params: json!({}),
        };
        let start = std::time::Instant::now();
        let result = send_request(path.to_str().unwrap(), &request);
        let elapsed = start.elapsed();
        server.join().expect("server thread completes");
        let _ = std::fs::remove_file(&path);

        // Truncated at the cap, no trailing newline or valid JSON: must be
        // rejected, not hang or silently succeed.
        assert!(result.is_err());
        assert!(
            elapsed < std::time::Duration::from_secs(3),
            "stopping at the {MAX_LINE_BYTES}-byte cap should be fast, not read the full \
             oversized stream or wait out send_request's 5s timeout (took {elapsed:?})"
        );
    }

    fn serve_chunks(
        path: &std::path::Path,
        chunks: Vec<super::StreamChunk>,
    ) -> thread::JoinHandle<()> {
        let listener = UnixListener::bind(path).expect("bind test socket");
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept test connection");
            let mut line = String::new();
            BufReader::new(stream.try_clone().expect("clone stream"))
                .read_line(&mut line)
                .expect("read request line");
            for chunk in chunks {
                let encoded = serde_json::to_vec(&chunk).expect("chunk serializes");
                stream.write_all(&encoded).expect("write chunk");
                stream.write_all(b"\n").expect("write newline");
            }
            stream.flush().expect("flush");
        })
    }

    fn stream_request() -> Request {
        Request {
            version: IPC_VERSION.into(),
            request_id: "req-1".into(),
            method: "MODEL_GENERATE".into(),
            params: json!({"stream": true}),
        }
    }

    #[test]
    fn send_streaming_request_dispatches_chunks_in_order_and_stops_at_done() {
        let path = temp_socket("ok");
        let _ = std::fs::remove_file(&path);
        let server = serve_chunks(
            &path,
            vec![
                stream_chunk("req-1".into(), 0, "Hello".into(), false, None),
                stream_chunk("req-1".into(), 1, " world".into(), false, None),
                stream_chunk("req-1".into(), 2, "".into(), true, None),
            ],
        );

        let mut deltas = Vec::new();
        let mut saw_done = false;
        send_streaming_request(path.to_str().unwrap(), &stream_request(), |chunk| {
            deltas.push(chunk.delta.clone());
            saw_done = chunk.done;
        })
        .expect("stream completes");
        server.join().expect("server thread completes");
        let _ = std::fs::remove_file(&path);

        assert_eq!(deltas, vec!["Hello", " world", ""]);
        assert!(saw_done);
    }

    #[test]
    fn send_streaming_request_delivers_a_mid_stream_error_as_the_final_chunk() {
        let path = temp_socket("error");
        let _ = std::fs::remove_file(&path);
        let server = serve_chunks(
            &path,
            vec![
                stream_chunk("req-1".into(), 0, "partial".into(), false, None),
                stream_chunk(
                    "req-1".into(),
                    1,
                    "".into(),
                    true,
                    Some(ipc_error("ERR_MODEL_FAILED", "boom")),
                ),
            ],
        );

        let mut last_error: Option<String> = None;
        send_streaming_request(path.to_str().unwrap(), &stream_request(), |chunk| {
            if chunk.done {
                last_error = chunk.error.as_ref().map(|e| e.code.clone());
            }
        })
        .expect("protocol completes cleanly even though the stream reports an error");
        server.join().expect("server thread completes");
        let _ = std::fs::remove_file(&path);

        assert_eq!(last_error, Some("ERR_MODEL_FAILED".to_owned()));
    }

    #[test]
    fn send_streaming_request_errors_when_the_connection_closes_before_done() {
        let path = temp_socket("eof");
        let _ = std::fs::remove_file(&path);
        let server = serve_chunks(
            &path,
            vec![stream_chunk(
                "req-1".into(),
                0,
                "partial".into(),
                false,
                None,
            )],
        );

        let mut deltas = Vec::new();
        let result = send_streaming_request(path.to_str().unwrap(), &stream_request(), |chunk| {
            deltas.push(chunk.delta.clone());
        });
        server.join().expect("server thread completes");
        let _ = std::fs::remove_file(&path);

        assert!(result.is_err());
        assert_eq!(deltas, vec!["partial"]);
    }
}
