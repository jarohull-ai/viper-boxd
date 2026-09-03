use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    fmt,
    io::{BufRead, BufReader, Write},
    time::Duration,
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
    use super::{Request, IPC_VERSION};
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
}
