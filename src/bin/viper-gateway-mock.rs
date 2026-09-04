use serde_json::{json, Value};
use std::{
    env,
    io::{BufRead, BufReader, Read, Write},
    os::unix::net::UnixStream,
};
use viper_boxd::ipc::{ipc_error as error, respond as response, Request, Response, IPC_VERSION};
use viper_boxd::research_policy::{sanitize_html, ResearchPolicy};

fn handle(request: Request) -> Response {
    if request.version != IPC_VERSION {
        return response(
            request.request_id,
            Err(error(
                "ERR_UNSUPPORTED_SCHEMA",
                "unsupported gateway version",
            )),
        );
    }
    let id = request.request_id;
    let result = match request.method.as_str() {
        "SEARCH" => request.params.get("query").and_then(Value::as_str).filter(|v| !v.trim().is_empty()).map(|query| json!({
            "gateway": "mock-research-v0", "evidence_class": "UNTRUSTED_EVIDENCE",
            "query": query, "results": [{"title": "Mock result", "url": "https://example.invalid/mock", "snippet": "Deterministic mock evidence."}]
        })).ok_or_else(|| error("ERR_INVALID_REQUEST", "SEARCH requires params.query")),
        "FETCH" => request.params.get("url").and_then(Value::as_str).map(|url| {
            ResearchPolicy::mock().validate_fetch_url(url).map(|validated| json!({
                "gateway": "mock-research-v0", "evidence_class": "UNTRUSTED_EVIDENCE",
                "url": validated.as_str(), "content": sanitize_html("<p>Deterministic mock fetched evidence.</p>"), "content_sha256": "mock-sha256"
            })).map_err(|v| error(v.code, v.message))
        }).unwrap_or_else(|| Err(error("ERR_INVALID_REQUEST", "FETCH requires params.url"))),
        "MODEL_GENERATE" => request.params.get("prompt").and_then(Value::as_str).filter(|v| !v.is_empty()).map(|prompt| json!({
            "gateway": "mock-model-v0", "classification": "MODEL_OUTPUT",
            "text": format!("Mock response for: {prompt}")
        })).ok_or_else(|| error("ERR_INVALID_REQUEST", "MODEL_GENERATE requires params.prompt")),
        _ => Err(error("ERR_TOOL_NOT_ALLOWED", "unsupported gateway method")),
    };
    response(id, result)
}

fn serve(mut stream: UnixStream) -> std::io::Result<()> {
    let mut line = String::new();
    BufReader::new(stream.try_clone()?)
        .take(viper_boxd::ipc::MAX_LINE_BYTES)
        .read_line(&mut line)?;
    let reply = match serde_json::from_str::<Request>(&line) {
        Ok(request) => handle(request),
        Err(e) => response(
            "unknown".into(),
            Err(error("ERR_INVALID_REQUEST", e.to_string())),
        ),
    };
    serde_json::to_writer(&mut stream, &reply).map_err(std::io::Error::other)?;
    stream.write_all(b"\n")?;
    stream.flush()
}

fn main() -> std::io::Result<()> {
    let socket = env::args()
        .nth(1)
        .unwrap_or_else(|| "/tmp/viper-gateway-mock.sock".into());
    let listener = viper_boxd::ipc::bind_unix_socket(&socket)?;
    eprintln!("viper-gateway-mock listening on {socket}");
    for stream in listener.incoming().flatten() {
        if viper_boxd::ipc::configure_server_stream(&stream).is_err() {
            continue;
        }
        let _ = serve(stream);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::handle;
    use serde_json::json;
    use viper_boxd::ipc::{Request, IPC_VERSION};
    fn request(method: &str, params: serde_json::Value) -> Request {
        Request {
            version: IPC_VERSION.into(),
            request_id: "test".into(),
            method: method.into(),
            params,
        }
    }
    #[test]
    fn returns_untrusted_search_evidence() {
        let r = handle(request("SEARCH", json!({"query":"rust"})));
        assert!(r.ok);
        assert_eq!(r.result.unwrap()["evidence_class"], "UNTRUSTED_EVIDENCE");
    }
    #[test]
    fn rejects_unknown_method() {
        let r = handle(request("DELETE", json!({})));
        assert!(!r.ok);
        assert_eq!(r.error.unwrap().code, "ERR_TOOL_NOT_ALLOWED");
    }
    #[test]
    fn rejects_missing_fetch_url() {
        let r = handle(request("FETCH", json!({})));
        assert!(!r.ok);
    }
    #[test]
    fn rejects_wrong_version() {
        let mut r = request("SEARCH", json!({"query":"x"}));
        r.version = "0.9".into();
        assert_eq!(handle(r).error.unwrap().code, "ERR_UNSUPPORTED_SCHEMA");
    }
}
