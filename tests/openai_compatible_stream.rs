//! Proves OpenAiCompatibleStreamTransport's SSE parsing against realistic
//! wire bytes, not just high-level canned chunks: the `data: {...}` shape,
//! the literal `data: [DONE]` terminator, OpenRouter's `:`-prefixed
//! keep-alive comment lines, and a mid-stream `error` event. Shapes are
//! taken from OpenAI's and OpenRouter's own published streaming docs.

use std::{
    io::{BufRead, BufReader, Write},
    net::{TcpListener, TcpStream},
    thread,
};
use viper_boxd::model_provider::{generate_stream, OpenAiCompatibleStreamTransport};

fn read_request_headers(stream: &TcpStream) {
    let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
            break;
        }
    }
}

/// Sends `body` as the full SSE response, then closes the connection —
/// `Connection: close` framing, no chunked encoding needed for a test
/// double that just wants the body accepted as complete.
fn spawn_sse_server(body: String) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
    let addr = listener.local_addr().expect("read test server address");
    let handle = thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            read_request_headers(&stream);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n{body}"
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });
    (format!("http://{addr}"), handle)
}

fn run(endpoint: &str) -> (Result<(), viper_boxd::research_policy::PolicyViolation>, Vec<(String, bool)>) {
    let mut deltas = Vec::new();
    let result = generate_stream(
        &OpenAiCompatibleStreamTransport {
            api_key: "test-key".into(),
        },
        endpoint,
        "gpt-4o-mini",
        "hi",
        1000,
        128,
        5,
        30,
        &mut |delta, done| deltas.push((delta.to_owned(), done)),
    );
    (result, deltas)
}

#[test]
fn delivers_deltas_in_order_and_stops_at_literal_done_line() {
    let body = concat!(
        "data: {\"choices\":[{\"delta\":{\"role\":\"assistant\",\"content\":\"\"},\"finish_reason\":null}]}\n\n",
        "data: {\"choices\":[{\"delta\":{\"content\":\"Hello\"},\"finish_reason\":null}]}\n\n",
        "data: {\"choices\":[{\"delta\":{\"content\":\" world\"},\"finish_reason\":null}]}\n\n",
        "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n",
        "data: [DONE]\n\n",
    );
    let (endpoint, server) = spawn_sse_server(body.to_owned());
    let (result, deltas) = run(&endpoint);
    server.join().expect("server thread completes");

    result.expect("stream completes");
    assert_eq!(
        deltas,
        vec![
            (String::new(), false),
            ("Hello".to_owned(), false),
            (" world".to_owned(), false),
            (String::new(), false),
            (String::new(), true),
        ]
    );
}

#[test]
fn skips_openrouter_style_keep_alive_comment_lines() {
    let body = concat!(
        ": OPENROUTER PROCESSING\n\n",
        "data: {\"choices\":[{\"delta\":{\"content\":\"Hi\"},\"finish_reason\":null}]}\n\n",
        ": OPENROUTER PROCESSING\n\n",
        "data: [DONE]\n\n",
    );
    let (endpoint, server) = spawn_sse_server(body.to_owned());
    let (result, deltas) = run(&endpoint);
    server.join().expect("server thread completes");

    result.expect("stream completes despite comment lines");
    assert_eq!(deltas, vec![("Hi".to_owned(), false), (String::new(), true)]);
}

#[test]
fn a_mid_stream_error_event_fails_the_call_without_a_done_chunk() {
    let body = "data: {\"error\":{\"message\":\"insufficient credits\",\"type\":\"invalid_request_error\"}}\n\n";
    let (endpoint, server) = spawn_sse_server(body.to_owned());
    let (result, deltas) = run(&endpoint);
    server.join().expect("server thread completes");

    let error = result.expect_err("an error event must fail the stream");
    assert_eq!(error.code, "ERR_MODEL_FAILED");
    assert!(error.message.contains("insufficient credits"));
    assert!(deltas.is_empty(), "on_delta must not be called for an error event");
}

#[test]
fn malformed_json_in_a_data_line_fails_the_call() {
    let body = "data: not valid json\n\n";
    let (endpoint, server) = spawn_sse_server(body.to_owned());
    let (result, _deltas) = run(&endpoint);
    server.join().expect("server thread completes");

    let error = result.expect_err("malformed JSON must fail the stream");
    assert_eq!(error.code, "ERR_MODEL_FAILED");
}

#[test]
fn a_connection_that_closes_without_done_fails_the_call() {
    let body = "data: {\"choices\":[{\"delta\":{\"content\":\"partial\"},\"finish_reason\":null}]}\n\n";
    let (endpoint, server) = spawn_sse_server(body.to_owned());
    let (result, deltas) = run(&endpoint);
    server.join().expect("server thread completes");

    let error = result.expect_err("closing before [DONE] must be treated as a failure");
    assert_eq!(error.code, "ERR_MODEL_FAILED");
    assert_eq!(deltas, vec![("partial".to_owned(), false)]);
}
