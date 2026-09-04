//! Proves `AnthropicStreamTransport`'s SSE parsing against realistic wire
//! bytes copied from Anthropic's own published streaming example
//! (`event:`/`data:` pairs, `message_stop` as the terminator, no `[DONE]`
//! sentinel), not just high-level canned chunks.

use std::{
    io::{BufRead, BufReader, Write},
    net::{TcpListener, TcpStream},
    thread,
};
use viper_boxd::model_provider::{generate_stream, AnthropicStreamTransport};

fn read_request_headers(stream: &TcpStream) {
    let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
            break;
        }
    }
}

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
        &AnthropicStreamTransport {
            api_key: "test-key".into(),
        },
        endpoint,
        "claude-sonnet-5",
        "hi",
        1000,
        128,
        5,
        30,
        &mut |delta, done| deltas.push((delta.to_owned(), done)),
    );
    (result, deltas)
}

/// Bytes taken directly from Anthropic's own "Full HTTP stream response"
/// documentation example, including the ping keep-alive event.
const REAL_EXAMPLE_BODY: &str = concat!(
    "event: message_start\n",
    "data: {\"type\": \"message_start\", \"message\": {\"id\": \"msg_1\", \"type\": \"message\", \"role\": \"assistant\", \"content\": [], \"model\": \"claude-sonnet-5\", \"stop_reason\": null, \"stop_sequence\": null, \"usage\": {\"input_tokens\": 25, \"output_tokens\": 1}}}\n",
    "\n",
    "event: content_block_start\n",
    "data: {\"type\": \"content_block_start\", \"index\": 0, \"content_block\": {\"type\": \"text\", \"text\": \"\"}}\n",
    "\n",
    "event: ping\n",
    "data: {\"type\": \"ping\"}\n",
    "\n",
    "event: content_block_delta\n",
    "data: {\"type\": \"content_block_delta\", \"index\": 0, \"delta\": {\"type\": \"text_delta\", \"text\": \"Hello\"}}\n",
    "\n",
    "event: content_block_delta\n",
    "data: {\"type\": \"content_block_delta\", \"index\": 0, \"delta\": {\"type\": \"text_delta\", \"text\": \"!\"}}\n",
    "\n",
    "event: content_block_stop\n",
    "data: {\"type\": \"content_block_stop\", \"index\": 0}\n",
    "\n",
    "event: message_delta\n",
    "data: {\"type\": \"message_delta\", \"delta\": {\"stop_reason\": \"end_turn\", \"stop_sequence\": null}, \"usage\": {\"output_tokens\": 15}}\n",
    "\n",
    "event: message_stop\n",
    "data: {\"type\": \"message_stop\"}\n",
    "\n",
);

#[test]
fn delivers_text_deltas_and_stops_at_message_stop() {
    let (endpoint, server) = spawn_sse_server(REAL_EXAMPLE_BODY.to_owned());
    let (result, deltas) = run(&endpoint);
    server.join().expect("server thread completes");

    result.expect("stream completes");
    assert_eq!(
        deltas,
        vec![("Hello".to_owned(), false), ("!".to_owned(), false), (String::new(), true)]
    );
}

#[test]
fn skips_non_text_events_without_emitting_deltas_for_them() {
    // message_start, content_block_start, ping, content_block_stop, and
    // message_delta in REAL_EXAMPLE_BODY must all be silently skipped:
    // exactly 3 on_delta calls total (2 text deltas + the final done).
    let (endpoint, server) = spawn_sse_server(REAL_EXAMPLE_BODY.to_owned());
    let (result, deltas) = run(&endpoint);
    server.join().expect("server thread completes");

    result.expect("stream completes");
    assert_eq!(deltas.len(), 3);
}

#[test]
fn a_mid_stream_error_event_fails_the_call_without_a_done_chunk() {
    let body = concat!(
        "event: error\n",
        "data: {\"type\": \"error\", \"error\": {\"type\": \"overloaded_error\", \"message\": \"Overloaded\"}}\n",
        "\n",
    );
    let (endpoint, server) = spawn_sse_server(body.to_owned());
    let (result, deltas) = run(&endpoint);
    server.join().expect("server thread completes");

    let error = result.expect_err("an error event must fail the stream");
    assert_eq!(error.code, "ERR_MODEL_FAILED");
    assert!(error.message.contains("Overloaded"));
    assert!(deltas.is_empty(), "on_delta must not be called for an error event");
}

#[test]
fn skips_non_text_delta_content_block_deltas() {
    // input_json_delta (tool use) must not be surfaced as a text delta.
    let body = concat!(
        "event: content_block_delta\n",
        "data: {\"type\": \"content_block_delta\", \"index\": 1, \"delta\": {\"type\": \"input_json_delta\", \"partial_json\": \"{\\\"x\\\":\"}}\n",
        "\n",
        "event: message_stop\n",
        "data: {\"type\": \"message_stop\"}\n",
        "\n",
    );
    let (endpoint, server) = spawn_sse_server(body.to_owned());
    let (result, deltas) = run(&endpoint);
    server.join().expect("server thread completes");

    result.expect("stream completes");
    assert_eq!(deltas, vec![(String::new(), true)]);
}

#[test]
fn a_connection_that_closes_without_message_stop_fails_the_call() {
    let body = concat!(
        "event: content_block_delta\n",
        "data: {\"type\": \"content_block_delta\", \"index\": 0, \"delta\": {\"type\": \"text_delta\", \"text\": \"partial\"}}\n",
        "\n",
    );
    let (endpoint, server) = spawn_sse_server(body.to_owned());
    let (result, deltas) = run(&endpoint);
    server.join().expect("server thread completes");

    let error = result.expect_err("closing before message_stop must be treated as a failure");
    assert_eq!(error.code, "ERR_MODEL_FAILED");
    assert_eq!(deltas, vec![("partial".to_owned(), false)]);
}
