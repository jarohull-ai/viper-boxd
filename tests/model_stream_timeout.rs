//! Proves the idle-chunk timeout and max-stream-duration caps
//! (STREAM_PLAN.md) actually terminate a stalled backend, not just that
//! they're config-validated. A deliberately slow/stuck TCP server is the
//! only way to exercise this: a live Ollama call responds too quickly.

use std::{
    io::{BufRead, BufReader, Write},
    net::{TcpListener, TcpStream},
    thread,
    time::{Duration, Instant},
};
use viper_boxd::model_provider::{generate_stream, OllamaStreamTransport};

fn read_request_headers(stream: &TcpStream) {
    let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
            break;
        }
    }
}

/// Accepts one connection, reads the request, then holds the connection
/// open without ever writing a body — the server is alive but silent,
/// exactly the case an idle-chunk timeout exists to catch.
fn spawn_silent_server(hold_open: Duration) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
    let addr = listener.local_addr().expect("read test server address");
    let handle = thread::spawn(move || {
        if let Ok((stream, _)) = listener.accept() {
            read_request_headers(&stream);
            thread::sleep(hold_open);
        }
    });
    (format!("http://{addr}"), handle)
}

/// Accepts one connection, sends one JSON line, then goes silent without
/// ever sending a `done: true` line — the gap-after-first-chunk case.
fn spawn_stalls_after_one_chunk(hold_open: Duration) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
    let addr = listener.local_addr().expect("read test server address");
    let handle = thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            read_request_headers(&stream);
            let body = b"{\"response\":\"partial\",\"done\":false}\n";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.write_all(body);
            let _ = stream.write_all(b"\r\n");
            let _ = stream.flush();
            thread::sleep(hold_open);
        }
    });
    (format!("http://{addr}"), handle)
}

#[test]
fn idle_timeout_terminates_a_server_that_never_sends_a_first_chunk() {
    let (endpoint, server) = spawn_silent_server(Duration::from_secs(5));
    let start = Instant::now();
    let mut deltas = Vec::new();
    let error = generate_stream(
        &OllamaStreamTransport,
        &endpoint,
        "mistral:7b",
        "hi",
        1000,
        128,
        /* idle_timeout_seconds */ 1,
        /* max_stream_duration_seconds */ 30,
        &mut |delta, done| deltas.push((delta.to_owned(), done)),
    )
    .expect_err("a silent server must trip the idle timeout");
    let elapsed = start.elapsed();

    assert_eq!(error.code, "ERR_MODEL_FAILED");
    assert!(error.message.contains("idle timeout"));
    assert!(deltas.is_empty());
    assert!(
        elapsed < Duration::from_secs(3),
        "idle timeout should fire near 1s, not wait out the server's 5s hold (took {elapsed:?})"
    );
    let _ = server; // server thread is left to finish on its own; see STREAM_PLAN.md
}

#[test]
fn idle_timeout_terminates_a_server_that_stalls_after_one_chunk() {
    let (endpoint, server) = spawn_stalls_after_one_chunk(Duration::from_secs(5));
    let start = Instant::now();
    let mut deltas = Vec::new();
    let error = generate_stream(
        &OllamaStreamTransport,
        &endpoint,
        "mistral:7b",
        "hi",
        1000,
        128,
        /* idle_timeout_seconds */ 1,
        /* max_stream_duration_seconds */ 30,
        &mut |delta, done| deltas.push((delta.to_owned(), done)),
    )
    .expect_err("a server that stalls mid-stream must trip the idle timeout");
    let elapsed = start.elapsed();

    assert_eq!(error.code, "ERR_MODEL_FAILED");
    assert!(error.message.contains("idle timeout"));
    assert_eq!(deltas, vec![("partial".to_owned(), false)]);
    assert!(
        elapsed < Duration::from_secs(3),
        "idle timeout should fire near 1s after the first chunk, not wait out the server's 5s hold (took {elapsed:?})"
    );
    let _ = server;
}

#[test]
fn max_stream_duration_bounds_a_server_that_sends_data_faster_than_the_idle_timeout() {
    // A server that keeps the connection alive with periodic bytes would
    // defeat an idle-only timeout; max_stream_duration is the backstop.
    // reqwest's own client-level timeout enforces this bound (STREAM_PLAN.md
    // "Implementation note"), so a max_stream_duration well under the
    // server's hold time must still cut the call off.
    let (endpoint, server) = spawn_silent_server(Duration::from_secs(10));
    let start = Instant::now();
    let error = generate_stream(
        &OllamaStreamTransport,
        &endpoint,
        "mistral:7b",
        "hi",
        1000,
        128,
        /* idle_timeout_seconds */ 30,
        /* max_stream_duration_seconds */ 2,
        &mut |_, _| {},
    )
    .expect_err("max_stream_duration must bound an idle-but-alive connection");
    let elapsed = start.elapsed();

    assert_eq!(error.code, "ERR_MODEL_FAILED");
    assert!(
        elapsed < Duration::from_secs(5),
        "max_stream_duration should cut the call off near 2s, not wait out the server's 10s hold (took {elapsed:?})"
    );
    let _ = server;
}
