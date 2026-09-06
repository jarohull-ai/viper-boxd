use std::{
    io::{BufRead, BufReader, Cursor, Read},
    sync::{Arc, Mutex},
    thread,
};
use viper_boxd::{
    admission::{AdmissionController, AdmissionDecision},
    ipc::MAX_LINE_BYTES,
};

#[test]
#[ignore = "nightly DoS regression: creates 1000 worker threads"]
fn thousand_concurrent_spawn_admissions_keep_excess_queued() {
    let controller = Arc::new(Mutex::new(AdmissionController::new(50).unwrap()));
    let mut workers = Vec::new();
    for index in 0..1000 {
        let controller = Arc::clone(&controller);
        workers.push(thread::spawn(move || {
            controller
                .lock()
                .expect("admission lock")
                .admit(&format!("BOX_{index:04}"))
                .expect("unique box id")
        }));
    }

    let decisions: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().expect("worker completes"))
        .collect();
    let started = decisions
        .iter()
        .filter(|decision| **decision == AdmissionDecision::Start)
        .count();
    let queued = decisions
        .iter()
        .filter(|decision| matches!(decision, AdmissionDecision::Queued { .. }))
        .count();
    let controller = controller.lock().expect("admission lock");

    assert_eq!(started, 50);
    assert_eq!(queued, 950);
    assert_eq!(controller.active_count(), 50);
    assert_eq!(controller.queued_count(), 950);
}

#[test]
#[ignore = "nightly DoS regression: allocates a 100 MiB malformed payload"]
fn one_hundred_mib_payload_is_cut_at_the_ipc_line_limit() {
    let payload = vec![b'X'; 100 * 1024 * 1024];
    let mut line = String::new();
    let bytes_read = BufReader::new(Cursor::new(payload))
        .take(MAX_LINE_BYTES)
        .read_line(&mut line)
        .expect("bounded read completes");

    assert_eq!(bytes_read as u64, MAX_LINE_BYTES);
    assert_eq!(line.len() as u64, MAX_LINE_BYTES);
}
