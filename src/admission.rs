//! Deterministic global Box admission and FIFO queueing.

use std::collections::{BTreeSet, VecDeque};

/// Result of attempting to admit a Box.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionDecision {
    /// Capacity was available and the Box may start now.
    Start,
    /// Capacity is exhausted; the Box is retained in FIFO order.
    Queued { position: usize },
}

/// In-memory global limit and FIFO queue. Persistent lifecycle recovery is a
/// separate concern; on process restart the daemon reconstructs active units
/// from systemd before accepting new work.
#[derive(Debug)]
pub struct AdmissionController {
    limit: usize,
    active: BTreeSet<String>,
    queued: VecDeque<String>,
}

impl AdmissionController {
    /// Creates a controller. A zero limit is invalid because it would turn
    /// every request into an unserviceable queue entry.
    pub fn new(limit: usize) -> Result<Self, String> {
        if limit == 0 {
            return Err("max active Boxes must be at least one".into());
        }
        Ok(Self {
            limit,
            active: BTreeSet::new(),
            queued: VecDeque::new(),
        })
    }

    /// Applies admission for a new unique Box ID.
    pub fn admit(&mut self, box_id: &str) -> Result<AdmissionDecision, String> {
        if box_id.is_empty()
            || self.active.contains(box_id)
            || self.queued.iter().any(|item| item == box_id)
        {
            return Err("duplicate or invalid Box ID".into());
        }
        // Once a request is waiting, later arrivals must not jump the FIFO
        // queue merely because a just-freed slot has not been drained yet.
        if self.active.len() < self.limit && self.queued.is_empty() {
            self.active.insert(box_id.to_owned());
            Ok(AdmissionDecision::Start)
        } else {
            self.queued.push_back(box_id.to_owned());
            Ok(AdmissionDecision::Queued {
                position: self.queued.len(),
            })
        }
    }

    /// Releases an active Box. The caller subsequently uses [`Self::start_next`]
    /// to start queued work only after its runtime resources are actually
    /// cleaned up.
    pub fn release(&mut self, box_id: &str) -> bool {
        self.active.remove(box_id)
    }

    /// Reserves one FIFO queued Box when capacity is available.
    pub fn start_next(&mut self) -> Option<String> {
        if self.active.len() >= self.limit {
            return None;
        }
        let next = self.queued.pop_front()?;
        self.active.insert(next.clone());
        Some(next)
    }

    /// Removes a still-queued request, for cancellation before it starts.
    pub fn cancel_queued(&mut self, box_id: &str) -> bool {
        let Some(position) = self.queued.iter().position(|item| item == box_id) else {
            return false;
        };
        self.queued.remove(position);
        true
    }

    /// Active Box count.
    pub fn active_count(&self) -> usize {
        self.active.len()
    }

    /// Queued request count.
    pub fn queued_count(&self) -> usize {
        self.queued.len()
    }

    /// Configured active limit.
    pub fn limit(&self) -> usize {
        self.limit
    }
}

#[cfg(test)]
mod tests {
    use super::{AdmissionController, AdmissionDecision};
    use std::sync::{Arc, Mutex};
    use std::thread;

    #[test]
    fn sixty_requests_keep_fifty_active_and_ten_queued() {
        let mut controller = AdmissionController::new(50).unwrap();
        for index in 0..60 {
            let decision = controller.admit(&format!("BOX_{index:02}")).unwrap();
            if index < 50 {
                assert_eq!(decision, AdmissionDecision::Start);
            } else {
                assert_eq!(
                    decision,
                    AdmissionDecision::Queued {
                        position: index - 49
                    }
                );
            }
        }
        assert_eq!(controller.active_count(), 50);
        assert_eq!(controller.queued_count(), 10);
        assert!(controller.release("BOX_00"));
        assert_eq!(controller.start_next(), Some("BOX_50".into()));
        assert_eq!(controller.active_count(), 50);
        assert_eq!(controller.queued_count(), 9);
    }

    #[test]
    fn thousand_concurrent_admissions_do_not_exceed_capacity() {
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
}
