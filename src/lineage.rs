//! Durable, fail-closed parent/child policy records for Box admission.
//!
//! The store contains policy snapshots, never prompts, provider credentials or
//! host paths.  Production services use `/var/lib/viper-boxd/lineage`; tests
//! and unprivileged development may explicitly select another directory.

use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::Write,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

static WRITE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Versioned subset of a profile which an inherited child may only narrow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicySnapshot {
    /// Helper-visible backend requirements.
    pub required_backend: Vec<String>,
    /// Administrator-owned logical gateway references.
    pub gateway_refs: Vec<String>,
    /// Maximum Box lifetime.
    pub ttl_seconds: u64,
    /// CPU quota percentage.
    pub cpu_quota_percent: u64,
    /// Memory limit in bytes.
    pub memory_limit_bytes: u64,
    /// Must be `STRICT` for the current helper.
    pub filesystem_mode: String,
    /// Must be `scratch` for the current helper.
    pub write_target: String,
}

impl PolicySnapshot {
    /// Returns whether this policy is no broader than `parent`.
    pub fn is_narrower_than(&self, parent: &Self) -> bool {
        let child_gateways: BTreeSet<&str> = self.gateway_refs.iter().map(String::as_str).collect();
        let parent_gateways: BTreeSet<&str> =
            parent.gateway_refs.iter().map(String::as_str).collect();
        self.filesystem_mode == "STRICT"
            && self.write_target == "scratch"
            && parent.filesystem_mode == "STRICT"
            && parent.write_target == "scratch"
            && child_gateways.is_subset(&parent_gateways)
            && self.ttl_seconds <= parent.ttl_seconds
            && self.cpu_quota_percent <= parent.cpu_quota_percent
            && self.memory_limit_bytes <= parent.memory_limit_bytes
    }
}

/// One durable lineage entry, stored as a single atomic JSON document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineageRecord {
    /// Schema identifier.
    pub schema: String,
    /// Box identifier, also used as the filename key.
    pub box_id: String,
    /// Optional immediate parent Box identifier.
    pub parent_box_id: Option<String>,
    /// JFP audit correlation identifier.
    pub audit_trace_id: String,
    /// UTC timestamp emitted by the trusted caller.
    pub created_at: String,
    /// Effective policy after parent narrowing.
    pub policy: PolicySnapshot,
}

/// Durable lineage store error.
#[derive(Debug)]
pub enum LineageError {
    /// Filesystem failure.
    Io(std::io::Error),
    /// Malformed or unsupported JSON record.
    Json(serde_json::Error),
    /// A record violates the store contract.
    Invalid(String),
}

impl std::fmt::Display for LineageError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "lineage I/O: {error}"),
            Self::Json(error) => write!(formatter, "lineage JSON: {error}"),
            Self::Invalid(error) => write!(formatter, "lineage record: {error}"),
        }
    }
}

impl std::error::Error for LineageError {}

impl From<std::io::Error> for LineageError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for LineageError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

/// In-memory index backed by one file per Box.
#[derive(Debug)]
pub struct LineageStore {
    directory: PathBuf,
    records: BTreeMap<String, LineageRecord>,
}

impl LineageStore {
    /// Opens a store and restores every existing record. A corrupt record
    /// makes the entire startup fail closed rather than silently dropping a
    /// parent relation.
    pub fn open(directory: impl Into<PathBuf>) -> Result<Self, LineageError> {
        let directory = directory.into();
        fs::create_dir_all(&directory)?;
        #[cfg(unix)]
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
        let mut records = BTreeMap::new();
        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            if !entry.file_type()?.is_file()
                || entry.path().extension().and_then(|item| item.to_str()) != Some("json")
            {
                continue;
            }
            let bytes = fs::read(entry.path())?;
            let record: LineageRecord = serde_json::from_slice(&bytes)?;
            validate_record(&record)?;
            if entry.file_name() != format!("{}.json", record.box_id).as_str() {
                return Err(LineageError::Invalid(
                    "record filename does not match Box ID".into(),
                ));
            }
            if records.insert(record.box_id.clone(), record).is_some() {
                return Err(LineageError::Invalid("duplicate Box record".into()));
            }
        }
        for record in records.values() {
            if let Some(parent_id) = record.parent_box_id.as_deref() {
                let parent = records.get(parent_id).ok_or_else(|| {
                    LineageError::Invalid(format!("unknown parent Box ID {parent_id}"))
                })?;
                if !record.policy.is_narrower_than(&parent.policy) {
                    return Err(LineageError::Invalid(
                        "restored child policy would broaden its parent".into(),
                    ));
                }
            }
        }
        Ok(Self { directory, records })
    }

    /// Reads a restored record by Box ID.
    pub fn get(&self, box_id: &str) -> Option<&LineageRecord> {
        self.records.get(box_id)
    }

    /// Number of restored or registered records.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether the store has no lineage records.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Registers and atomically persists a policy. Existing records are
    /// immutable: a Box ID cannot be replayed with a broader policy.
    pub fn register(&mut self, record: LineageRecord) -> Result<(), LineageError> {
        validate_record(&record)?;
        if self.records.contains_key(&record.box_id) {
            return Err(LineageError::Invalid(
                "Box ID already has a lineage record".into(),
            ));
        }
        if let Some(parent_id) = record.parent_box_id.as_deref() {
            let parent = self.records.get(parent_id).ok_or_else(|| {
                LineageError::Invalid(format!("unknown parent Box ID {parent_id}"))
            })?;
            if !record.policy.is_narrower_than(&parent.policy) {
                return Err(LineageError::Invalid(
                    "child policy would broaden its parent".into(),
                ));
            }
        }
        let path = self.path_for(&record.box_id)?;
        let temporary = self.directory.join(format!(
            ".{}.{}.tmp",
            record.box_id,
            WRITE_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let bytes = serde_json::to_vec_pretty(&record)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(&bytes)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        self.records.insert(record.box_id.clone(), record);
        Ok(())
    }

    fn path_for(&self, box_id: &str) -> Result<PathBuf, LineageError> {
        if !valid_box_id(box_id) {
            return Err(LineageError::Invalid("invalid Box ID".into()));
        }
        Ok(self.directory.join(format!("{box_id}.json")))
    }
}

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

fn valid_box_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 48
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

fn validate_record(record: &LineageRecord) -> Result<(), LineageError> {
    if record.schema != "viper-boxd.lineage.v0" {
        return Err(LineageError::Invalid("unsupported schema".into()));
    }
    if !valid_box_id(&record.box_id) || record.audit_trace_id.trim().is_empty() {
        return Err(LineageError::Invalid(
            "invalid Box ID or audit trace".into(),
        ));
    }
    if record.policy.filesystem_mode != "STRICT" || record.policy.write_target != "scratch" {
        return Err(LineageError::Invalid(
            "only STRICT scratch policy is supported".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{LineageRecord, LineageStore, PolicySnapshot};
    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn directory() -> PathBuf {
        std::env::temp_dir().join(format!(
            "viper-lineage-test-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    fn policy(gateway_refs: &[&str], ttl: u64) -> PolicySnapshot {
        PolicySnapshot {
            required_backend: vec!["systemd".into()],
            gateway_refs: gateway_refs.iter().map(|value| (*value).into()).collect(),
            ttl_seconds: ttl,
            cpu_quota_percent: 50,
            memory_limit_bytes: 512,
            filesystem_mode: "STRICT".into(),
            write_target: "scratch".into(),
        }
    }

    fn record(box_id: &str, parent_box_id: Option<&str>, policy: PolicySnapshot) -> LineageRecord {
        LineageRecord {
            schema: "viper-boxd.lineage.v0".into(),
            box_id: box_id.into(),
            parent_box_id: parent_box_id.map(str::to_owned),
            audit_trace_id: format!("TRACE_{box_id}"),
            created_at: "2026-09-05T00:00:00Z".into(),
            policy,
        }
    }

    #[test]
    fn restart_restores_parent_child_relationship() {
        let directory = directory();
        let mut store = LineageStore::open(&directory).unwrap();
        store
            .register(record("PARENT", None, policy(&["MODEL:ONE"], 60)))
            .unwrap();
        store
            .register(record("CHILD", Some("PARENT"), policy(&["MODEL:ONE"], 30)))
            .unwrap();
        drop(store);

        let restored = LineageStore::open(&directory).unwrap();
        assert_eq!(restored.len(), 2);
        assert_eq!(
            restored.get("CHILD").unwrap().parent_box_id.as_deref(),
            Some("PARENT")
        );
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn broadening_child_is_rejected() {
        let directory = directory();
        let mut store = LineageStore::open(&directory).unwrap();
        store
            .register(record("PARENT", None, policy(&[], 30)))
            .unwrap();
        assert!(store
            .register(record("CHILD", Some("PARENT"), policy(&["MODEL:ONE"], 60)))
            .is_err());
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn restart_rejects_a_persisted_orphan_child() {
        let directory = directory();
        let mut store = LineageStore::open(&directory).unwrap();
        store
            .register(record("PARENT", None, policy(&["MODEL:ONE"], 60)))
            .unwrap();
        drop(store);
        let orphan = record("ORPHAN", Some("MISSING"), policy(&["MODEL:ONE"], 30));
        fs::write(
            directory.join("ORPHAN.json"),
            serde_json::to_vec(&orphan).unwrap(),
        )
        .unwrap();
        assert!(LineageStore::open(&directory).is_err());
        let _ = fs::remove_dir_all(directory);
    }
}
