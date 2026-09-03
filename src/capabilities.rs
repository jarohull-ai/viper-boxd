use serde::Serialize;
use std::{env, fs, path::Path};

#[derive(Debug, Serialize)]
pub struct CapabilityObservation {
    pub detected: bool,
    pub enforceable: bool,
    pub evidence: String,
}

#[derive(Debug, Serialize)]
pub struct CapabilityReport {
    pub schema: &'static str,
    pub probe_mode: &'static str,
    pub backend_ready: bool,
    pub platform: &'static str,
    pub capabilities: Capabilities,
}

#[derive(Debug, Serialize)]
pub struct Capabilities {
    pub mount_namespace: CapabilityObservation,
    pub network_namespace: CapabilityObservation,
    pub cgroup_v2: CapabilityObservation,
    pub user_namespaces: CapabilityObservation,
    pub systemd_run: CapabilityObservation,
}

impl Capabilities {
    pub fn supports_enforceable(&self, requirement: &str) -> bool {
        match requirement {
            "mount_namespace" => self.mount_namespace.enforceable,
            "network_policy" | "network_namespace" => self.network_namespace.enforceable,
            "cgroup_limits" | "cgroup_v2" => self.cgroup_v2.enforceable,
            "user_namespaces" => self.user_namespaces.enforceable,
            "systemd" | "systemd_run" => self.systemd_run.enforceable,
            _ => false,
        }
    }
}

fn presence(path: &str, evidence: &str) -> CapabilityObservation {
    let detected = Path::new(path).exists();
    CapabilityObservation {
        detected,
        // Detection alone never proves that the future backend can enforce it.
        enforceable: false,
        evidence: if detected {
            evidence.to_owned()
        } else {
            format!("not detected: {path}")
        },
    }
}

fn command_present(command: &str) -> bool {
    env::var_os("PATH")
        .into_iter()
        .flat_map(|paths| env::split_paths(&paths).collect::<Vec<_>>())
        .map(|dir| dir.join(command))
        .any(|candidate| candidate.is_file())
}

pub fn probe() -> CapabilityReport {
    #[cfg(target_os = "linux")]
    let platform = "linux";
    #[cfg(not(target_os = "linux"))]
    let platform = "unsupported";

    #[cfg(target_os = "linux")]
    let (mount_namespace, network_namespace, cgroup_v2, user_namespaces) = {
        let userns = fs::read_to_string("/proc/sys/user/max_user_namespaces")
            .ok()
            .and_then(|value| value.trim().parse::<u64>().ok())
            .map(|value| value > 0)
            .unwrap_or(false);
        (
            presence("/proc/self/ns/mnt", "current mount namespace is visible"),
            presence("/proc/self/ns/net", "current network namespace is visible"),
            presence(
                "/sys/fs/cgroup/cgroup.controllers",
                "cgroup v2 controllers are visible",
            ),
            CapabilityObservation {
                detected: userns,
                enforceable: false,
                evidence: if userns {
                    "user namespace quota is non-zero".to_owned()
                } else {
                    "user namespace quota is disabled or unavailable".to_owned()
                },
            },
        )
    };
    #[cfg(not(target_os = "linux"))]
    let (mount_namespace, network_namespace, cgroup_v2, user_namespaces) = (
        unavailable("Linux namespace probe is not available"),
        unavailable("Linux namespace probe is not available"),
        unavailable("Linux cgroup probe is not available"),
        unavailable("Linux user namespace probe is not available"),
    );

    let systemd_run_detected = command_present("systemd-run");
    let systemd_run = CapabilityObservation {
        detected: systemd_run_detected,
        enforceable: false,
        evidence: if systemd_run_detected {
            "systemd-run executable is present; user-unit enforcement not tested".to_owned()
        } else {
            "systemd-run executable is not present".to_owned()
        },
    };

    CapabilityReport {
        schema: "viper-boxd.capabilities.v0",
        probe_mode: "READ_ONLY",
        backend_ready: false,
        platform,
        capabilities: Capabilities {
            mount_namespace,
            network_namespace,
            cgroup_v2,
            user_namespaces,
            systemd_run,
        },
    }
}

#[cfg(not(target_os = "linux"))]
fn unavailable(evidence: &str) -> CapabilityObservation {
    CapabilityObservation {
        detected: false,
        enforceable: false,
        evidence: evidence.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::probe;

    #[test]
    fn probe_is_explicitly_non_enforcing() {
        let report = probe();
        assert_eq!(report.schema, "viper-boxd.capabilities.v0");
        assert_eq!(report.probe_mode, "READ_ONLY");
        assert!(!report.backend_ready);
        assert!(!report.capabilities.mount_namespace.enforceable);
        assert!(!report.capabilities.network_namespace.enforceable);
        assert!(!report.capabilities.cgroup_v2.enforceable);
    }
}
