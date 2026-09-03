# Profile Schema (Design Draft)

Profiles are trusted configuration, not agent-provided manifests. This draft
defines the minimum shape that the simulator must resolve.

```toml
schema = "viper-boxd.profile.v0"
profile_id = "RESEARCH_READONLY_V1"
workspace_class = "project"
network_mode = "RESEARCH"
direct_network = "DENY"
allowed_gateways = ["MODEL_GATEWAY", "RESEARCH_GATEWAY"]
tool_bindings = ["MODEL_GENERATE", "SEARCH", "FETCH"]
read_paths = ["workspace"]
write_target = "scratch"
required_backend = ["mount_namespace", "network_policy", "cgroup_limits"]
execution_ttl_seconds = 300
cpu_quota_percent = 50
memory_limit_bytes = 1073741824
max_model_tokens = 12000
max_research_requests = 30
max_fetch_bytes = 5242880
evidence_class = "UNTRUSTED"
output_schema = "EVIDENCE_REPORT_V1"
```

The concrete schema is not stable yet. Any field that grants authority must be
resolved from an administrator-owned registry and validated against the JFP
manifest before execution.
