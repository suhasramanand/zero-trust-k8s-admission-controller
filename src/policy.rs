//! Policy-as-code configuration loading and validation rules

use serde::Deserialize;
use std::path::Path;
use std::{fs, io};

#[derive(Debug, Clone, Deserialize)]
pub struct PolicyConfig {
    pub policies: Policies,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Policies {
    #[serde(default)]
    pub pod_security: PodSecurityPolicy,
    #[serde(default)]
    pub mtls_injection: MtlsInjectionPolicy,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct PodSecurityPolicy {
    #[serde(default = "default_true")]
    pub deny_privilege_escalation: bool,
    #[serde(default = "default_true")]
    pub deny_privileged: bool,
    #[serde(default)]
    pub require_read_only_root_filesystem: bool,
    #[serde(default = "default_true")]
    pub deny_host_namespaces: bool,
    #[serde(default)]
    pub require_non_root: bool,
    #[serde(default)]
    pub blocked_volumes: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct MtlsInjectionPolicy {
    #[serde(default)]
    pub namespace_selector: MtlsNamespaceSelector,
    #[serde(default = "default_volume_name")]
    pub volume_name: String,
    #[serde(default = "default_mount_path")]
    pub mount_path: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct MtlsNamespaceSelector {
    #[serde(rename = "zero-trust.io/mtls", default)]
    pub mtls_enabled: String,
}

impl MtlsNamespaceSelector {
    pub fn matches(&self, labels: &std::collections::HashMap<String, String>) -> bool {
        if self.mtls_enabled.is_empty() {
            return false;
        }
        labels
            .get("zero-trust.io/mtls")
            .map(|v| v == &self.mtls_enabled)
            .unwrap_or(false)
    }
}

fn default_true() -> bool {
    true
}

fn default_volume_name() -> String {
    "mtls-certs".to_string()
}

fn default_mount_path() -> String {
    "/var/run/mtls".to_string()
}

impl PolicyConfig {
    pub fn load<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let contents = fs::read_to_string(path)?;
        let config: PolicyConfig = serde_yaml::from_str(&contents)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        Ok(config)
    }

    /// Load from path or return default if file doesn't exist
    pub fn load_or_default<P: AsRef<Path>>(path: P) -> Self {
        Self::load(path).unwrap_or_else(|_| Self::default())
    }
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            policies: Policies {
                pod_security: PodSecurityPolicy::default(),
                mtls_injection: MtlsInjectionPolicy::default(),
            },
        }
    }
}
