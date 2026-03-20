//! Pod security validation logic - enforces zero-trust policies

use crate::policy::PodSecurityPolicy;
use k8s_openapi::api::core::v1::{Pod, PodSpec};
use std::collections::HashMap;

/// Result of validating a pod against security policies
pub type ValidationResult = Result<(), Vec<String>>;

/// Validate a pod spec against the configured pod security policy
pub fn validate_pod(pod: &Pod, policy: &PodSecurityPolicy) -> ValidationResult {
    let spec = pod.spec.as_ref().ok_or_else(|| {
        vec!["Pod spec is required".to_string()]
    })?;

    let mut errors = Vec::new();

    // Validate init containers
    for (i, container) in spec.init_containers.as_deref().unwrap_or_default().iter().enumerate() {
        if let Err(e) = validate_container_security(&container.security_context, policy, "initContainer", i) {
            errors.extend(e);
        }
    }

    // Validate main containers
    for (i, container) in spec.containers.iter().enumerate() {
        if let Err(e) = validate_container_security(&container.security_context, policy, "container", i) {
            errors.extend(e);
        }
    }

    // Validate pod-level security
    if let Err(e) = validate_pod_level_security(spec, policy) {
        errors.extend(e);
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

fn validate_container_security(
    ctx: &Option<k8s_openapi::api::core::v1::SecurityContext>,
    policy: &PodSecurityPolicy,
    container_type: &str,
    index: usize,
) -> ValidationResult {
    let mut errors = Vec::new();
    let ctx = ctx.as_ref();

    // Check allowPrivilegeEscalation
    if policy.deny_privilege_escalation {
        let allowed = ctx
            .and_then(|c| c.allow_privilege_escalation)
            .unwrap_or(true); // Default is true if not set - K8s allows escalation by default
        if allowed {
            errors.push(format!(
                "{}[{}]: allowPrivilegeEscalation must be false (privilege escalation not allowed in zero-trust environment)",
                container_type, index
            ));
        }
    }

    // Check privileged
    if policy.deny_privileged {
        let privileged = ctx
            .and_then(|c| c.privileged)
            .unwrap_or(false);
        if privileged {
            errors.push(format!(
                "{}[{}]: privileged containers are not allowed",
                container_type, index
            ));
        }
    }

    // Check readOnlyRootFilesystem
    if policy.require_read_only_root_filesystem {
        let read_only = ctx
            .and_then(|c| c.read_only_root_filesystem)
            .unwrap_or(false);
        if !read_only {
            errors.push(format!(
                "{}[{}]: readOnlyRootFilesystem must be true",
                container_type, index
            ));
        }
    }

    // Check runAsNonRoot
    if policy.require_non_root {
        let non_root = ctx
            .and_then(|c| c.run_as_non_root)
            .unwrap_or(false);
        if !non_root {
            errors.push(format!(
                "{}[{}]: runAsNonRoot must be true",
                container_type, index
            ));
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

fn validate_pod_level_security(spec: &PodSpec, policy: &PodSecurityPolicy) -> ValidationResult {
    let mut errors = Vec::new();

    // Check host namespaces
    if policy.deny_host_namespaces {
        if spec.host_pid.unwrap_or(false) {
            errors.push("hostPID is not allowed".to_string());
        }
        if spec.host_ipc.unwrap_or(false) {
            errors.push("hostIPC is not allowed".to_string());
        }
        if spec.host_network.unwrap_or(false) {
            errors.push("hostNetwork is not allowed".to_string());
        }
    }

    // Check volumes
    for vol in spec.volumes.iter().flatten() {
        let vol_type = get_volume_type(vol);
        if policy.blocked_volumes.iter().any(|b| vol_type == *b) {
            errors.push(format!("Volume type '{}' is not allowed", vol_type));
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

fn get_volume_type(vol: &k8s_openapi::api::core::v1::Volume) -> &'static str {
    if vol.host_path.is_some() {
        "hostPath"
    } else if vol.azure_file.is_some() {
        "azureFile"
    } else if vol.cephfs.is_some() {
        "cephfs"
    } else if vol.csi.is_some() {
        "csi"
    } else if vol.downward_api.is_some() {
        "downwardAPI"
    } else if vol.empty_dir.is_some() {
        "emptyDir"
    } else if vol.ephemeral.is_some() {
        "ephemeral"
    } else if vol.fc.is_some() {
        "fc"
    } else if vol.flex_volume.is_some() {
        "flexVolume"
    } else if vol.flocker.is_some() {
        "flocker"
    } else if vol.gce_persistent_disk.is_some() {
        "gcePersistentDisk"
    } else if vol.git_repo.is_some() {
        "gitRepo"
    } else if vol.glusterfs.is_some() {
        "glusterfs"
    } else if vol.iscsi.is_some() {
        "iscsi"
    } else if vol.nfs.is_some() {
        "nfs"
    } else if vol.persistent_volume_claim.is_some() {
        "persistentVolumeClaim"
    } else if vol.photon_persistent_disk.is_some() {
        "photonPersistentDisk"
    } else if vol.projected.is_some() {
        "projected"
    } else if vol.portworx_volume.is_some() {
        "portworxVolume"
    } else if vol.quobyte.is_some() {
        "quobyte"
    } else if vol.rbd.is_some() {
        "rbd"
    } else if vol.scale_io.is_some() {
        "scaleIO"
    } else if vol.secret.is_some() {
        "secret"
    } else if vol.storageos.is_some() {
        "storageos"
    } else if vol.vsphere_volume.is_some() {
        "vsphereVolume"
    } else if vol.config_map.is_some() {
        "configMap"
    } else {
        "unknown"
    }
}

/// Extract namespace labels for mTLS injection decision (from admission request context)
pub fn namespace_has_mtls_label(labels: &HashMap<String, String>, expected_value: &str) -> bool {
    labels
        .get("zero-trust.io/mtls")
        .map(|v| v == expected_value)
        .unwrap_or(false)
}
