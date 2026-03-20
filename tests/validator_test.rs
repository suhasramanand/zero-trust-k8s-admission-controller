//! Unit tests for pod security validation

use k8s_openapi::api::core::v1::{Container, Pod, PodSpec, SecurityContext};
use zero_trust_admission_controller::policy::PodSecurityPolicy;
use zero_trust_admission_controller::validate_pod;

fn policy_strict() -> PodSecurityPolicy {
    PodSecurityPolicy {
        deny_privilege_escalation: true,
        deny_privileged: true,
        require_read_only_root_filesystem: false,
        deny_host_namespaces: true,
        require_non_root: false,
        blocked_volumes: vec!["hostPath".to_string(), "privileged".to_string()],
    }
}

fn pod_with_privilege_escalation() -> Pod {
    Pod {
        spec: Some(PodSpec {
            containers: vec![Container {
                name: "test".to_string(),
                security_context: Some(SecurityContext {
                    allow_privilege_escalation: Some(true),
                    privileged: None,
                    ..Default::default()
                }),
                ..Default::default()
            }],
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn pod_compliant() -> Pod {
    Pod {
        spec: Some(PodSpec {
            containers: vec![Container {
                name: "test".to_string(),
                security_context: Some(SecurityContext {
                    allow_privilege_escalation: Some(false),
                    privileged: Some(false),
                    ..Default::default()
                }),
                ..Default::default()
            }],
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn pod_privileged() -> Pod {
    Pod {
        spec: Some(PodSpec {
            containers: vec![Container {
                name: "test".to_string(),
                security_context: Some(SecurityContext {
                    allow_privilege_escalation: Some(false),
                    privileged: Some(true),
                    ..Default::default()
                }),
                ..Default::default()
            }],
            ..Default::default()
        }),
        ..Default::default()
    }
}

#[test]
fn test_deny_privilege_escalation() {
    let policy = policy_strict();
    let pod = pod_with_privilege_escalation();
    let result = validate_pod(&pod, &policy);
    assert!(result.is_err());
    let errs = result.unwrap_err();
    assert!(errs.iter().any(|e| e.contains("allowPrivilegeEscalation")));
}

#[test]
fn test_accept_compliant_pod() {
    let policy = policy_strict();
    let pod = pod_compliant();
    let result = validate_pod(&pod, &policy);
    assert!(result.is_ok());
}

#[test]
fn test_deny_privileged_container() {
    let policy = policy_strict();
    let pod = pod_privileged();
    let result = validate_pod(&pod, &policy);
    assert!(result.is_err());
    let errs = result.unwrap_err();
    assert!(errs.iter().any(|e| e.contains("privileged")));
}
