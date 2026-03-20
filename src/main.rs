//! Zero-Trust Kubernetes Admission Controller
//!
//! Validating webhook that enforces pod security standards and prevents privilege escalation.
//! Mutating webhook for mTLS certificate injection in zero-trust namespaces.

use zero_trust_admission_controller::{policy::PolicyConfig, validate_pod};

use axum::{Json, Router, routing::post};
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use kube::core::{
    DynamicObject, Resource, ResourceExt,
    admission::{AdmissionRequest, AdmissionResponse, AdmissionReview},
};
use k8s_openapi::api::core::v1::Pod;
use std::{error::Error, net::SocketAddr, path::Path, sync::Arc};
use tokio::net::TcpListener;
use tokio_rustls::{rustls::pki_types::CertificateDer, rustls::ServerConfig, TlsAcceptor};
use tower_http::trace::TraceLayer;
use tower::Service;
use tracing::*;

/// Shared application state
struct AppState {
    policy: PolicyConfig,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Required for rustls 0.23+
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,zero_trust_admission_controller=debug".into()),
        )
        .init();

    // Load policy-as-code configuration
    let policy_path = std::env::var("POLICY_CONFIG")
        .unwrap_or_else(|_| "config/policies.yaml".to_string());
    let policy = PolicyConfig::load_or_default(&policy_path);
    info!("Loaded policy from {} (or using defaults)", policy_path);

    let state = Arc::new(AppState { policy });

    let app = Router::new()
        .route("/validate", post(validate_handler))
        .route("/mutate", post(mutate_handler))
        .with_state(state)
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(tower_http::trace::DefaultMakeSpan::new().level(Level::INFO)),
        );

    let addr: SocketAddr = format!(
        "{}:8443",
        std::env::var("ADMISSION_PRIVATE_IP").unwrap_or_else(|_| "0.0.0.0".to_string())
    )
    .parse()?;

    let cert_path = std::env::var("TLS_CERT_FILE")
        .unwrap_or_else(|_| "admission-controller-tls.crt".to_string());
    let key_path = std::env::var("TLS_KEY_FILE")
        .unwrap_or_else(|_| "admission-controller-tls.key".to_string());

    let tls_acceptor = TlsAcceptor::from(load_rustls_config(&cert_path, &key_path)?);
    let tcp_listener = TcpListener::bind(addr).await?;

    info!("Zero-Trust Admission Controller listening on {} (TLS)", addr);

    loop {
        let tower_service = app.clone();
        let tls_acceptor = tls_acceptor.clone();

        let (stream, addr) = tcp_listener.accept().await?;

        tokio::spawn(async move {
            let Ok(tls_stream) = tls_acceptor.accept(stream).await else {
                error!("TLS handshake failed for connection from {}", addr);
                return;
            };

            let stream = TokioIo::new(tls_stream);
            let hyper_service = hyper::service::service_fn(move |req: hyper::Request<Incoming>| {
                tower_service.clone().call(req)
            });

            if let Err(err) = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                .serve_connection(stream, hyper_service)
                .await
            {
                warn!("Error serving connection from {}: {}", addr, err);
            }
        });
    }
}

fn load_rustls_config(cert_path: &str, key_path: &str) -> Result<Arc<ServerConfig>, Box<dyn Error>> {
    let cert_file = std::fs::File::open(Path::new(cert_path))?;
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut std::io::BufReader::new(cert_file))
        .filter_map(|r| r.ok())
        .map(|c| c.into_owned().into())
        .collect();

    let key_file = std::fs::File::open(Path::new(key_path))?;
    let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(key_file))?
        .ok_or("No private key found in key file")?;

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("Invalid cert/key: {}", e))?;

    Ok(Arc::new(config))
}

/// Validating webhook - enforces pod security policies
async fn validate_handler(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    Json(body): Json<serde_json::Value>,
) -> Json<AdmissionReview<DynamicObject>> {
    let review: AdmissionReview<DynamicObject> = match serde_json::from_value(body) {
        Ok(r) => r,
        Err(err) => {
            error!("Invalid admission review: {}", err);
            return Json(
                AdmissionResponse::invalid(err.to_string())
                    .into_review(),
            );
        }
    };
    let req: AdmissionRequest<DynamicObject> = match review.try_into() {
        Ok(req) => req,
        Err(_) => {
            error!("Invalid admission request: missing request field");
            return Json(
                AdmissionResponse::invalid("Missing request in AdmissionReview".to_string())
                    .into_review(),
            );
        }
    };

    let mut res = AdmissionResponse::from(&req);

    if let Some(obj) = &req.object {
        let name = obj.name_any();
        let kind = req.kind.kind.clone();

        // Only validate Pod resources
        if kind == "Pod" {
            let pod: Pod = match obj.clone().try_parse() {
                Ok(p) => p,
                Err(e) => {
                    error!("Failed to parse pod: {}", e);
                    return Json(res.deny(format!("Invalid pod spec: {}", e)).into_review());
                }
            };

            match validate_pod(&pod, &state.policy.policies.pod_security) {
                Ok(()) => {
                    info!("Accepted: {:?} on Pod/{}", req.operation, name);
                }
                Err(errors) => {
                    let msg = errors.join("; ");
                    warn!("Denied: {:?} on Pod/{} - {}", req.operation, name, msg);
                    res = res.deny(msg);
                }
            }
        } else {
            // Non-pod resources pass through
            info!("Accepted: {:?} on {}/{} (not a Pod, no validation)", req.operation, kind, name);
        }
    }

    Json(res.into_review())
}

/// Mutating webhook - injects mTLS certificates into pods in zero-trust namespaces
async fn mutate_handler(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    Json(body): Json<serde_json::Value>,
) -> Json<AdmissionReview<DynamicObject>> {
    let review: AdmissionReview<DynamicObject> = match serde_json::from_value(body) {
        Ok(r) => r,
        Err(err) => {
            error!("Invalid admission review: {}", err);
            return Json(
                AdmissionResponse::invalid(err.to_string())
                    .into_review(),
            );
        }
    };
    let req: AdmissionRequest<DynamicObject> = match review.try_into() {
        Ok(req) => req,
        Err(_) => {
            error!("Invalid admission request: missing request field");
            return Json(
                AdmissionResponse::invalid("Missing request in AdmissionReview".to_string())
                    .into_review(),
            );
        }
    };

    let mut res = AdmissionResponse::from(&req);

    if let Some(obj) = req.object {
        let name = obj.name_any();
        let kind = req.kind.kind.clone();

        if kind == "Pod" {
            let pod_labels: std::collections::HashMap<String, String> = obj
                .meta()
                .labels
                .as_ref()
                .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
                .unwrap_or_default();

            // Get namespace labels from ObjectMeta - for pods, namespace labels come from request
            // In admission, we get namespace from req.namespace; namespace labels would need
            // a separate API call. For simplicity, check for pod annotation as opt-in.
            let mtls_annotation = obj.meta().annotations.as_ref().and_then(|a| {
                a.get("zero-trust.io/mtls").cloned()
            });
            let mtls_policy = &state.policy.policies.mtls_injection;
            let should_inject = mtls_annotation.as_deref() == Some("enabled")
                || (!mtls_policy.namespace_selector.mtls_enabled.is_empty()
                    && mtls_policy.namespace_selector.matches(&pod_labels));

            if should_inject {
                info!("Injecting mTLS certs into Pod/{}", name);
                let mut patch_ops = Vec::new();

                // Add volume for mTLS certs (expects secret 'mtls-certs' to exist in namespace)
                if obj.data.get("spec").and_then(|s| s.get("volumes")).is_none() {
                    patch_ops.push(serde_json::json!({
                        "op": "add",
                        "path": "/spec/volumes",
                        "value": []
                    }));
                }

                let volume = serde_json::json!({
                    "name": mtls_policy.volume_name,
                    "secret": {
                        "secretName": "mtls-certs",
                        "optional": true
                    }
                });
                patch_ops.push(serde_json::json!({
                    "op": "add",
                    "path": "/spec/volumes/-",
                    "value": volume
                }));

                // Add volume mount to each container
                if let Some(containers) = obj.data.get("spec").and_then(|s| s.get("containers")) {
                    if let Some(containers_arr) = containers.as_array() {
                        for (i, container) in containers_arr.iter().enumerate() {
                            if container.get("volumeMounts").is_none() {
                                patch_ops.push(serde_json::json!({
                                    "op": "add",
                                    "path": format!("/spec/containers/{}/volumeMounts", i),
                                    "value": []
                                }));
                            }
                            let mount = serde_json::json!({
                                "name": mtls_policy.volume_name,
                                "readOnly": true,
                                "mountPath": mtls_policy.mount_path
                            });
                            patch_ops.push(serde_json::json!({
                                "op": "add",
                                "path": format!("/spec/containers/{}/volumeMounts/-", i),
                                "value": mount
                            }));
                        }
                    }
                }

                let patch_json = serde_json::Value::Array(patch_ops);
                if let Ok(patch) = serde_json::from_value::<json_patch::Patch>(patch_json) {
                    if let Ok(res_with_patch) = res.clone().with_patch(patch) {
                        res = res_with_patch;
                    } else {
                        warn!("Failed to apply mTLS patch");
                    }
                }
            }
        }
    }

    Json(res.into_review())
}
