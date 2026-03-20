#!/usr/bin/env bash
# Zero-Trust Admission Controller - TLS & Webhook Setup
# Generates CA and server certs, applies webhook configurations
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
DEPLOY_DIR="$PROJECT_DIR/deploy"

# Require: private IP reachable from cluster (for local dev)
# Use 0.0.0.0 or service DNS when running in-cluster
ADMISSION_IP="${ADMISSION_PRIVATE_IP:-0.0.0.0}"

echo "=== Zero-Trust Admission Controller Setup ==="
echo "Admission controller IP/host: $ADMISSION_IP"

# Cleanup existing webhooks
kubectl delete validatingwebhookconfiguration zero-trust-admission-controller 2>/dev/null || true
kubectl delete mutatingwebhookconfiguration zero-trust-mtls-injection 2>/dev/null || true

# Create output directory for certs
CERT_DIR="$PROJECT_DIR/certs"
mkdir -p "$CERT_DIR"
cd "$CERT_DIR"

# Generate CA
echo "Generating CA certificate..."
openssl req -nodes -new -x509 -keyout ca.key -out ca.crt \
    -subj "/CN=zero-trust-admission-controller-ca" -days 3650

# Generate server key
openssl genrsa -out admission-tls.key 2048

# Create extfile for SAN (include both default and zero-trust-system for compatibility)
echo "subjectAltName = DNS:zero-trust-admission-controller,DNS:zero-trust-admission-controller.default.svc,DNS:zero-trust-admission-controller.zero-trust-system,DNS:zero-trust-admission-controller.zero-trust-system.svc,DNS:zero-trust-admission-controller.zero-trust-system.svc.cluster.local,IP:${ADMISSION_IP}" > extfile.cnf

# Generate and sign server cert
openssl req -new -key admission-tls.key \
    -subj "/CN=zero-trust-admission-controller.zero-trust-system.svc" |
    openssl x509 -req -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out admission-tls.crt -extfile extfile.cnf -days 365

# Copy certs to project root for local dev (expected by default TLS paths)
cp admission-tls.crt "$PROJECT_DIR/admission-controller-tls.crt"
cp admission-tls.key "$PROJECT_DIR/admission-controller-tls.key"

# Apply to cluster only if kubectl is available and cluster is reachable
if kubectl cluster-info &>/dev/null; then
    # Create namespace and TLS secret for in-cluster deployment
    kubectl create namespace zero-trust-system 2>/dev/null || true
    kubectl delete secret zero-trust-admission-tls -n zero-trust-system 2>/dev/null || true
    kubectl create secret tls zero-trust-admission-tls -n zero-trust-system \
        --cert=admission-tls.crt --key=admission-tls.key

    # Create policy configmap
    kubectl create configmap zero-trust-policy-config -n zero-trust-system \
        --from-file="$PROJECT_DIR/config/policies.yaml" \
        --dry-run=client -o yaml | kubectl apply -n zero-trust-system -f -

    # Apply webhook configs (for in-cluster with Service)
    CA_PEM_B64="$(openssl base64 -A < ca.crt)"
    sed -e "s/\${CA_PEM_B64}/$CA_PEM_B64/g" \
        "$DEPLOY_DIR/validating-webhook.yaml.tpl" | kubectl apply -f -
    sed -e "s/\${CA_PEM_B64}/$CA_PEM_B64/g" \
        "$DEPLOY_DIR/mutating-webhook.yaml.tpl" | kubectl apply -f -
    echo "Webhook configurations applied to cluster."
else
    echo "Kubernetes cluster not reachable. Certs generated for local dev."
fi

echo ""
echo "=== Setup complete ==="
echo "Certs generated in: $CERT_DIR"
echo ""
echo "For local development (webhook URL to your machine):"
echo "  export ADMISSION_PRIVATE_IP=<your-ip-reachable-from-cluster>"
echo "  ./scripts/setup.sh"
echo "  cargo run"
echo ""
echo "For in-cluster deployment:"
echo "  docker build -t zero-trust-admission-controller:latest ."
echo "  kind load docker-image zero-trust-admission-controller:latest  # if using kind"
echo "  kubectl apply -f deploy/deployment.yaml"
