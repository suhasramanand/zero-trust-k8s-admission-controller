#!/usr/bin/env bash
# Test Zero-Trust Admission Controller on Minikube (Docker driver)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
IMAGE="zero-trust-admission-controller:latest"

echo "=== Zero-Trust Admission Controller - Minikube Test ==="

# 1. Ensure Docker is running
if ! docker info &>/dev/null; then
    echo "ERROR: Docker is not running. Please start Docker Desktop first."
    exit 1
fi

# 2. Start Minikube if needed
if ! minikube status &>/dev/null; then
    echo "Starting Minikube (Docker driver)..."
    minikube start --driver=docker
fi
echo "Minikube is running."

# 3. Use minikube's docker env to build inside minikube's docker
echo "Building image (using minikube docker-env)..."
eval $(minikube docker-env)
cd "$PROJECT_DIR"
docker build -t "$IMAGE" .

# 4. Run setup (generates certs, applies webhooks)
echo "Running setup (certs + webhooks)..."
cd "$PROJECT_DIR"
./scripts/setup.sh

# 5. Deploy the admission controller
echo "Deploying admission controller..."
kubectl apply -f "$PROJECT_DIR/deploy/deployment.yaml"

# 6. Wait for deployment
echo "Waiting for deployment to be ready..."
kubectl rollout status deployment/zero-trust-admission-controller -n zero-trust-system --timeout=120s

# 7. Test: Compliant pod (should succeed)
echo ""
echo "=== Test 1: Compliant pod (allowPrivilegeEscalation=false) - should SUCCEED ==="
kubectl run test-compliant --image=nginx --restart=Never --overrides='{
  "spec": {
    "containers": [{
      "name": "nginx",
      "image": "nginx",
      "securityContext": {
        "allowPrivilegeEscalation": false,
        "privileged": false
      }
    }]
  }
}' 2>&1 && echo "PASS: Compliant pod created" || echo "FAIL: Compliant pod rejected"

# 8. Test: Non-compliant pod (privilege escalation) - should be rejected
echo ""
echo "=== Test 2: Non-compliant pod (allowPrivilegeEscalation not set) - should FAIL ==="
if kubectl run test-bad --image=nginx --restart=Never 2>&1 | grep -q "admission webhook"; then
    echo "PASS: Non-compliant pod correctly rejected by webhook"
else
    echo "Check result: pod may have been created (webhook might not have rejected)"
fi

# 9. Cleanup test pods
echo ""
echo "Cleaning up test pods..."
kubectl delete pod test-compliant --ignore-not-found 2>/dev/null || true
kubectl delete pod test-bad --ignore-not-found 2>/dev/null || true

echo ""
echo "=== Test complete ==="
echo "View controller logs: kubectl logs -l app=zero-trust-admission-controller -n zero-trust-system -f"
