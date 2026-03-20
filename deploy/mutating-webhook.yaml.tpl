---
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingWebhookConfiguration
metadata:
  name: zero-trust-mtls-injection
  labels:
    app: zero-trust-admission-controller
webhooks:
  - name: zero-trust-mtls-injection.default.svc
    clientConfig:
      caBundle: "${CA_PEM_B64}"
      service:
        name: zero-trust-admission-controller
        namespace: zero-trust-system
        path: "/mutate"
    rules:
      - operations: ["CREATE", "UPDATE"]
        apiGroups: [""]
        apiVersions: ["v1"]
        resources: ["pods"]
        scope: "*"
    failurePolicy: Ignore
    admissionReviewVersions: ["v1"]
    sideEffects: None
    namespaceSelector:
      matchLabels:
        zero-trust.io/mtls: "enabled"
    timeoutSeconds: 5
