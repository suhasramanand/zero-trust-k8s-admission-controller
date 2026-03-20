---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: zero-trust-admission-controller
  labels:
    app: zero-trust-admission-controller
webhooks:
  - name: zero-trust-pod-security.default.svc
    clientConfig:
      caBundle: "${CA_PEM_B64}"
      service:
        name: zero-trust-admission-controller
        namespace: zero-trust-system
        path: "/validate"
    namespaceSelector:
      matchExpressions:
        - key: kubernetes.io/metadata.name
          operator: NotIn
          values: [zero-trust-system]
    rules:
      - operations: ["CREATE", "UPDATE"]
        apiGroups: [""]
        apiVersions: ["v1"]
        resources: ["pods"]
        scope: "*"
    failurePolicy: Fail
    admissionReviewVersions: ["v1"]
    sideEffects: None
    timeoutSeconds: 5
