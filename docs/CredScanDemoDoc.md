# Azure Defender K8S In Cluster Defense Credential Scan Demo

---
## Table of Contents
- Files
- Demo flow
- TODO
---

## Files
### New files
- pkg
  - dataproviders
    - credscan - new package
      - credscan_client.go - credscan package 'header'
      - credscan_provider.go - credscan package implementation
      - CredScanResultsDoc.md - details of credscan server results
- policy
  - kubernetes-resource-credentials - new policy files for credscan
    - examples
      - good
        - healthy.yaml
      - violations
        - violatecontainpassword.yaml
    - BlockK8SResourceWithSecrets.json - policy definition
    - constraint.yaml
    - template.yaml

### Edited files
- webhook.yaml - upload 'side-car' 
- values.yaml
- main.go
- handler.go
- azd_sec_info_provider.go - add members to azdsecinfo structs
- azd_annotations_jsonpatch_generator.go - add credscan annotations patch

---
## Demo flow
- Install
  - Assign 'Kubernetes clusters should gate deployment of resources with secrets' policy from Azure Policy
    - Choose Deny or Audit.
    - Decide 'MatchingConfidenceThresholdForExcludingResourceWithSecrets' threshold. 
  - Add secret to your cluster in order to pull credScan Image
  - helm install
- After installation, deploying a pod with risk of secrets appearing in the pod's definition will results with block or audit
- Blocking a pod will result with a message describing the secret type

The credential scan server runs as a 'side-car' container to the main Webhook image.
Webhook container sends http requests (by localhost - running in the same pod) of kubernetes resources as a json string and get the scan results from credScan container.

---
## TODO
2. Support all kubernetes resources
3. Deny doesn't work. Currently, only audit works. 