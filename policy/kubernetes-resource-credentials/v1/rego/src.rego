package k8sazuredefenderblockresourceswithsecrets

# This violation checks if the resource contain secrets.
violation[{"msg": msg, "details": details}] {
    credScanAnnotations := getResourceCredScanAnnotations(input.review)
    weakness := credScanAnnotations.credScanInfo[_]
    weakness.matchingConfidence > input.parameters.matchingConfidenceThresholdForExcludingResourceWithSecrets
    msg := sprintf("%v, Secret found in the resource. The secret type is: <%v>. Match prefix: <%v>", [credScanAnnotations.ScanStatus, weakness.credentialInfo.name, weakness.match.matchPrefix])
    details := weakness
    }

# Gets review object and returns unnmarshelled scan resulsts (i.e. as array of scan results).
getResourceCredScanAnnotations(review) = credScanAnnotations{
    scanResults := review.object.metadata.annotations["resource.credential.scan.info"]
    credScanAnnotations := json.unmarshal(scanResults)
  }