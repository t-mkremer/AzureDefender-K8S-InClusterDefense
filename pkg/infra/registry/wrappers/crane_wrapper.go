package wrappers

import (
	"github.com/pkg/errors"
	"time"
)

// ICraneWrapper wraps crane operations
type ICraneWrapper interface {
	// Digest get image digest using image ref using crane Digest call
	Digest(ref string) (string, error)
}

// CraneWrapper wraps crane operations
type CraneWrapper struct{
	retryAttempts int
	retryDuration	time.Duration
}

// Digest get image digest using image ref using crane Digest call
// Todo add auth options to pull secrets and ACR MSI based - currently only supports docker config auth
// K8s chain pull secrets ref: https://github.com/google/go-containerregistry/blob/main/pkg/authn/k8schain/k8schain.go
// ACR ref: // https://github.com/Azure/acr-docker-credential-helper/blob/master/src/docker-credential-acr/acr_login.go
func (craneWrapper *CraneWrapper) Digest(ref string) (string, error) {
	//TODO implement this method using the libraries that were mentioned above. in the meantime, return static digest
	//(resolved digest of tomerwdevops.azurecr.io/imagescan:62 - https://ms.portal.azure.com/#@microsoft.onmicrosoft.com/resource/subscriptions/4009f3ee-43c4-4f19-97e4-32b6f2285a68/resourceGroups/tomerwdevops/providers/Microsoft.ContainerRegistry/registries/tomerwdevops/repository)
	digest := "sha256:f6a835256950f699175eecb9fd82e4a84684c9bab6ffb641b6fc23ff7b23e4b3"
	return digest, nil
	//return crane.Digest(ref)
}

// DigestWithRetry re-executing Digest in case of a failure according to retryPolicy
func (craneWrapper *CraneWrapper) DigestWithRetry(ref string) (res string, err error) {
	retryCount := 0
	for retryCount < craneWrapper.retryAttempts{
		// TODO change Digest call after Digest method has been implemented correctly
		// TODO deal with cases for which we do not want to retry after method as been implemented
		// Execute Digest and check if an error occurred. We want to retry if err is not nil
		if res, err = craneWrapper.Digest(ref); err == nil {
			return res, nil
		} else {
			retryCount += 1
			// wait (i * craneWrapper.retryDuration) milliseconds between retries
			time.Sleep(time.Duration(retryCount) * craneWrapper.retryDuration * time.Millisecond)
		}
	}
	return res, errors.Wrapf(err, "failed after %d retries due to error", retryCount)
}
