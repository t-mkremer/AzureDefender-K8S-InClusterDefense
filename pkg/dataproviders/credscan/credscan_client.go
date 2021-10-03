package credscan

import (
	"github.com/Azure/AzureDefender-K8S-InClusterDefense/pkg/azdsecinfo/contracts"
	"github.com/Azure/AzureDefender-K8S-InClusterDefense/pkg/infra/instrumentation/trace"
	corev1 "k8s.io/api/core/v1"
	"time"
)

const (
	// cred scan server url - the sidecar
	_credScanServerUrl = "http://localhost:80/scanString"

	// CredScanInfoAnnotationName - key under annotations
	CredScanInfoAnnotationName = "/resource.credential.scan.info"

	// regex to extract the key before the secret from MatchPrefix
	matchPrefixRegex = "(\")([^:,{}[]*?)(\")" // match all substrings between "" such that ,{}[ don't appear in them

	// the default annotation that admissionWebhook add to resource annotations
	admissionWebhookDefaultAnnotation = "kubectl.kubernetes.io/last-applied-configuration"
)

//interface_____________________________________________________________________________________________________________

type ICredScanDataProvider interface {
	GetCredScanResults(pod *corev1.Pod) ([]*CredScanInfo, error)
}

//structs_______________________________________________________________________________________________________________

// CredScanDataProvider for ICredScanDataProvider implementation
type CredScanDataProvider struct {
	tracerProvider trace.ITracerProvider
}

// structs hierarchy for credScan results_______________________________________________________________________________
// The hierarchy is bottom up

// CredentialInfoStruct - a struct contain the weakness description
type CredentialInfo struct {
	//the weakness description
	Name string `json:"name"`
}

type MatchInfo struct{
	MatchPrefix string `json:"matchPrefix"`
}

// CredScanInfo represents cred scan information about a possible unhealthy property
type CredScanInfo struct {

	// a struct contain the weakness description
	CredentialInfo CredentialInfo `json:"credentialInfo"`

	// a number represent the MatchingConfidence of the weakness (from 1 to 100)
	MatchingConfidence float64 `json:"matchingConfidence"`

	Match MatchInfo `json:"match"`
}


// CredScanInfoList a list of cred scan information
type CredScanInfoList struct {

	//GeneratedTimestamp represents the time the scan info list (this) was generated
	GeneratedTimestamp time.Time `json:"generatedTimestamp"`

	//List of CredScanInfo
	CredScanResults []*CredScanInfo `json:"CredScanInfo"`

	ScanStatus contracts.ScanStatus

}