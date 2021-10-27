package contracts

import "time"

const (
	// CredScanInfoAnnotationName - key under annotations
	CredScanInfoAnnotationName = "resource.credential.scan.info"
)
// CredScanInfoList a list of cred scan information
type CredScanInfoList struct {

	//GeneratedTimestamp represents the time the scan info list (this) was generated
	GeneratedTimestamp time.Time `json:"generatedTimestamp"`

	// CredScanResults is a list of CredScanInfo
	CredScanResults []*CredScanInfo `json:"credScanInfo"`

	// ScanStatus is the credential status - healthy or unhealthy
	ScanStatus ScanStatus

}

// CredScanInfo represents cred scan information about a possible unhealthy property
type CredScanInfo struct {

	// a struct contain the weakness description
	CredentialInfo CredentialInfo `json:"credentialInfo"`

	// a number represent the MatchingConfidence of the weakness (from 1 to 100)
	MatchingConfidence float64 `json:"matchingConfidence"`

	Match MatchInfo `json:"match"`
}

// CredentialInfo - a struct contain the weakness description
type CredentialInfo struct {
	//the weakness description
	Name string `json:"name"`
}


type MatchInfo struct{
	MatchPrefix string `json:"matchPrefix"`
}
