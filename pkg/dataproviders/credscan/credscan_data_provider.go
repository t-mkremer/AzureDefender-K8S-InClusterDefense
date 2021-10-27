package credscan

import (
	"encoding/json"
	"github.com/Azure/AzureDefender-K8S-InClusterDefense/pkg/azdsecinfo/contracts"
	"github.com/Azure/AzureDefender-K8S-InClusterDefense/pkg/infra/instrumentation"
	"github.com/Azure/AzureDefender-K8S-InClusterDefense/pkg/infra/instrumentation/trace"
	"github.com/Azure/AzureDefender-K8S-InClusterDefense/pkg/infra/utils"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	"regexp"
)

const (
	// The default annotation that admissionWebhook add to resource annotations
	_admissionWebhookDefaultAnnotation = "kubectl.kubernetes.io/last-applied-configuration"

	// regex to extract the key before the secret from MatchPrefix
	// Match all substrings between "" such that ,{}[ don't appear in them
	// i.e: \"namespace\":\"default\",\"annotations\":{\"password\":\" will find namespace, default, annotations, password
	_matchPrefixRegex = "(\")([^:,{}[]*?)(\")"
)

// ICredScanDataProvider is a provider for credScan data
type ICredScanDataProvider interface {
	//GetCredScanResults get credential scan results of the resourceMetadata
	GetCredScanResults(pod *corev1.Pod) (*contracts.CredScanInfoList, error)
}

// CredScanDataProvider implements ICredScanDataProvider interface
var _ ICredScanDataProvider = (*CredScanDataProvider)(nil)

// CredScanDataProvider for ICredScanDataProvider implementation
type CredScanDataProvider struct {
	tracerProvider trace.ITracerProvider
	credScanClient *CredScanClient
}

// NewCredScanDataProvider Constructor
func NewCredScanDataProvider(instrumentationProvider instrumentation.IInstrumentationProvider, credScanClient *CredScanClient) *CredScanDataProvider {
	return &CredScanDataProvider{
		tracerProvider:    instrumentationProvider.GetTracerProvider("CredScanDataProvider"),
		credScanClient: credScanClient,
	}
}

// GetCredScanResults - get credential scan results of the resourceMetadata.
func (provider *CredScanDataProvider) GetCredScanResults(pod *corev1.Pod) (*contracts.CredScanInfoList, error){
	tracer := provider.tracerProvider.GetTracer("GetCredScanResults")
	tracer.Info("Received", "pod name", pod.Name, "namespace", pod.Namespace)
	body, err:= provider.encodeResourceForCredScan(pod)
	if err != nil {
		err = errors.Wrap(err, "CredScan.GetCredScanResults failed on encodeResourceForCredScan")
		tracer.Error(err, "")
		return nil, err
	}

	unparsedScanResults, err := provider.credScanClient.initiateCredScanRequest(body)
	if err != nil {
		err = errors.Wrap(err, "CredScan.GetCredScanResults failed on initiateCredScanRequest")
		tracer.Error(err, "")
		return nil, err
	}

	scanResults, err := provider.parseCredScanResults(unparsedScanResults)
	if err != nil {
		err = errors.Wrap(err, "CredScan.GetCredScanResults failed on parseCredScanResults")
		tracer.Error(err, "")
		return nil, err
	}

	scanInfoList := &contracts.CredScanInfoList{
		CredScanResults:         scanResults,
	}
	if len(scanInfoList.CredScanResults) > 0 {
		scanInfoList.ScanStatus = contracts.UnhealthyScan
	}else {
		scanInfoList.ScanStatus = contracts.HealthyScan
	}

	return scanInfoList, nil
}

// encodeResourceForCredScan convert request into json buffer.
// In order to match the credScan server API the request must be converted to escaped json string and only then to buffer
func (provider *CredScanDataProvider) encodeResourceForCredScan(pod *corev1.Pod) ([]byte, error){

	tracer := provider.tracerProvider.GetTracer("encodeResourceForCredScan")

	// Remove default annotation that kubectl admissionWebhook add to resource (if the resource is created by apply -f kubectl admissionWebhook saves the yaml file as annotations ).
	// The removal reason is to avoid duplication of scan results
	defaultAnnotations, admissionWebhookDefaultAnnotationExist := pod.Annotations[_admissionWebhookDefaultAnnotation]
	if admissionWebhookDefaultAnnotationExist {
		pod.Annotations[_admissionWebhookDefaultAnnotation] = ""
	}

	// marshal pod.
	body, err := json.Marshal(pod)
	if err != nil {
		err = errors.Wrap(err, "CredScan.encodeResourceForCredScan failed on json.Marshal results")
		tracer.Error(err, "")
		return nil, err
	}

	// revert the change done to pod annotations - (the change was deleting admissionWebhookDefaultAnnotation from annotations)
	if admissionWebhookDefaultAnnotationExist {
		pod.Annotations[_admissionWebhookDefaultAnnotation] = defaultAnnotations
	}

	// string(body) is *unescaped* json string. CredScan server receive escaped json string.
	// Marshal string(body) returns the escaped string
	body , err= json.Marshal(string(body))
	if err != nil {
		err = errors.Wrap(err, "CredScan.encodeResourceForCredScan failed on json.Marshal results")
		tracer.Error(err, "")
		return nil, err
	}
	return body, nil
}

// parseCredScanResults convert the string response into array of scan results
func (provider *CredScanDataProvider) parseCredScanResults(postRes []byte) ([]*contracts.CredScanInfo, error){
	tracer := provider.tracerProvider.GetTracer("parseCredScanResults")
	if postRes == nil {
		return nil, errors.Wrap(utils.NilArgumentError, "parseCredScanResults got nil postRes")
	}

	var scanResults []*contracts.CredScanInfo
	err := json.Unmarshal(postRes, &scanResults)
	if err != nil{
		err = errors.Wrap(err, "CredScan.parseCredScanResults failed on Unmarshal CredScanResults")
		tracer.Error(err, "")
		return nil, err
	}
	for _,scanResult := range scanResults{
		scanResult.Match.MatchPrefix = provider.parseMatchPrefix(scanResult.Match.MatchPrefix)
	}
	return scanResults, nil
}

// parseMatchPrefix extract the key before the secret from MatchPrefix.
// MatchPrefix don't include the current secret itself but may include previous secrets.
// If There is no key before the secret, keep the entire MatchPrefix (because there is no risk in exposing other secrets).
// For example:
//		matchPrefix = "1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"unhealthy-pod-unscanned\",\"namespace\":\"default\",\"annotations\":{\"password\":\"
// 		parseMatchPrefix will return  "password"
func (provider *CredScanDataProvider) parseMatchPrefix(matchPrefix string) string{
	reg := regexp.MustCompile(_matchPrefixRegex)
	regexMatches := reg.FindAllString(matchPrefix, -1) // -1 means return all matches.
	matchesLen := len(regexMatches)
	if matchesLen > 0 {
		lastIndex := len(regexMatches[matchesLen - 1]) - 1      // take only last match
		matchPrefix = regexMatches[matchesLen - 1][1:lastIndex] // trim the string from "
	}
	return matchPrefix
}

