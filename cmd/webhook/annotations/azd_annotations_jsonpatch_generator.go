package annotations

import (
	"encoding/json"
	"github.com/Azure/AzureDefender-K8S-InClusterDefense/pkg/infra/utils"
	corev1 "k8s.io/api/core/v1"
	"sync"
	"time"

	"github.com/Azure/AzureDefender-K8S-InClusterDefense/pkg/azdsecinfo/contracts"
	"github.com/pkg/errors"
	"gomodules.xyz/jsonpatch/v2"
)

const (
	// _addPatchOperation operation type in json patch to add annotations
	_addPatchOperation = "add"
	// _annotationPatchPath operation path in json patch to add object annotations
	_annotationPatchPath = "/metadata/annotations"
)

// CreateContainersVulnerabilityScanAnnotationPatchAdd returns an add type json patch in order to add to annotations map a new key value of ContainersVulnerabilityScanInfoAnnotationName.
// It does so by adding to the exiting map the new key value and setting the updated map as the json patch value.
// The function creates a scanInfoList from the provided containers scan info  slice of type contracts.ContainerVulnerabilityScanInfoList serialize/marshal it and set it as a value string to the new key annotation
// Contracts.ContainersVulnerabilityScanInfoAnnotationName (azuredefender.io/containers.vulnerability.scan.info)
// If the annotations map doesn't exist, it creates a new map and add the key value before setting it as the json patch value.
// As a result, the annotations are updated with no override of the existing values.
func CreateContainersVulnerabilityScanAnnotationPatchAdd(containersScanInfoList []*contracts.ContainerVulnerabilityScanInfo, pod *corev1.Pod, mutex *sync.Mutex) error {
	scanInfoList := &contracts.ContainerVulnerabilityScanInfoList{
		GeneratedTimestamp: time.Now().UTC(),
		Containers:         containersScanInfoList,
	}

	// Marshal the scan info list (annotations can only be strings)
	serVulnerabilitySecInfo, err := marshalAnnotationInnerObject(scanInfoList)
	if err != nil {
		return errors.Wrap(err, "AzdAnnotationsPatchGenerator failed marshaling scanInfoList during CreateContainersVulnerabilityScanAnnotationPatchAdd")
	}

	// Create annotations map and add to the map serVulnerabilitySecInfo. If the pod's annotations is nil create a new map
	err = updateAnnotations(pod, contracts.ContainersVulnerabilityScanInfoAnnotationName, serVulnerabilitySecInfo, mutex)
	if err != nil {
		return errors.Wrap(err, "AzdAnnotationsPatchGenerator failed updating annotations because pod is nil during CreateContainersVulnerabilityScanAnnotationPatchAdd")
	}

	return nil
}

// CreateK8SResourceCredScanAnnotationPatchAdd returns an add type json patch in order to add to annotations map a new key value of CredScanInfoAnnotationName.
// It does so by adding to the exiting map the new key value and setting the updated map as the json patch value.
// The function creates a scanInfoList from the provided scan info  slice of type contracts.CredScanInfoList serialize/marshal it and set it as a value string to the new key annotation
// contracts.CredScanInfoAnnotationName (resource.credential.scan.info)
// If the annotations map doesn't exist, it creates a new map and add the key value before setting it as the json patch value.
// As a result, the annotations are updated with no override of the existing values.
// TODO - create common function for main functionality for CreateContainersVulnerabilityScanAnnotationPatchAdd and CreateK8SResourceCredScanAnnotationPatchAdd
func CreateK8SResourceCredScanAnnotationPatchAdd(scanInfoList *contracts.CredScanInfoList, pod *corev1.Pod, mutex *sync.Mutex) error {
	scanInfoList.GeneratedTimestamp = time.Now().UTC()

	// Marshal the scan info list (annotations can only be strings)
	serCredSecInfo, err := marshalAnnotationInnerObject(scanInfoList)
	if err != nil {
		return errors.Wrap(err, "AzdAnnotationsPatchGenerator failed marshaling scanInfoList during CreateServiceCredScanAnnotationPatchAdd")
	}

	// Create annotations map and add to the map serVulnerabilitySecInfo. If the pod's annotations is nil create a new map
	err = updateAnnotations(pod, contracts.CredScanInfoAnnotationName, serCredSecInfo, mutex)
	if err != nil {
		return errors.Wrap(err, "AzdAnnotationsPatchGenerator failed updating annotations because pod is nil during CreateK8SResourceCredScanAnnotationPatchAdd")
	}

	return nil
}

// marshalAnnotationInnerObject marshaling provided object needed to be set as string in annotations to json represented string
func marshalAnnotationInnerObject(object interface{}) (string, error) {
	// Marshal object
	marshaledVulnerabilitySecInfo, err := json.Marshal(object)
	if err != nil {
		return "", err
	}

	// Cast to string
	ser := string(marshaledVulnerabilitySecInfo)
	return ser, nil
}

func CreatePatch(pod *corev1.Pod) (*jsonpatch.JsonPatchOperation, error){
	if pod == nil {
		return nil, utils.NilArgumentError
	}
	// Create an add operation to annotations to add or create if annotations are empty
	// **important note** any future changes to the pod's annotation map will result in changing the json patch because annotations is a map reference.
	patch := jsonpatch.NewOperation(_addPatchOperation, _annotationPatchPath, pod.GetAnnotations())
	return &patch, nil
}

// updateAnnotations update the annotations of a given pod with the given key and value.
// If annotations map not exist - create a new map and add the key.
// Return the annotations map
// only on routine can read/write to the pod's annotations map
func updateAnnotations(pod *corev1.Pod, key string, value string, mutex *sync.Mutex) error{
	if pod == nil {
		return utils.NilArgumentError
	}
	mutex.Lock()
	annotations := pod.GetAnnotations()
	if annotations == nil {
		annotations = make(map[string]string)
		pod.SetAnnotations(annotations)
	}
	annotations[key]=value
	mutex.Unlock()
	return nil
}
