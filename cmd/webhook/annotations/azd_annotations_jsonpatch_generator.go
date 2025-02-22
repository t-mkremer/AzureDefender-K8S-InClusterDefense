package annotations

import (
	"encoding/json"
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

// CreateContainersVulnerabilityScanAnnotationPatchAdd creates and return an add type json patch to add to annotations map a new key value of ContainersVulnerabilityScanInfoAnnotationName.
// The function creates a scanInfoList from the provided containers scan info  slice of type contracts.ContainerVulnerabilityScanInfoList serialize/marshal it and set it as a value string to key annotation
// Contracts.ContainersVulnerabilityScanInfoAnnotationName (azuredefender.io/containers.vulnerability.scan.info)
func CreateContainersVulnerabilityScanAnnotationPatchAdd(containersScanInfoList []*contracts.ContainerVulnerabilityScanInfo) (*jsonpatch.JsonPatchOperation, error) {
	scanInfoList := &contracts.ContainerVulnerabilityScanInfoList{
		GeneratedTimestamp: time.Now().UTC(),
		Containers:         containersScanInfoList,
	}

	// Marshal the scan info list (annotations can only be strings)
	serVulnerabilitySecInfo, err := marshalAnnotationInnerObject(scanInfoList)
	if err != nil {
		return nil, errors.Wrap(err, "AzdAnnotationsPatchGenerator failed marshaling scanInfoList during CreateContainersVulnerabilityScanAnnotationPatchAdd")
	}

	// Create an add operation to annotations to add or create if annotations are empty
	patch := jsonpatch.NewOperation(_addPatchOperation, _annotationPatchPath, map[string]string{contracts.ContainersVulnerabilityScanInfoAnnotationName: serVulnerabilitySecInfo})
	return &patch, nil
}

// marshalAnnotationInnerObject marshaling provided object needed to be set as string in annotations to json represetned string
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

///
