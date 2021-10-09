package credscan

import (
	"bytes"
	"github.com/Azure/AzureDefender-K8S-InClusterDefense/pkg/infra/instrumentation"
	"github.com/Azure/AzureDefender-K8S-InClusterDefense/pkg/infra/instrumentation/trace"
	"github.com/pkg/errors"
	"io/ioutil"
	"net/http"
)

const(

	_requestMethod = "POST"

	_headerKey = "Content-Type"

	_headerValue = "application/json"
)


type CredScanClient struct {
	tracerProvider  trace.ITracerProvider
	credScanServerUrl string
}

func NewCredScanClient (instrumentationProvider instrumentation.IInstrumentationProvider, credScanServerUrl string) *CredScanClient{
	return &CredScanClient{
		tracerProvider: instrumentationProvider.GetTracerProvider("CredScanClient"),
		credScanServerUrl: credScanServerUrl,
	}
}

// initiateCredScanRequest http request to credscan server
// return json string represent cred scan results
func (client *CredScanClient) initiateCredScanRequest(jsonStr []byte) ([]byte, error) {
	tracer := client.tracerProvider.GetTracer("initiateCredScanRequest")

	req, err := http.NewRequest(_requestMethod, client.credScanServerUrl, bytes.NewBuffer(jsonStr))
	if err != nil {
		err = errors.Wrap(err, "CredScan.initiateCredScanRequest failed on http.NewRequest")
		tracer.Error(err, "")
		return nil, err
	}
	req.Header.Set(_headerKey, _headerValue)

	httpClient := &http.Client{}
	resp, err := httpClient.Do(req) //TODO add retry policy
	if err != nil {
		err = errors.Wrap(err, "CredScan.initiateCredScanRequest failed on posting http request")
		tracer.Error(err, "")
		return nil, err
	}
	tracer.Info("http response data", "status", resp.Status, "status code", resp.StatusCode)
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		err = errors.Wrap(err, "CredScan.initiateCredScanRequest failed on ReadAll")
		tracer.Error(err, "")
		return nil, err
	}
	return body, nil
}