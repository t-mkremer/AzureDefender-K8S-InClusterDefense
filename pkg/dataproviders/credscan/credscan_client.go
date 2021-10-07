package credscan

import (
	"bytes"
	"github.com/pkg/errors"
	"io/ioutil"
	"net/http"
)

const(
	// cred scan server url - the sidecar
	_credScanServerUrl = "http://localhost:80/scanString"

	_requestMethod = "POST"

	_headerKey = "Content-Type"

	_headerValue = "application/json"
)

// initiateCredScanRequest http request to credscan server
// return json string represent cred scan results
func (provider *CredScanDataProvider) initiateCredScanRequest(jsonStr []byte) ([]byte, error) {
	tracer := provider.tracerProvider.GetTracer("initiateCredScanRequest")

	req, err := http.NewRequest(_requestMethod, _credScanServerUrl, bytes.NewBuffer(jsonStr))
	if err != nil {
		err = errors.Wrap(err, "CredScan.initiateCredScanRequest failed on http.NewRequest")
		tracer.Error(err, "")
		return nil, err
	}
	req.Header.Set(_headerKey, _headerValue)

	client := &http.Client{}
	resp, err := client.Do(req) //TODO add retry policy
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