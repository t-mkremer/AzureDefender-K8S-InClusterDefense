package webhook

import "sync"

const (
	// number of providers - currently arg and credScan
	_numberOfProviders int = 2
)

// HandlerSync is responsible for synchronizing the providers
type HandlerSync struct {
	// handlerMutex is the mutex of HandlerSync
	handlerMutex *sync.Mutex
	// handlerMutex is the WaitGroup of HandlerSync
	scansWaitGroup *sync.WaitGroup
	// vulnerabilityScanInfoErrorChannel is a channel for sending errors occur during image vulnerability scan
	vulnerabilityScanInfoErrorChannel chan error
	// credScanAnnotationErrorChannel is a channel for sending errors occur during credScan
	credScanAnnotationErrorChannel chan error
}

// newHandlerSync Constructor for HandlerSync
func newHandlerSync() *HandlerSync{
	handlerSync := &HandlerSync{
		handlerMutex: &sync.Mutex{},
		scansWaitGroup: &sync.WaitGroup{},
		vulnerabilityScanInfoErrorChannel: make(chan error),
		credScanAnnotationErrorChannel: make(chan error),
	}
	// Define how many providers will run in parallel
	handlerSync.scansWaitGroup.Add(_numberOfProviders)
	return handlerSync
}
