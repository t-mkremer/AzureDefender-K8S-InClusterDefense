package webhook

import "sync"

// HandlerSync is responsible for synchronizing the providers
type HandlerSync struct {
	// handlerMutex is the mutex of HandlerSync
	handlerMutex *sync.Mutex
	// vulnerabilityScanInfoErrorChannel is a channel for sending errors occur during image vulnerability scan
	vulnerabilityScanInfoErrorChannel chan error
	// credScanAnnotationErrorChannel is a channel for sending errors occur during credScan
	credScanAnnotationErrorChannel chan error
}

// newHandlerSync Constructor for HandlerSync
func newHandlerSync() *HandlerSync{
	handlerSync := &HandlerSync{
		handlerMutex: &sync.Mutex{},
		vulnerabilityScanInfoErrorChannel: make(chan error),
		credScanAnnotationErrorChannel: make(chan error),
	}
	return handlerSync
}
