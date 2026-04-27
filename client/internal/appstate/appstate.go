// Package appstate holds process-global runtime state (atomics + the DTLS
// handshake semaphore) shared between client subpackages.
//
// Startup configuration (Debug, ManualCaptcha, AutoCaptchaSliderPOC, DNSMode,
// AppCancel) lives in internal/appcfg and is threaded explicitly.
package appstate

import (
	"sync/atomic"
)

var (
	ActiveLocalPeer      atomic.Value
	GlobalCaptchaLockout atomic.Int64
	ConnectedStreams     atomic.Int32
	HandshakeSem         = make(chan struct{}, 3)
)
