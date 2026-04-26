// Package appstate holds process-global state shared between client subpackages.
//
// Exists to break import cycles between vkauth/turnconn/captcha after the
// refactor of client/main.go. All values are mutated only from main() at
// startup or via atomic ops thereafter.
package appstate

import (
	"context"
	"sync/atomic"
)

var (
	ActiveLocalPeer      atomic.Value
	GlobalCaptchaLockout atomic.Int64
	ConnectedStreams     atomic.Int32
	GlobalAppCancel      context.CancelFunc
	HandshakeSem         = make(chan struct{}, 3)
	Debug                bool
	ManualCaptcha        bool
	AutoCaptchaSliderPOC bool
)
