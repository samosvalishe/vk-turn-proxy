// Package dispatcher holds the inbound-UDP packet pool shared between
// main()'s read goroutine and turnconn's per-stream DTLS readers.
package dispatcher

import "sync"

type UDPPacket struct {
	Data []byte
	N    int
}

var PacketPool = sync.Pool{
	New: func() any { return &UDPPacket{Data: make([]byte, 2048)} },
}
