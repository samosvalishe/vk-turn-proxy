package main

import "sync"

type UDPPacket struct {
	Data []byte
	N    int
}

var packetPool = sync.Pool{
	New: func() any { return &UDPPacket{Data: make([]byte, 2048)} },
}
