package main

import (
	"context"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/cacggghp/vk-turn-proxy/tcputil"
	"github.com/xtaci/smux"
)

// handleVLESSConnection creates a KCP+smux session over DTLS and forwards
// each smux stream as a TCP connection to the backend (Xray/VLESS).
func handleVLESSConnection(ctx context.Context, dtlsConn net.Conn, connectAddr string) {
	// 1. Create KCP session over DTLS
	kcpSess, err := tcputil.NewKCPOverDTLS(dtlsConn, true)
	if err != nil {
		log.Printf("KCP session error: %s", err)
		return
	}
	defer func() {
		if closeErr := kcpSess.Close(); closeErr != nil {
			log.Printf("failed to close KCP session: %v", closeErr)
		}
	}()
	log.Printf("KCP session established (server)")

	// 2. Create smux server session over KCP
	smuxSess, err := smux.Server(kcpSess, tcputil.DefaultSmuxConfig())
	if err != nil {
		log.Printf("smux server error: %s", err)
		return
	}
	defer func() {
		if err := smuxSess.Close(); err != nil {
			log.Printf("failed to close smux session: %v", err)
		}
	}()
	log.Printf("smux session established (server)")

	// 3. Accept smux streams and forward to backend via TCP
	var wg sync.WaitGroup
	for {
		stream, err := smuxSess.AcceptStream()
		if err != nil {
			select {
			case <-ctx.Done():
			default:
				log.Printf("smux accept error: %s", err)
			}
			break
		}

		wg.Add(1)
		go func(s *smux.Stream) {
			defer wg.Done()

			defer func() {
				if err := s.Close(); err != nil && err != smux.ErrGoAway {
					log.Printf("failed to close smux stream: %v", err)
				}
			}()

			// Connect to backend (Xray/VLESS)
			backendConn, err := net.DialTimeout("tcp", connectAddr, 10*time.Second)
			if err != nil {
				log.Printf("backend dial error: %s", err)
				return
			}
			defer func() {
				if err := backendConn.Close(); err != nil {
					log.Printf("failed to close backend connection: %v", err)
				}
			}()

			// Bidirectional copy
			pipeConn(ctx, s, backendConn)
		}(stream)
	}
	wg.Wait()
}

// pipeConn copies data bidirectionally between two connections.
func pipeConn(ctx context.Context, c1, c2 net.Conn) {
	ctx2, cancel := context.WithCancel(ctx)
	defer cancel()

	context.AfterFunc(ctx2, func() {
		if err := c1.SetDeadline(time.Now()); err != nil {
			log.Printf("pipeConn: failed to set deadline c1: %v", err)
		}
		if err := c2.SetDeadline(time.Now()); err != nil {
			log.Printf("pipeConn: failed to set deadline c2: %v", err)
		}
	})

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		if _, err := io.Copy(c1, c2); err != nil {
			log.Printf("pipeConn: c1<-c2 copy error: %v", err)
		}
	}()

	go func() {
		defer wg.Done()
		if _, err := io.Copy(c2, c1); err != nil {
			log.Printf("pipeConn: c2<-c1 copy error: %v", err)
		}
	}()

	wg.Wait()

	// Reset deadlines (best-effort; connection may already be closed)
	if err := c1.SetDeadline(time.Time{}); err != nil {
		log.Printf("pipeConn: failed to reset deadline c1: %v", err)
	}
	if err := c2.SetDeadline(time.Time{}); err != nil {
		log.Printf("pipeConn: failed to reset deadline c2: %v", err)
	}
}
