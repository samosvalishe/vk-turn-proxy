package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
)

func main() {
	listen := flag.String("listen", "0.0.0.0:56000", "listen on ip:port")
	connect := flag.String("connect", "", "connect to ip:port")
	vlessMode := flag.Bool("vless", false, "VLESS mode: forward TCP connections (for VLESS) instead of UDP packets")
	flag.Parse()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-signalChan
		log.Printf("Terminating...\n")
		cancel()
		<-signalChan
		log.Fatalf("Exit...\n")
	}()

	addr, err := net.ResolveUDPAddr("udp", *listen)
	if err != nil {
		panic(err)
	}
	if len(*connect) == 0 {
		log.Panicf("server address is required")
	}
	// Generate a certificate and private key to secure the connection
	certificate, genErr := selfsign.GenerateSelfSigned()
	if genErr != nil {
		panic(genErr)
	}

	//
	// Everything below is the pion-DTLS API! Thanks for using it ❤️.
	//

	var pool *dtlsPool
	if !*vlessMode {
		pool = newDtlsPool(ctx, *connect)
	}

	// Connect to a DTLS server
	listener, err := dtls.ListenWithOptions(
		"udp",
		addr,
		dtls.WithCertificates(certificate),
		dtls.WithExtendedMasterSecret(dtls.RequireExtendedMasterSecret),
		dtls.WithCipherSuites(dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
		dtls.WithConnectionIDGenerator(dtls.RandomCIDGenerator(8)),
	)
	if err != nil {
		panic(err)
	}
	context.AfterFunc(ctx, func() {
		if err = listener.Close(); err != nil {
			panic(err)
		}
	})

	fmt.Println("Listening")

	wg1 := sync.WaitGroup{}
	for {
		select {
		case <-ctx.Done():
			wg1.Wait()
			return
		default:
		}
		// Wait for a connection.
		conn, err := listener.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		wg1.Add(1)
		go func(conn net.Conn) {
			defer wg1.Done()
			defer func() {
				if closeErr := conn.Close(); closeErr != nil {
					log.Printf("failed to close incoming connection: %s", closeErr)
				}
			}()
			log.Printf("Connection from %s\n", conn.RemoteAddr())

			// Perform the handshake with a 30-second timeout
			ctx1, cancel1 := context.WithTimeout(ctx, 30*time.Second)
			defer cancel1()

			dtlsConn, ok := conn.(*dtls.Conn)
			if !ok {
				log.Println("Type error: expected *dtls.Conn")
				return
			}
			log.Println("Start handshake")
			if err := dtlsConn.HandshakeContext(ctx1); err != nil {
				log.Printf("Handshake failed: %v", err)
				return
			}
			log.Println("Handshake done")

			if *vlessMode {
				handleVLESSConnection(ctx, dtlsConn, *connect)
			} else {
				pool.handleConn(ctx, dtlsConn)
			}

			log.Printf("Connection closed: %s\n", conn.RemoteAddr())
		}(conn)
	}
}

type dtlsPool struct {
	mu     sync.RWMutex
	conns  []net.Conn
	idx    uint64
	server *net.UDPConn
}

func newDtlsPool(ctx context.Context, connectAddr string) *dtlsPool {
	serverAddr, err := net.ResolveUDPAddr("udp", connectAddr)
	if err != nil {
		log.Panicf("Failed to resolve backend address: %v", err)
	}
	serverConn, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		log.Panicf("Failed to connect to backend: %v", err)
	}

	p := &dtlsPool{
		server: serverConn,
	}

	go func() {
		buf := make([]byte, 1600)
		for {
			select {
			case <-ctx.Done():
				_ = serverConn.Close()
				return
			default:
			}

			if err := serverConn.SetReadDeadline(time.Now().Add(time.Second * 5)); err != nil {
				continue
			}

			n, err := serverConn.Read(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				log.Printf("dtlsPool backend read err: %v", err)
				time.Sleep(1 * time.Second)
				continue
			}

			c := p.pick()
			if c != nil {
				if err := c.SetWriteDeadline(time.Now().Add(time.Second * 5)); err == nil {
					_, _ = c.Write(buf[:n])
				}
			}
		}
	}()

	return p
}

func (p *dtlsPool) pick() net.Conn {
	p.mu.RLock()
	defer p.mu.RUnlock()
	n := uint64(len(p.conns))
	if n == 0 {
		return nil
	}
	i := atomic.AddUint64(&p.idx, 1) - 1
	return p.conns[i%n]
}

func (p *dtlsPool) handleConn(ctx context.Context, conn net.Conn) {
	p.mu.Lock()
	p.conns = append(p.conns, conn)
	p.mu.Unlock()

	defer func() {
		p.mu.Lock()
		for i, c := range p.conns {
			if c == conn {
				p.conns = append(p.conns[:i], p.conns[i+1:]...)
				break
			}
		}
		p.mu.Unlock()
	}()

	ctx2, cancel2 := context.WithCancel(ctx)
	defer cancel2()
	context.AfterFunc(ctx2, func() {
		_ = conn.SetDeadline(time.Now()) //nolint:errcheck
	})

	buf := make([]byte, 1600)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if err := conn.SetReadDeadline(time.Now().Add(time.Minute * 30)); err != nil {
			log.Printf("conn SetReadDeadline err: %v", err)
			return
		}

		n, err := conn.Read(buf)
		if err != nil {
			log.Printf("conn Read err: %v", err)
			return
		}

		if err := p.server.SetWriteDeadline(time.Now().Add(time.Second * 5)); err == nil {
			if _, err = p.server.Write(buf[:n]); err != nil {
				log.Printf("server Write err: %v", err)
			}
		}
	}
}
