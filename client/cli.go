package main

import (
	"net"
	"sync"
)

// dnsMode is set in main() from the -dns flag and consumed by appDialer().
var dnsMode = DNSModeAuto

// dohResolverSingleton is shared across all callers of appDialer().
var (
	dohResolverOnce     sync.Once
	dohResolverInstance *DohResolver
)

func sharedDohResolver() *DohResolver {
	dohResolverOnce.Do(func() {
		dohResolverInstance = NewDohResolver(nil)
	})
	return dohResolverInstance
}

// appDialer returns the net.Dialer used by tls-client and other HTTP callers.
// DNS transport is selected by the -dns flag (udp | doh | auto).
func appDialer() net.Dialer {
	return buildDialer(dnsMode, sharedDohResolver())
}

// installGlobalResolver wires net.DefaultResolver to the same DNS transport
// chosen by the -dns flag, so that any caller bypassing appDialer (third-party
// libs that build their own http.Client without our Dialer) still uses DoH /
// auto-fallback rather than the OS resolver.
func installGlobalResolver() {
	d := appDialer()
	if d.Resolver != nil {
		net.DefaultResolver = d.Resolver
	}
}
