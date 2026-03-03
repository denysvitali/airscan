package airscan_test

import (
	"net"
	"net/http"
	"testing"

	"github.com/brutella/dnssd"
	"github.com/stapelberg/airscan"
)

func TestDialer(t *testing.T) {
	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}

	srv := &http.Server{Handler: mockScanner(t)}
	go srv.Serve(ln)
	t.Cleanup(func() {
		srv.Shutdown(t.Context())
		ln.Close()
	})

	addr := ln.Addr().(*net.TCPAddr)

	// use a dnssd service struct
	svc := dnssd.BrowseEntry{
		// Likely unreachable:
		Host:   "unreachable.invalid",
		Domain: "localhost",
		Port:   addr.Port,
		IPs: []net.IP{
			// Likely unreachable:
			net.ParseIP("255.255.255.255"),
			// Actually reachable:
			addr.IP,
		},
	}
	cl := airscan.NewClientForService(&svc)
	cl.SetDebug(true)
	if _, err := cl.ScannerStatus(); err != nil {
		t.Fatal(err)
	}
}
