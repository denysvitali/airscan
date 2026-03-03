package airscan

import (
	"context"
	"log"
	"net"
	"slices"
	"sync"
)

type fallbackDialer struct {
	underlying *net.Dialer
	mu         sync.Mutex
	hostports  []string
	debug      *bool
}

func (d *fallbackDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if d.debug != nil && *d.debug {
		log.Printf("DialContext(%s, %s)", network, addr)
	}
	var lastErr error
	d.mu.Lock()
	defer d.mu.Unlock()
	for idx, hostport := range d.hostports {
		if d.debug != nil && *d.debug {
			log.Printf("-> trying %s", hostport)
		}
		conn, err := d.underlying.DialContext(ctx, network, hostport)
		if err != nil {
			lastErr = err
			continue
		}
		d.hostports = slices.Insert(slices.Delete(d.hostports, idx, idx+1), 0, hostport)
		return conn, nil
	}
	return nil, lastErr
}
