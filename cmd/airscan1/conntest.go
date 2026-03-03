// Copyright 2020 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/brutella/dnssd"
	"github.com/spf13/cobra"
	"github.com/stapelberg/airscan"
)

var conntestCmd = &cobra.Command{
	Use:   "conntest",
	Short: "Test reachability of an AirScan scanner",
	RunE:  runConntest,
}

type conntestFlags struct {
	host    string
	ip      string
	timeout time.Duration
}

var cf conntestFlags

func init() {
	conntestCmd.Flags().StringVar(&cf.host, "host", "", "DNS-SD hostname of the scanner")
	conntestCmd.Flags().StringVar(&cf.ip, "ip", "", "direct IP or IP:port of the scanner")
	conntestCmd.Flags().DurationVar(&cf.timeout, "timeout", 5*time.Second, "connection timeout")

	conntestCmd.MarkFlagsMutuallyExclusive("host", "ip")
	conntestCmd.MarkFlagsOneRequired("host", "ip")
}

func runConntest(cmd *cobra.Command, args []string) error {
	ctx, canc := context.WithCancel(context.Background())
	defer canc()
	if cf.timeout > 0 {
		ctx, canc = context.WithTimeout(ctx, cf.timeout)
		defer canc()
	}

	if cf.ip != "" {
		return testConnsIP(ctx, cf.ip)
	}

	// DNS-SD path
	printInfo("Finding scanner %q (timeout: %v)...", cf.host, cf.timeout)
	svc, err := resolveViaDNSSDEntry(cf.host, cf.timeout)
	if err != nil {
		return err
	}
	hostports := buildHostports(svc)
	testHostports(ctx, hostports)
	return nil
}

func testConnsIP(ctx context.Context, addr string) error {
	_, _, err := net.SplitHostPort(addr)
	if err != nil {
		// No port provided — probe common scanner ports concurrently
		testHostports(ctx, []string{
			net.JoinHostPort(addr, "80"),
			net.JoinHostPort(addr, "9095"),
			net.JoinHostPort(addr, "443"),
		})
		return nil
	}
	testHostports(ctx, []string{addr})
	return nil
}

func buildHostports(svc *dnssd.BrowseEntry) []string {
	port := strconv.Itoa(svc.Port)
	hostports := []string{
		net.JoinHostPort(svc.Host, port),
		net.JoinHostPort(svc.Host+"."+svc.Domain, port),
	}
	for _, ip := range svc.IPs {
		hostports = append(hostports, net.JoinHostPort(ip.String(), port))
	}
	return hostports
}

func testHostports(ctx context.Context, hostports []string) {
	var wg sync.WaitGroup
	for _, hostport := range hostports {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", hostport)
			if err != nil {
				printWarning("%s: %v", hostport, err)
				return
			}
			defer conn.Close()
			printSuccess("%s: reachable!", hostport)
		}()
	}
	wg.Wait()
}

func resolveViaDNSSDEntry(host string, timeout time.Duration) (*dnssd.BrowseEntry, error) {
	ctx, canc := context.WithCancel(context.Background())
	defer canc()
	if timeout > 0 {
		ctx, canc = context.WithTimeout(ctx, timeout)
		defer canc()
	}

	var found *dnssd.BrowseEntry

	addFn := func(srv dnssd.BrowseEntry) {
		if srv.Host == host {
			canc()
			found = &srv
		}
	}

	rmvFn := func(srv dnssd.BrowseEntry) {}

	if err := dnssd.LookupType(ctx, airscan.ServiceName, addFn, rmvFn); err != nil &&
		err != context.Canceled &&
		err != context.DeadlineExceeded {
		return nil, err
	}

	if found == nil {
		return nil, fmt.Errorf("scanner %q not found", host)
	}
	return found, nil
}
