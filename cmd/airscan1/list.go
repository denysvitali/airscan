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
	"strings"
	"time"

	"github.com/brutella/dnssd"
	"github.com/spf13/cobra"
	"github.com/stapelberg/airscan"
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "Discover AirScan scanners on the local network",
	RunE:  runList,
}

var listTimeout time.Duration

func init() {
	listCmd.Flags().DurationVar(&listTimeout, "timeout", 5*time.Second, "time to wait for device discovery")
}

func humanDeviceName(srv dnssd.BrowseEntry) string {
	if ty := srv.Text["ty"]; ty != "" {
		return ty
	}
	// miekg/dns escapes characters in DNS labels: as per RFC1034 and
	// RFC1035, labels do not actually permit whitespace. The purpose of
	// escaping originally appears to be to use these labels in a DNS
	// master file, but for our UI, backslashes look just wrong:
	return strings.ReplaceAll(srv.Name, "\\", "")
}

func runList(cmd *cobra.Command, args []string) error {
	printInfo("Discovering AirScan devices (timeout: %v)...", listTimeout)

	ctx, canc := context.WithCancel(context.Background())
	defer canc()
	if listTimeout > 0 {
		ctx, canc = context.WithTimeout(ctx, listTimeout)
		defer canc()
	}

	var rows [][]string

	addFn := func(srv dnssd.BrowseEntry) {
		printDebug("DNS-SD service discovered: %+v", srv)
		var ips []string
		for _, ip := range srv.IPs {
			ips = append(ips, ip.String())
		}
		rows = append(rows, []string{
			humanDeviceName(srv),
			srv.Host,
			strings.Join(ips, ", "),
		})
	}

	rmvFn := func(srv dnssd.BrowseEntry) {
		printDebug("DNS-SD service vanished: %s", srv.Host)
	}

	if err := dnssd.LookupType(ctx, airscan.ServiceName, addFn, rmvFn); err != nil &&
		err != context.Canceled &&
		err != context.DeadlineExceeded {
		return err
	}

	if len(rows) == 0 {
		printWarning("No AirScan devices found.")
		return nil
	}

	fmt.Println(newDeviceTable(rows).Render())
	fmt.Println()
	printInfo("Use --host=<HOST> with scan or conntest commands.")

	return nil
}
