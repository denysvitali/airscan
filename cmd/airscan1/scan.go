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
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/brutella/dnssd"
	"github.com/google/renameio/v2"
	"github.com/spf13/cobra"
	"github.com/stapelberg/airscan"
	"github.com/stapelberg/airscan/preset"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan a document from an AirScan scanner",
	RunE:  runScan,
}

type scanFlags struct {
	host    string
	ip      string
	scanDir string
	source  string
	size    string
	format  string
	color   string
	duplex  bool
	timeout time.Duration
}

var sf scanFlags

func init() {
	scanCmd.Flags().StringVar(&sf.host, "host", "", "DNS-SD hostname of the scanner")
	scanCmd.Flags().StringVar(&sf.ip, "ip", "", "direct IP or IP:port of the scanner (skips DNS-SD)")
	scanCmd.Flags().StringVar(&sf.scanDir, "scan-dir", ".", "directory in which to store scanned pages")
	scanCmd.Flags().StringVar(&sf.source, "source", "platen", "document source: platen or adf")
	scanCmd.Flags().StringVar(&sf.size, "size", "A4", "page size: A4 or letter")
	scanCmd.Flags().StringVar(&sf.format, "format", "image/jpeg", "file format to request from the scanner")
	scanCmd.Flags().StringVar(&sf.color, "color", "Grayscale8", "color mode: Grayscale8 or RGB24")
	scanCmd.Flags().BoolVar(&sf.duplex, "duplex", true, "scan both sides of the page")
	scanCmd.Flags().DurationVar(&sf.timeout, "timeout", 5*time.Second, "timeout for DNS-SD discovery")

	scanCmd.MarkFlagsMutuallyExclusive("host", "ip")
	scanCmd.MarkFlagsOneRequired("host", "ip")
}

func runScan(cmd *cobra.Command, args []string) error {
	var cl *airscan.Client
	var err error

	if sf.ip != "" {
		printDebug("Connecting directly to %s", sf.ip)
		cl = airscan.NewClientForIP(sf.ip)
	} else {
		printInfo("Finding scanner %q (timeout: %v)...", sf.host, sf.timeout)
		cl, err = resolveViaDNSSD(sf.host, sf.timeout)
		if err != nil {
			return err
		}
	}

	if skipCertVerify {
		transport := cl.HTTPClient.(*http.Client).Transport.(*http.Transport)
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	cl.SetDebug(debugMode)

	if err := os.MkdirAll(sf.scanDir, 0700); err != nil {
		return err
	}

	return doScan(cl, sf)
}

func resolveViaDNSSD(host string, timeout time.Duration) (*airscan.Client, error) {
	ctx, canc := context.WithCancel(context.Background())
	defer canc()
	if timeout > 0 {
		ctx, canc = context.WithTimeout(ctx, timeout)
		defer canc()
	}

	var found *dnssd.BrowseEntry

	addFn := func(srv dnssd.BrowseEntry) {
		printDebug("DNS-SD service discovered: %+v", srv)
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

	return airscan.NewClientForService(found), nil
}

func doScan(cl *airscan.Client, flags scanFlags) error {
	settings := preset.GrayscaleA4ADF()

	switch flags.source {
	case "platen":
		settings.InputSource = "Platen"
	case "adf":
		// already set by preset
	default:
		return fmt.Errorf("unexpected source: got %q, want one of platen or adf", flags.source)
	}

	switch flags.size {
	case "A4":
		// already set by preset
	case "letter":
		settings.ScanRegions.Regions[0].Width = 2550
		settings.ScanRegions.Regions[0].Height = 3300
	default:
		return fmt.Errorf("unexpected page size: got %q, want one of A4 or letter", flags.size)
	}

	suffix := "jpg"
	switch flags.format {
	case "image/jpeg":
		// default
	case "application/pdf":
		suffix = "pdf"
		settings.DocumentFormat = "application/pdf"
	}

	switch flags.color {
	case "Grayscale8":
		// already set by preset
	case "RGB24":
		settings.ColorMode = "RGB24"
	}

	settings.Duplex = flags.duplex

	scan, err := cl.Scan(settings)
	if err != nil {
		return err
	}
	defer scan.Close()

	pagenum := 1
	for scan.ScanPage() {
		printInfo("Receiving page %d...", pagenum)

		var fn string
		for {
			fn = filepath.Join(flags.scanDir, fmt.Sprintf("page%d.%s", pagenum, suffix))
			_, err := os.Stat(fn)
			if err == nil {
				pagenum++
				continue
			}
			if os.IsNotExist(err) {
				break
			}
		}

		o, err := renameio.TempFile("", fn)
		if err != nil {
			return err
		}
		defer o.Cleanup()

		if _, err := io.Copy(o, scan.CurrentPage()); err != nil {
			return err
		}

		size, err := o.Seek(0, io.SeekCurrent)
		if err != nil {
			return err
		}

		if err := o.CloseAtomicallyReplace(); err != nil {
			return err
		}

		printSuccess("Wrote %s (%d bytes)", fn, size)
		pagenum++
	}

	return scan.Err()
}
