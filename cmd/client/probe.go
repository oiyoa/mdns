// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"masterdnsvpn-go/internal/config"
	"masterdnsvpn-go/pkg/probe"
)

// probeVerdict is the stable stdout contract the scanner parses. Keep field
// names stable across releases.
type probeVerdict struct {
	Accepted      bool   `json:"accepted"`
	Reason        string `json:"reason"`
	UploadBytes   int    `json:"uploadBytes"`
	UploadChars   int    `json:"uploadChars"`
	DownloadBytes int    `json:"downloadBytes"`
	RTTMillis     int64  `json:"rttMillis"`
}

type probeCLIOptions struct {
	configPath string
	jsonPath   string
	jsonBase64 string
	domains    string
	key        string
	ip         string
	port       int
	timeout    time.Duration
}

func newProbeFlagSet(output io.Writer) (*flag.FlagSet, *probeCLIOptions, *config.ClientConfigFlagBinder, error) {
	fs := flag.NewFlagSet("probe", flag.ContinueOnError)
	fs.SetOutput(output)

	opts := &probeCLIOptions{}
	// Config sources — identical to the client.
	fs.StringVar(&opts.configPath, "config", "", "Path to client configuration file (TOML/JSON)")
	fs.StringVar(&opts.configPath, "c", "", "Alias for -config")
	fs.StringVar(&opts.jsonPath, "json", "", "Path to client JSON configuration file")
	fs.StringVar(&opts.jsonPath, "j", "", "Alias for -json")
	fs.StringVar(&opts.jsonBase64, "json_base64", "", "Load client JSON configuration from base64")
	fs.StringVar(&opts.jsonBase64, "json-base64", "", "Alias for -json_base64")
	// Convenience aliases mirroring the client.
	fs.StringVar(&opts.domains, "d", "", "Alias for -domains (comma separated)")
	fs.StringVar(&opts.key, "k", "", "Alias for -encryption-key")
	fs.StringVar(&opts.key, "key", "", "Compatibility alias for -encryption-key")
	// Probe-specific.
	fs.StringVar(&opts.ip, "ip", "", "resolver IP to certify (required)")
	fs.IntVar(&opts.port, "port", 53, "resolver UDP port")
	fs.DurationVar(&opts.timeout, "timeout", 0, "per-probe RTT timeout (0 = engine default)")

	// All ENCRYPTION_KEY / DOMAINS / DATA_ENCRYPTION_METHOD / *_MTU / LOG_LEVEL
	// override flags, generated from the config struct exactly as for the client.
	binder, err := config.NewClientConfigFlagBinder(fs)
	if err != nil {
		return nil, nil, nil, err
	}
	return fs, opts, binder, nil
}

func runProbeCommand(args []string) int {
	fs, opts, binder, err := newProbeFlagSet(os.Stderr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "probe: %v\n", err)
		return 1
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if opts.ip == "" {
		fmt.Fprintln(os.Stderr, "probe: -ip is required")
		fs.Usage()
		return 2
	}

	overrides := binder.Overrides()
	if opts.domains != "" {
		overrides.Values["Domains"] = strings.Split(opts.domains, ",")
	}
	if opts.key != "" {
		overrides.Values["EncryptionKey"] = opts.key
	}

	var cfg config.ClientConfig
	switch {
	case opts.jsonBase64 != "":
		cfg, err = config.LoadProbeClientConfigFromJSONBase64(opts.jsonBase64, overrides)
	case opts.jsonPath != "":
		cfg, err = config.LoadProbeClientConfig(opts.jsonPath, overrides)
	case opts.configPath != "":
		cfg, err = config.LoadProbeClientConfig(opts.configPath, overrides)
	default:
		cfg, err = config.NewProbeClientConfigFromOverrides(overrides)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "probe: %v\n", err)
		return 1
	}

	pr, err := probe.NewFromConfig(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "probe: %v\n", err)
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	res := pr.Probe(ctx, opts.ip, opts.port, opts.timeout)

	out, err := json.Marshal(probeVerdict{
		Accepted:      res.Accepted,
		Reason:        res.Reason,
		UploadBytes:   res.UploadBytes,
		UploadChars:   res.UploadChars,
		DownloadBytes: res.DownloadBytes,
		RTTMillis:     res.RTTMillis,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "probe: marshal: %v\n", err)
		return 1
	}
	fmt.Println(string(out))
	return 0
}
