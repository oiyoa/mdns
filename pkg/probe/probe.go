// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package probe

import (
	"context"
	"fmt"
	"time"

	"masterdnsvpn-go/internal/client"
	"masterdnsvpn-go/internal/config"
	"masterdnsvpn-go/internal/logger"
	"masterdnsvpn-go/internal/security"
)

// Result is the verdict for one resolver. Reason on reject is one of
// "upload" / "download" / "config" / "cancelled".
type Result struct {
	Accepted      bool
	Reason        string
	UploadBytes   int
	UploadChars   int
	DownloadBytes int
	RTTMillis     int64
}

// Prober holds a reusable in-memory engine client for certifying resolvers.
type Prober struct {
	c      *client.Client
	domain string
}

// NewFromConfig builds a Prober from a finalized ClientConfig. It performs no
// I/O and starts no goroutines; the client is never Run().
func NewFromConfig(cc config.ClientConfig) (*Prober, error) {
	if len(cc.Domains) == 0 {
		return nil, fmt.Errorf("probe: domain required")
	}
	codec, err := security.NewCodec(cc.DataEncryptionMethod, cc.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("probe: codec: %w", err)
	}
	log := logger.New("MasterDnsVPN Prober", cc.LogLevel)
	return &Prober{c: client.New(cc, log, codec), domain: cc.Domains[0]}, nil
}

// Probe certifies one resolver at ip:port. perProbeTimeout bounds each probe
// RTT (0 uses the engine default). Cancel via ctx. Safe for concurrent use.
func (pr *Prober) Probe(ctx context.Context, ip string, port int, perProbeTimeout time.Duration) Result {
	out := pr.c.ProbeStandaloneMTU(ctx, ip, port, pr.domain, perProbeTimeout)
	return Result{
		Accepted:      out.Accepted,
		Reason:        out.Reason,
		UploadBytes:   out.UploadBytes,
		UploadChars:   out.UploadChars,
		DownloadBytes: out.DownloadBytes,
		RTTMillis:     out.RTTMillis,
	}
}
