// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================
package client

import (
	"context"
	"fmt"
	"time"
)

// MTUProbeOutcome reports the result of one ProbeStandaloneMTU call. Reason is
// "" on accept, else "upload" / "download" / "config" / "cancelled".
type MTUProbeOutcome struct {
	Accepted      bool
	Reason        string
	UploadBytes   int
	UploadChars   int
	DownloadBytes int
	RTTMillis     int64
}

// ProbeStandaloneMTU runs the engine's upload/download MTU binary search against
// ip:port. It builds a transient Connection inline and never touches the
// balancer, so it is safe on a Client that has never been Run(). timeout bounds
// each probe RTT (c.mtuTestTimeout if zero); total wall time is capped below.
func (c *Client) ProbeStandaloneMTU(
	ctx context.Context,
	ip string,
	port int,
	domain string,
	timeout time.Duration,
) MTUProbeOutcome {
	if c == nil || c.codec == nil {
		return MTUProbeOutcome{Reason: "config"}
	}
	if domain == "" || ip == "" {
		return MTUProbeOutcome{Reason: "config"}
	}
	if port <= 0 {
		port = 53
	}

	// mtuTestTimeout is fixed at New() and read directly by the probe helpers,
	// so the timeout arg only bounds the outer ctx deadline computed below.
	probeTimeout := timeout
	if probeTimeout <= 0 {
		probeTimeout = c.mtuTestTimeout
		if probeTimeout <= 0 {
			probeTimeout = 4 * time.Second
		}
	}
	retries := c.mtuTestRetries
	if retries < 1 {
		retries = 1
	}
	// log2(512) ≈ 9 candidates per stage × 2 stages × retries × per-probe
	// timeout, plus a safety margin. Hard cap at 30s — a real path takes ≤4s.
	walltimeCap := time.Duration(int64(probeTimeout) * int64(retries) * 20)
	if walltimeCap < 4*time.Second {
		walltimeCap = 4 * time.Second
	}
	if walltimeCap > 30*time.Second {
		walltimeCap = 30 * time.Second
	}
	pCtx, cancel := context.WithTimeout(ctx, walltimeCap)
	defer cancel()

	maxUploadPayload := c.maxUploadMTUPayload(domain)
	if maxUploadPayload <= 0 {
		return MTUProbeOutcome{Reason: "config"}
	}

	conn := Connection{
		// Synthetic key: applyMTUDecision is never called here, but a non-empty
		// key keeps any reused-connection logging clean.
		Key:           fmt.Sprintf("scan-probe:%s:%d", ip, port),
		Domain:        domain,
		ResolverLabel: fmt.Sprintf("%s:%d", ip, port),
	}

	result, reason := c.probeConnectionMTU(pCtx, conn, maxUploadPayload)
	if pCtx.Err() != nil && reason != mtuRejectNone {
		return MTUProbeOutcome{Reason: "cancelled"}
	}
	switch reason {
	case mtuRejectUpload:
		return MTUProbeOutcome{
			Accepted:    false,
			Reason:      "upload",
			UploadBytes: result.UploadBytes,
			UploadChars: result.UploadChars,
		}
	case mtuRejectDownload:
		return MTUProbeOutcome{
			Accepted:      false,
			Reason:        "download",
			UploadBytes:   result.UploadBytes,
			UploadChars:   result.UploadChars,
			DownloadBytes: result.DownloadBytes,
		}
	}
	return MTUProbeOutcome{
		Accepted:      true,
		UploadBytes:   result.UploadBytes,
		UploadChars:   result.UploadChars,
		DownloadBytes: result.DownloadBytes,
		RTTMillis:     result.ResolveTime.Milliseconds(),
	}
}
