/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"fmt"
	"io"
	"strings"

	"golang.zx2c4.com/wireguard/conn"
)

// SCION-specific UAPI operations and configurations

// handleScionUAPISet handles SCION-specific UAPI set operations
func (device *Device) handleScionUAPISet(key, value string) error {
	switch key {
	case "scion_path_policy":
		return device.setScionPathPolicy(value)
	default:
		return fmt.Errorf("unknown SCION UAPI key: %s", key)
	}
}

// setScionPathPolicy sets the SCION path selection policy
func (device *Device) setScionPathPolicy(value string) error {
	device.net.Lock()
	defer device.net.Unlock()

	if scionBind, ok := device.net.bind.(*conn.ScionNetBind); ok {
		scionBind.SetPathPolicy(value)
		device.log.Verbosef("Set SCION path policy to: %s", value)
		return nil
	}

	return fmt.Errorf("SCION bind not available")
}

// writeScionUAPIStatus writes SCION-specific status to the UAPI
func (device *Device) writeScionUAPIStatus(buf io.Writer) {
	device.net.RLock()
	defer device.net.RUnlock()

	if scionBind, ok := device.net.bind.(*conn.ScionNetBind); ok {
		fmt.Fprintf(buf, "scion_enabled=true\n")
		// Add current path policy
		fmt.Fprintf(buf, "scion_path_policy=%s\n", scionBind.GetPathPolicy())
	} else {
		fmt.Fprintf(buf, "scion_enabled=false\n")
	}
}

// Peer-specific SCION methods

// setScionPeerEndpoint sets a SCION endpoint for a peer
func (peer *Peer) setScionPeerEndpoint(value string) error {
	peer.endpoint.Lock()
	defer peer.endpoint.Unlock()

	if scionBind, ok := peer.device.net.bind.(*conn.ScionNetBind); ok {
		endpoint, err := scionBind.ParseEndpoint(value)
		if err != nil {
			return fmt.Errorf("failed to parse SCION endpoint %s: %w", value, err)
		}

		peer.endpoint.val = endpoint
		peer.device.log.Verbosef("Set SCION endpoint for peer: %s", value)
		return nil
	}

	return fmt.Errorf("SCION bind not available")
}

// writeScionPeerStatus writes SCION-specific peer status
func (peer *Peer) writeScionPeerStatus(buf io.Writer) {
	peer.endpoint.Lock()
	defer peer.endpoint.Unlock()

	if scionEp, ok := peer.endpoint.val.(*conn.ScionNetEndpoint); ok {
		fmt.Fprintf(buf, "scion_endpoint=true\n")
		if scionAddr := scionEp.GetScionAddr(); scionAddr != nil {
			fmt.Fprintf(buf, "scion_address=%s\n", scionAddr.String())
		}

	} else {
		fmt.Fprintf(buf, "scion_endpoint=false\n")
	}
}

// Enhanced UAPI command parsing for SCION

// parseScionUAPILine parses a SCION-specific UAPI line
func parseScionUAPILine(line string) (key, value string, isScionCommand bool) {
	if !strings.HasPrefix(line, "scion_") {
		return "", "", false
	}

	parts := strings.SplitN(line, "=", 2)
	if len(parts) != 2 {
		return "", "", false
	}

	return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), true
}
