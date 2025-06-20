/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"

	"github.com/scionproto/scion/pkg/addr"
)

const (
	DefaultSCIONDaemonAddr = "127.0.0.1:30255"
)

func GetScionAddress() string {
	cmd := exec.Command("scion", "address")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}

// LoadScionConfigFromEnv loads SCION configuration from environment variables
func LoadScionConfigFromEnv() (*ScionConfig, error) {
	config := &ScionConfig{
		DaemonAddr: DefaultSCIONDaemonAddr,
		PathPolicy: PathPolicyShortest,
	}

	// Load daemon address from environment
	if addr := os.Getenv(EnvSCIONDaemonAddr); addr != "" {
		config.DaemonAddr = addr
	}

	// Load path policy from environment
	if policy := os.Getenv(EnvSCIONPathPolicy); policy != "" {
		config.PathPolicy = ParsePathPolicy(policy)
	}

	// Try to get SCION address from scion command first, then fallback to environment
	scionAddress := GetScionAddress()
	if scionAddress == "" {
		scionAddress = os.Getenv(EnvSCIONLocalIA)
	}

	if scionAddress == "" {
		return nil, fmt.Errorf("SCION configuration not found: neither scion command nor %s environment variable available", EnvSCIONLocalIA)
	}

	// Parse SCION address into IA and IP
	parts := strings.Split(scionAddress, ",")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid SCION address format %q: expected ISD-AS,IP", scionAddress)
	}

	// Parse ISD-AS
	ia, err := addr.ParseIA(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid ISD-AS in SCION address %q: %w", scionAddress, err)
	}

	// Parse IP address
	localIP := net.ParseIP(parts[1])
	if localIP == nil {
		return nil, fmt.Errorf("invalid IP address in SCION address %q", scionAddress)
	}

	config.LocalIP = localIP
	config.LocalIA = ia
	return config, nil
}

// ValidateConfig validates the SCION configuration
func (c *ScionConfig) ValidateConfig() error {
	if c.LocalIA.IsZero() {
		return fmt.Errorf("LocalIA cannot be zero")
	}

	if c.DaemonAddr == "" {
		return fmt.Errorf("DaemonAddr cannot be empty")
	}

	return nil
}

// String returns a string representation of the configuration
func (c *ScionConfig) String() string {
	return fmt.Sprintf("ScionConfig{LocalIA: %s, DaemonAddr: %s, PathPolicy: %s}",
		c.LocalIA, c.DaemonAddr, c.PathPolicy)
}

// DefaultScionConfig returns a default SCION configuration
func DefaultScionConfig() *ScionConfig {
	return &ScionConfig{
		DaemonAddr: DefaultSCIONDaemonAddr,
		PathPolicy: PathPolicyFirst,
	}
}

// ParseIA parses an IA string in the format "ISD-AS"
func ParseIA(s string) (addr.IA, error) {
	return addr.ParseIA(s)
}

// FormatIA formats an IA to string
func FormatIA(ia addr.IA) string {
	return ia.String()
}

// Environment variable names for SCION configuration
const (
	EnvSCIONDaemonAddr = "SCION_DAEMON_ADDRESS"
	EnvSCIONLocalIA    = "SCION_LOCAL_IA"
	EnvSCIONTopology   = "SCION_TOPOLOGY_FILE"
	EnvSCIONPathPolicy = "SCION_PATH_POLICY"
)

// GetConfigSummary returns a summary of current SCION configuration
func GetConfigSummary() string {
	var parts []string

	if addr := os.Getenv(EnvSCIONDaemonAddr); addr != "" {
		parts = append(parts, fmt.Sprintf("DaemonAddr=%s", addr))
	}

	if ia := os.Getenv(EnvSCIONLocalIA); ia != "" {
		parts = append(parts, fmt.Sprintf("LocalIA=%s", ia))
	}

	if policy := os.Getenv(EnvSCIONPathPolicy); policy != "" {
		parts = append(parts, fmt.Sprintf("PathPolicy=%s", policy))
	}

	if len(parts) == 0 {
		return "No SCION configuration found"
	}

	return strings.Join(parts, ", ")
}
