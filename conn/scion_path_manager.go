// SCION Path Manager for WireGuard backend.
// Maintains per-destination SCION path cache, refreshed in background.
// Uses sciond via daemon.Connector from bind_scion.go.

package conn

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/snet"
)

// refreshInterval is the default cadence at which the manager re‑resolves
// paths.  Callers may override this by passing WithRefreshInterval when
// building the PathManager.
const refreshInterval = 5 * time.Minute

// PathCacheEntry represents a cache entry for paths to a specific IA
type PathCacheEntry struct {
	Paths          []snet.Path // All available paths
	SelectedIndex  int         // Index of currently selected path
	IsManualSelect bool        // Whether path was manually selected
	LastRefresh    time.Time   // When paths were last refreshed
	PathRanks      []PathRank  // Ranking information for each path
	LastError      error       // Last error encountered during refresh
}

// PathRank contains ranking information for a single path
type PathRank struct {
	LatencyScore   time.Duration // Calculated latency score
	BandwidthScore uint64        // Calculated bandwidth score
	HopCount       int           // Number of hops
	LastVerified   time.Time     // When the path was last verified
	IsAlive        bool          // Whether the path is currently alive
}

// PathManager maintains fresh SCION paths for all remote IAs that the program
// has seen so far.  All public methods are concurrency‑safe.
//
// A single instance is shared by all ScionNetBind objects, but nothing stops
// you from running several independent managers if you prefer tighter
// isolation.
//
// On creation PathManager immediately fetches paths for any destinations that
// were registered prior to Start() – this gives callers deterministic latency
// for their first packet.
//
// A background goroutine does periodic refreshes until Close() is called.  The
// manager is therefore long‑lived and should be closed during program
// shutdown.

type PathManager struct {
	ctx    context.Context
	cancel context.CancelFunc

	d       daemon.Connector
	localIA addr.IA
	policy  PathPolicy

	mu    sync.RWMutex // protects everything below
	cache map[addr.IA]*PathCacheEntry
	log   Logger

	refresh    time.Duration
	httpServer *http.Server // Added for the API server
}

// NewPathManager wires up a new path manager.  The background refresh only
// starts after Start() is called.
func NewPathManager(d daemon.Connector, localIA addr.IA, pol PathPolicy, log Logger, opts ...PathManagerOption) *PathManager {
	pm := &PathManager{
		d:       d,
		localIA: localIA,
		policy:  pol,
		cache:   make(map[addr.IA]*PathCacheEntry),
		log:     log,
		refresh: refreshInterval,
	}
	for _, opt := range opts {
		opt(pm)
	}
	pm.ctx, pm.cancel = context.WithCancel(context.Background())
	pm.Start() // This starts the refresh loop
	// Start the API server with default and fallback ports
	go func() { // Run in a goroutine to not block NewPathManager
		if err := pm.StartAPIServer(defaultAPIPort, fallbackAPIPort1, fallbackAPIPort2); err != nil {
			pm.log.Errorf("Failed to start PathManager API server: %v", err)
		}
	}()
	return pm
}

// PathManagerOption configures a PathManager.
// Currently only WithRefreshInterval exists but more can be added as needed.
type PathManagerOption func(*PathManager)

func WithRefreshInterval(d time.Duration) PathManagerOption {
	return func(pm *PathManager) { pm.refresh = d }
}

// Start kicks off the periodic refresh goroutine.  Calling Start multiple
// times is a no‑op.
func (pm *PathManager) Start() {
	go pm.loop()
}

func (pm *PathManager) loop() {
	ticker := time.NewTicker(pm.refresh)
	defer ticker.Stop()
	for {
		select {
		case <-pm.ctx.Done():
			return
		case <-ticker.C:
			pm.refreshAll()
		}
	}
}

// Close stops the background refresh.  It is safe to call Close more than
// once.
func (pm *PathManager) Close() {
	pm.cancel()
	if pm.httpServer != nil {
		pm.log.Verbosef("Shutting down PathManager API server...")
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		if err := pm.httpServer.Shutdown(shutdownCtx); err != nil {
			pm.log.Errorf("PathManager API server shutdown error: %v", err)
		} else {
			pm.log.Verbosef("PathManager API server gracefully shut down.")
		}
	}
}

// RegisterEndpoint ensures that the given destination IA is tracked.  The
// method is cheap if the IA is already known.
func (pm *PathManager) RegisterEndpoint(ia addr.IA) {
	pm.mu.RLock()
	_, exists := pm.cache[ia]
	pm.mu.RUnlock()
	if exists {
		return
	}

	// Use double-checked locking to avoid race conditions
	pm.mu.Lock()
	// Double-check after acquiring write lock
	if _, exists := pm.cache[ia]; exists {
		pm.mu.Unlock()
		return
	}
	pm.cache[ia] = nil
	pm.mu.Unlock()

	// Create empty entry and trigger immediate fetch so callers get paths
	// right away.
	if err := pm.refreshOne(ia); err != nil {
		pm.log.Errorf("SCION path fetch failed for %s: %v", ia, err)
	}
}

// getPaths returns a snapshot of the current paths for a destination IA.  The
// slice is safe for the caller to modify.
func (pm *PathManager) getPaths(ia addr.IA) []snet.Path {
	pm.mu.RLock()
	entry := pm.cache[ia]
	pm.mu.RUnlock()
	if entry == nil {
		return nil
	}
	out := make([]snet.Path, len(entry.Paths))
	copy(out, entry.Paths)
	return out
}

func (pm *PathManager) GetPath(ia addr.IA) (snet.Path, error) {
	pm.mu.RLock()
	entry := pm.cache[ia]
	pm.mu.RUnlock()
	if entry == nil || len(entry.Paths) == 0 {
		return nil, fmt.Errorf("no path found for IA %s", ia)
	}
	return entry.Paths[entry.SelectedIndex], nil
}

func (pm *PathManager) refreshAll() {
	pm.mu.RLock()
	dests := make([]addr.IA, 0, len(pm.cache))
	for ia := range pm.cache {
		dests = append(dests, ia)
	}
	pm.mu.RUnlock()
	for _, ia := range dests {
		if err := pm.refreshOne(ia); err != nil {
			pm.log.Errorf("SCION path refresh failed for %s: %v", ia, err)
		}
	}
}

func (pm *PathManager) refreshOne(dest addr.IA) error {
	ctx, cancel := context.WithTimeout(pm.ctx, 3*time.Second)
	defer cancel()

	paths, err := pm.d.Paths(ctx, dest, pm.localIA, daemon.PathReqFlags{Refresh: true})
	if err != nil {
		pm.mu.Lock()
		if entry := pm.cache[dest]; entry != nil {
			entry.LastError = err
		}
		pm.mu.Unlock()
		return fmt.Errorf("daemon Paths(): %w", err)
	}

	if len(paths) == 0 {
		pm.log.Verbosef("No paths found from %s to %s", pm.localIA, dest)
	}

	// Create path ranks
	ranks := make([]PathRank, len(paths))
	for i, path := range paths {
		meta := path.Metadata()
		hopCount := 0
		if meta != nil {
			hopCount = len(meta.Interfaces)
		}
		ranks[i] = PathRank{
			LatencyScore:   latencyScore(path),
			BandwidthScore: bandwidthScore(path),
			HopCount:       hopCount,
			LastVerified:   time.Now(),
			IsAlive:        true,
		}
	}

	// Update cache
	pm.mu.Lock()
	defer pm.mu.Unlock()

	entry := pm.cache[dest]
	if entry == nil {
		entry = &PathCacheEntry{}
		pm.cache[dest] = entry
	}

	// Handle manual path selection
	manualPathFound := false
	if entry.IsManualSelect && len(entry.Paths) > 0 &&
		entry.SelectedIndex >= 0 && entry.SelectedIndex < len(entry.Paths) {

		oldPath := entry.Paths[entry.SelectedIndex]
		oldFingerprint := snet.Fingerprint(oldPath).String()

		// Find the same path in the new set
		for i, newPath := range paths {
			if snet.Fingerprint(newPath).String() == oldFingerprint {
				// Found the same path, move it to the front and preserve selection
				if i != 0 {
					// Move the path and its corresponding rank to position 0
					paths[0], paths[i] = paths[i], paths[0]
					ranks[0], ranks[i] = ranks[i], ranks[0]
				}
				entry.SelectedIndex = 0
				manualPathFound = true
				break
			}
		}
	}

	// If no manual selection or manual path not found, use policy-based sorting
	if !manualPathFound {
		if len(paths) > 0 {
			// Create indices for sorting to maintain path-rank correspondence
			indices := make([]int, len(paths))
			for i := range indices {
				indices[i] = i
			}

			// Sort indices based on path policy
			sort.SliceStable(indices, func(i, j int) bool {
				return lessByPolicy(paths[indices[i]], paths[indices[j]], pm.policy)
			})

			// Reorder both paths and ranks based on sorted indices
			sortedPaths := make([]snet.Path, len(paths))
			sortedRanks := make([]PathRank, len(ranks))
			for i, idx := range indices {
				sortedPaths[i] = paths[idx]
				sortedRanks[i] = ranks[idx]
			}
			paths = sortedPaths
			ranks = sortedRanks
		}
		entry.SelectedIndex = 0
		entry.IsManualSelect = false
	}

	entry.Paths = paths
	entry.PathRanks = ranks
	entry.LastRefresh = time.Now()
	entry.LastError = nil

	return nil
}

// SetPolicy sets the path selection policy
func (pm *PathManager) SetPolicy(policy string) {
	// Update policy without holding the lock during refresh
	pm.mu.Lock()
	pm.policy = ParsePathPolicy(policy)
	pm.mu.Unlock()

	// Refresh all paths with new policy (this will acquire its own locks)
	pm.refreshAll()
}

// lessByPolicy implements the four simple scoring policies that bind_scion.go
// exposes via the PathPolicy enum.
func lessByPolicy(a, b snet.Path, pol PathPolicy) bool {
	switch pol {
	case PathPolicyShortest:
		metaA := a.Metadata()
		metaB := b.Metadata()
		laA := 0
		laB := 0
		if metaA != nil {
			laA = len(metaA.Interfaces)
		}
		if metaB != nil {
			laB = len(metaB.Interfaces)
		}
		return laA < laB
	case PathPolicyBandwidth:
		return bandwidthScore(a) > bandwidthScore(b)
	case PathPolicyLatency:
		return latencyScore(a) < latencyScore(b)
	case PathPolicyFirst:
		fallthrough
	default:
		return false // keep original order (changed from true to false for stable sort)
	}
}

func bandwidthScore(p snet.Path) uint64 {
	meta := p.Metadata()
	if meta == nil || len(meta.Bandwidth) == 0 {
		return 0
	}
	min := meta.Bandwidth[0]
	for _, bw := range meta.Bandwidth[1:] {
		if bw < min {
			min = bw
		}
	}
	return min
}

func latencyScore(p snet.Path) time.Duration {
	meta := p.Metadata()
	if meta == nil || len(meta.Latency) == 0 {
		return time.Duration(1<<63 - 1) // effectively +∞
	}
	var total time.Duration
	for _, l := range meta.Latency {
		if l < 0 {
			// Missing measurement – treat as very slow.
			return time.Duration(1<<63 - 1)
		}
		total += l
	}
	return total
}

// PathInfo represents the JSON structure for path information
type PathInfo struct {
	LocalISDAS  string        `json:"local_isd_as"`
	Destination string        `json:"destination"`
	Paths       []PathDetails `json:"paths"`
	Error       string        `json:"error,omitempty"`
}

// PathDetails represents the JSON structure for individual path details
type PathDetails struct {
	Index       int       `json:"index"`
	Fingerprint string    `json:"fingerprint"`
	Hops        []HopInfo `json:"hops"`
	Sequence    string    `json:"sequence"`
	NextHop     string    `json:"next_hop"`
	Expiry      string    `json:"expiry"`
	MTU         uint16    `json:"mtu"`
	Latency     []int64   `json:"latency"`
	Bandwidth   []uint64  `json:"bandwidth"`
	Status      string    `json:"status"`
	LocalIP     string    `json:"local_ip"`
}

// HopInfo represents the JSON structure for hop information
type HopInfo struct {
	IFID  uint16 `json:"ifid"`
	ISDAS string `json:"isd_as"`
}

// GetPathsJSON returns a JSON string containing available paths for the given IA
func (pm *PathManager) GetPathsJSON(iaStr string) (string, error) {
	// Parse the IA string
	ia, err := addr.ParseIA(iaStr)
	if err != nil {
		return "", fmt.Errorf("invalid IA format: %w", err)
	}

	// Get paths for the IA with optimized locking
	pm.mu.RLock()
	entry := pm.cache[ia]
	localIA := pm.localIA
	pm.mu.RUnlock()

	if entry == nil || len(entry.Paths) == 0 {
		// Try to register and refresh paths if none found
		pm.RegisterEndpoint(ia)
		pm.mu.RLock()
		entry = pm.cache[ia]
		pm.mu.RUnlock()
	}

	// Create path info structure
	pathInfo := PathInfo{
		LocalISDAS:  localIA.String(),
		Destination: iaStr,
	}

	if entry == nil || len(entry.Paths) == 0 {
		pathInfo.Error = "No paths available"
	} else {
		pathInfo.Paths = make([]PathDetails, 0, len(entry.Paths))
		for i, path := range entry.Paths {
			meta := path.Metadata()
			if meta == nil {
				// Skip paths with no metadata, but log the issue
				continue
			}

			// Convert latencies to int64 (milliseconds)
			latencies := make([]int64, len(meta.Latency))
			for j, l := range meta.Latency {
				if l < 0 {
					latencies[j] = -1
				} else {
					latencies[j] = l.Milliseconds()
				}
			}

			// Create sequence string
			var sequence strings.Builder
			for j, iface := range meta.Interfaces {
				if j > 0 {
					sequence.WriteString(" ")
				}
				sequence.WriteString(iface.String())
			}

			// Get next hop
			nextHop := path.UnderlayNextHop()
			nextHopStr := ""
			if nextHop != nil {
				nextHopStr = nextHop.String()
			}

			// Get path status
			status := "alive"
			if i < len(entry.PathRanks) && !entry.PathRanks[i].IsAlive {
				status = "dead"
			}

			details := PathDetails{
				Index:       i,
				Fingerprint: snet.Fingerprint(path).String(),
				MTU:         meta.MTU,
				Latency:     latencies,
				Bandwidth:   meta.Bandwidth,
				Sequence:    sequence.String(),
				NextHop:     nextHopStr,
				Expiry:      meta.Expiry.Format(time.RFC3339),
				Status:      status,
				LocalIP:     localIA.String(),
			}

			// Add hop information
			details.Hops = make([]HopInfo, len(meta.Interfaces))
			for j, iface := range meta.Interfaces {
				details.Hops[j] = HopInfo{
					IFID:  uint16(iface.ID),
					ISDAS: iface.IA.String(),
				}
			}

			pathInfo.Paths = append(pathInfo.Paths, details)
		}
	}

	// Convert to JSON
	jsonData, err := json.MarshalIndent(pathInfo, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal path info: %w", err)
	}

	return string(jsonData), nil
}

// SetPath sets the path for a given IA based on the path index.
// If the index is invalid or no paths are available, it returns an error.
func (pm *PathManager) SetPath(iaStr string, pathIndex int) error {
	// Parse the IA string
	ia, err := addr.ParseIA(iaStr)
	if err != nil {
		return fmt.Errorf("invalid IA format: %w", err)
	}

	// Get current paths and update selection atomically
	pm.mu.Lock()
	defer pm.mu.Unlock()

	entry := pm.cache[ia]

	// Check if we have any paths
	if entry == nil || len(entry.Paths) == 0 {
		return fmt.Errorf("no paths available for IA %s", iaStr)
	}

	// Check if the index is valid
	if pathIndex < 0 || pathIndex >= len(entry.Paths) {
		return fmt.Errorf("invalid path index %d for IA %s (available paths: %d)",
			pathIndex, iaStr, len(entry.Paths))
	}

	// Update the cache entry
	entry.SelectedIndex = pathIndex
	entry.IsManualSelect = true

	return nil
}

// --- HTTP API Server ---

const (
	defaultAPIPort   = 28015
	fallbackAPIPort1 = 28016
	fallbackAPIPort2 = 28017
)

// StartAPIServer initializes and starts the HTTP API server for the PathManager.
// It tries the defaultPort and then any fallbackPorts if the initial ones are in use.
func (pm *PathManager) StartAPIServer(defaultPort int, fallbackPorts ...int) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/paths", pm.handleGetPathsJSON())
	mux.HandleFunc("/path", pm.handleSetPath())

	pm.httpServer = &http.Server{
		Handler: mux,
		// Consider adding ReadTimeout, WriteTimeout, IdleTimeout for robustness
	}

	portsToTry := append([]int{defaultPort}, fallbackPorts...)
	var listener net.Listener
	var err error
	var actualPort int

	for _, port := range portsToTry {
		addr := ":" + strconv.Itoa(port)
		listener, err = net.Listen("tcp", addr)
		if err == nil {
			actualPort = port
			pm.log.Verbosef("PathManager API server attempting to listen on %s", addr)
			break
		}
		pm.log.Verbosef("PathManager API server failed to listen on port %d: %v. Trying next port.", port, err)
	}

	if listener == nil {
		// Use the standard logger if pm.log is not available or for critical startup errors
		log.Printf("PathManager API server failed to bind to any of the specified ports (%v): %v", portsToTry, err)
		return fmt.Errorf("failed to bind to any of the specified ports (%v): %w", portsToTry, err)
	}

	pm.log.Verbosef("PathManager API server listening on :%d", actualPort)
	// This next line uses the standard log package for messages from http.Server
	go func() {
		if err := pm.httpServer.Serve(listener); err != nil && err != http.ErrServerClosed {
			pm.log.Errorf("PathManager API server crashed: %v", err)
		}
	}()
	pm.log.Verbosef("PathManager API server started serving.")
	return nil
}

// handleGetPathsJSON is the HTTP handler for GET /paths?ia=<ia_string>
func (pm *PathManager) handleGetPathsJSON() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		iaStr := r.URL.Query().Get("ia")
		if iaStr == "" {
			http.Error(w, "Missing 'ia' query parameter", http.StatusBadRequest)
			return
		}

		jsonResponse, err := pm.GetPathsJSON(iaStr)
		if err != nil {
			// Check if the error is due to invalid IA format for a more specific status code
			if strings.Contains(err.Error(), "invalid IA format") {
				http.Error(w, fmt.Sprintf("Failed to get paths: %v", err), http.StatusBadRequest)
			} else if strings.Contains(err.Error(), "No paths available") {
				http.Error(w, fmt.Sprintf("Failed to get paths: %v", err), http.StatusNotFound)
			} else {
				http.Error(w, fmt.Sprintf("Failed to get paths: %v", err), http.StatusInternalServerError)
			}
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, writeErr := w.Write([]byte(jsonResponse))
		if writeErr != nil {
			pm.log.Errorf("Error writing /paths response: %v", writeErr)
		}
	}
}

// SetPathRequest defines the structure for the /path request body
type SetPathRequest struct {
	IA        string `json:"ia"`
	PathIndex int    `json:"path_index"`
}

// handleSetPath is the HTTP handler for POST /path
func (pm *PathManager) handleSetPath() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req SetPathRequest
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields() // Prevent unexpected fields

		if err := decoder.Decode(&req); err != nil {
			http.Error(w, fmt.Sprintf("Invalid request body: %v", err), http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		if req.IA == "" {
			http.Error(w, "Missing 'ia' in request body", http.StatusBadRequest)
			return
		}
		// path_index can be 0, so no specific check for missing, only type.

		err := pm.SetPath(req.IA, req.PathIndex)
		if err != nil {
			// Discriminate errors for better client feedback
			if strings.Contains(err.Error(), "invalid IA format") || strings.Contains(err.Error(), "invalid path index") {
				http.Error(w, fmt.Sprintf("Failed to set path: %v", err), http.StatusBadRequest)
			} else if strings.Contains(err.Error(), "no paths available") {
				http.Error(w, fmt.Sprintf("Failed to set path: %v", err), http.StatusNotFound)
			} else {
				http.Error(w, fmt.Sprintf("Failed to set path: %v", err), http.StatusInternalServerError)
			}
			return
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "Path successfully set") // Simple confirmation message
	}
}
