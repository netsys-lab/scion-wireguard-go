// SCION Network Bind for WireGuard backend.
// Provides SCION network support for WireGuard.

package conn

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/snet"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

var (
	_ Bind = (*ScionNetBind)(nil)
)

// ScionNetBind implements Bind for SCION networks
type ScionNetBind struct {
	mu     sync.RWMutex
	logger Logger

	// SCION network and connections
	scionNetwork  *snet.SCIONNetwork
	scionConn     *snet.Conn
	batchConn     *ScionBatchConn
	localAddr     *net.UDPAddr
	daemonService daemon.Service
	daemonConn    daemon.Connector

	// Path management
	pathManager *PathManager

	// Configuration
	config *ScionConfig

	// State
	useBatch bool

	// Cached connection data for hot paths (accessed under mu)
	cachedConnData *connData
}

// connData holds frequently accessed connection data to reduce lock contention
type connData struct {
	batchConn   *ScionBatchConn
	scionConn   *snet.Conn
	pathManager *PathManager
	useBatch    bool
	// Batch connection fields
	ipv4PC        *ipv4.PacketConn
	ipv6PC        *ipv6.PacketConn
	ipv4RxOffload bool
	ipv6RxOffload bool
	ipv4TxOffload bool
	ipv6TxOffload bool
	scmpHandler   snet.SCMPHandler
}

// ScionConfig holds SCION-specific configuration
type ScionConfig struct {
	DaemonAddr string
	LocalAS    addr.AS
	PathPolicy PathPolicy
	LocalIA    addr.IA
	LocalIP    net.IP
	LocalPort  uint16
}

type PathPolicy int

const (
	PathPolicyShortest PathPolicy = iota
	PathPolicyBandwidth
	PathPolicyLatency
	PathPolicyFirst
)

func (p PathPolicy) String() string {
	switch p {
	case PathPolicyShortest:
		return "shortest"
	case PathPolicyBandwidth:
		return "bandwidth"
	case PathPolicyLatency:
		return "latency"
	case PathPolicyFirst:
		return "first"
	default:
		return "unknown"
	}
}

func ParsePathPolicy(s string) PathPolicy {
	switch strings.ToLower(s) {
	case "shortest":
		return PathPolicyShortest
	case "bandwidth":
		return PathPolicyBandwidth
	case "latency":
		return PathPolicyLatency
	case "first":
		return PathPolicyFirst
	default:
		return PathPolicyFirst
	}
}

// Logger interface for SCION bind
type Logger interface {
	Verbosef(format string, args ...interface{})
	Errorf(format string, args ...interface{})
}

// ScionNetEndpoint represents a SCION endpoint
type ScionNetEndpoint struct {
	StdNetEndpoint
	scionAddr *snet.UDPAddr
}

var (
	_ Endpoint = &ScionNetEndpoint{}
)

func NewScionNetBind(config *ScionConfig, logger Logger) *ScionNetBind {
	useBatch := os.Getenv("USE_BATCH") == "1"
	if useBatch {
		useBatch = runtime.GOOS == "linux" || runtime.GOOS == "android"
	}

	return &ScionNetBind{
		config:         config,
		logger:         logger,
		useBatch:       useBatch,
		cachedConnData: &connData{},
	}
}

func (s *ScionNetBind) initSCION() error {
	if s.config == nil {
		return fmt.Errorf("SCION config is nil")
	}

	// Set up daemon service
	daemonAddr := s.config.DaemonAddr
	if daemonAddr == "" {
		daemonAddr = DefaultSCIONDaemonAddr
	}

	s.daemonService = daemon.Service{
		Address: daemonAddr,
		Metrics: daemon.Metrics{},
	}

	// Connect to SCION daemon
	ctx := context.Background()
	conn, err := s.daemonService.Connect(ctx)
	if err != nil {
		return fmt.Errorf("failed to connect to SCION daemon at %s: %w", daemonAddr, err)
	}
	s.daemonConn = conn

	// Get local IA from daemon
	localIA, err := s.daemonConn.LocalIA(ctx)
	if err != nil {
		s.daemonConn.Close()
		return fmt.Errorf("failed to get local IA from daemon: %w", err)
	}

	// Override with config if specified
	if s.config.LocalIA.IsZero() {
		s.config.LocalIA = localIA
	}

	// Initialize SCION network with proper topology
	s.scionNetwork = &snet.SCIONNetwork{
		Topology:    s.daemonConn,
		ReplyPather: snet.DefaultReplyPather{},
		Metrics:     snet.SCIONNetworkMetrics{},
	}

	s.pathManager = NewPathManager(
		s.daemonConn,        // SCION daemon connection
		s.config.LocalIA,    // our IA
		s.config.PathPolicy, // selection policy
		s.logger,
		WithRefreshInterval(5*time.Minute),
	)
	s.logger.Verbosef("SCION network initialized with IA %s", s.config.LocalIA)

	return nil
}

// updateCachedConnData updates the cached connection data under lock
func (s *ScionNetBind) updateCachedConnData() {
	s.cachedConnData.batchConn = s.batchConn
	s.cachedConnData.scionConn = s.scionConn
	s.cachedConnData.pathManager = s.pathManager
	s.cachedConnData.useBatch = s.useBatch

	if s.batchConn != nil {
		s.cachedConnData.ipv4PC = s.batchConn.ipv4PC
		s.cachedConnData.ipv6PC = s.batchConn.ipv6PC
		s.cachedConnData.ipv4RxOffload = s.batchConn.ipv4RxOffload
		s.cachedConnData.ipv6RxOffload = s.batchConn.ipv6RxOffload
		s.cachedConnData.ipv4TxOffload = s.batchConn.ipv4TxOffload
		s.cachedConnData.ipv6TxOffload = s.batchConn.ipv6TxOffload
		s.cachedConnData.scmpHandler = s.batchConn.scmpHandler
	}
}

func (s *ScionNetBind) getUDPConn(localAddr *net.UDPAddr, port uint16) (*net.UDPConn, error) {
	start, end, err := s.scionNetwork.Topology.PortRange(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to get port range: %w", err)
	}

	network := "udp4"
	if localAddr.IP.To4() == nil {
		network = "udp6"
	}

	if port != 0 {
		conn, err := listenConfig().ListenPacket(context.Background(), network, localAddr.String())
		if err != nil {
			return nil, fmt.Errorf("failed to listen on SCION: %w", err)
		}
		return conn.(*net.UDPConn), nil
	}

	restrictedStart := start
	if start < 1024 {
		restrictedStart = 1024
	}
	for port := end; port >= restrictedStart; port-- {
		localAddr.Port = int(port)
		conn, err := listenConfig().ListenPacket(context.Background(), network, localAddr.String())
		if err == nil {
			return conn.(*net.UDPConn), nil
		}
		if strings.Contains(err.Error(), "address already in use") {
			continue
		}
		return nil, err
	}
	return nil, fmt.Errorf("binding to port range: start=%d, end=%d",
		restrictedStart, end)
}

func (s *ScionNetBind) Open(port uint16) ([]ReceiveFunc, uint16, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.scionConn != nil || s.batchConn != nil {
		return nil, 0, ErrBindAlreadyOpen
	}

	// Initialize SCION if config is provided
	if s.config != nil {
		if err := s.initSCION(); err != nil {
			s.logger.Errorf("Failed to initialize SCION: %v", err)
			return nil, 0, fmt.Errorf("SCION initialization failed: %w", err)
		}
	} else {
		return nil, 0, fmt.Errorf("SCION config is required")
	}

	var fns []ReceiveFunc
	var actualPort uint16

	// Create SCION local address
	s.localAddr = &net.UDPAddr{IP: s.config.LocalIP, Port: int(port)}

	if s.useBatch {
		// Try to use batch connection on Linux/Android
		udpConn, err := s.getUDPConn(s.localAddr, port)
		if err != nil {
			s.logger.Errorf("Failed to create UDP conn for batch: %v", err)
			s.logger.Verbosef("Falling back to regular SCION connection")
			s.useBatch = false
		} else {
			s.batchConn = NewScionBatchConn(
				udpConn,
				s.config.LocalIA,
				s.scionNetwork.Topology,
				s.pathManager,
				s.logger,
			)
			scmpHandler := s.scionNetwork.SCMPHandler
			s.batchConn.SetSCMPHandler(scmpHandler)
			actualPort = uint16(s.batchConn.LocalAddr().(*net.UDPAddr).Port)

			// Update cached connection data
			s.updateCachedConnData()

			fns = append(fns, s.makeReceiveSCION())
			s.logger.Verbosef("SCION batch listener started on port %d", actualPort)
		}
	}

	// Fallback to regular SCION connection if batch failed or not supported
	if !s.useBatch || s.batchConn == nil {
		conn, err := s.scionNetwork.Listen(context.Background(), "udp", s.localAddr)
		if err != nil {
			s.logger.Errorf("Failed to listen on SCION: %v", err)
			return nil, 0, fmt.Errorf("failed to listen on SCION: %w", err)
		}
		s.scionConn = conn
		actualPort = uint16(s.scionConn.LocalAddr().(*snet.UDPAddr).Host.Port)

		// Update cached connection data
		s.updateCachedConnData()

		fns = append(fns, s.makeReceiveSCION())
		s.logger.Verbosef("SCION listener started on port %d (non-batch)", actualPort)
	}

	if len(fns) == 0 {
		return nil, 0, fmt.Errorf("no listeners could be started")
	}

	return fns, actualPort, nil
}

func (s *ScionNetBind) makeReceiveSCION() ReceiveFunc {
	return func(bufs [][]byte, sizes []int, eps []Endpoint) (n int, err error) {
		s.mu.RLock()
		connData := *s.cachedConnData // Copy struct to minimize lock time
		s.mu.RUnlock()

		if connData.batchConn != nil {
			return connData.batchConn.ReadBatch(
				connData.ipv4PC, connData.ipv6PC, connData.scmpHandler,
				connData.ipv4RxOffload, connData.ipv6RxOffload,
				bufs, sizes, eps)
		}

		if connData.scionConn != nil {
			return s.receiveSCION(connData.scionConn, bufs, sizes, eps)
		}

		return 0, fmt.Errorf("no suitable transport for endpoint")
	}
}

func (s *ScionNetBind) receiveSCION(scionConn *snet.Conn, bufs [][]byte, sizes []int, eps []Endpoint) (n int, err error) {
	if scionConn == nil {
		return 0, net.ErrClosed
	}

	// Read packet from SCION connection
	buffer := bufs[0]
	readBytes, remote, err := scionConn.ReadFrom(buffer)
	if err != nil {
		s.logger.Errorf("Error reading from SCION connection: %v", err)
		return 0, err
	}

	sizes[0] = readBytes
	// Convert net.Addr to our endpoint type
	if scionAddr, ok := remote.(*snet.UDPAddr); ok {
		// Use optimized IP address conversion
		addr, err := convertIPToAddr(scionAddr.NextHop.IP)
		if err != nil {
			return 0, fmt.Errorf("invalid IP address in SCION NextHop: %w", err)
		}

		addrPort := netip.AddrPortFrom(addr, uint16(scionAddr.NextHop.Port))
		eps[0] = &ScionNetEndpoint{
			StdNetEndpoint: StdNetEndpoint{
				AddrPort: addrPort,
			},
			scionAddr: scionAddr,
		}
	} else {
		// Fallback if it's not a SCION address
		return 0, fmt.Errorf("unexpected address type: %T", remote)
	}

	return 1, nil
}

func (s *ScionNetBind) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var firstErr error

	if s.batchConn != nil {
		if err := s.batchConn.Close(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("batch conn close: %w", err)
		}
		s.batchConn = nil
	}

	if s.scionConn != nil {
		if err := s.scionConn.Close(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("scion conn close: %w", err)
		}
		s.scionConn = nil
	}

	if s.pathManager != nil {
		s.pathManager.Close()
		s.pathManager = nil
	}

	if s.daemonConn != nil {
		if err := s.daemonConn.Close(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("daemon conn close: %w", err)
		}
		s.daemonConn = nil
	}

	// Clear cached data
	s.cachedConnData = &connData{}

	return firstErr
}

func (s *ScionNetBind) SetMark(mark uint32) error {
	// SCION doesn't support SO_MARK directly
	return nil
}

func (s *ScionNetBind) Send(bufs [][]byte, ep Endpoint) error {
	scionEp, ok := ep.(*ScionNetEndpoint)
	if !ok {
		return ErrWrongEndpointType
	}

	s.mu.RLock()
	connData := *s.cachedConnData // Copy struct to minimize lock time
	s.mu.RUnlock()

	// Update path if path manager is available
	if connData.pathManager != nil {
		if p, err := connData.pathManager.GetPath(scionEp.scionAddr.IA); err == nil {
			scionEp.scionAddr.Path = p.Dataplane()
			scionEp.scionAddr.NextHop = p.UnderlayNextHop()
		}
	}

	// Use batch connection if available
	if connData.batchConn != nil && connData.useBatch {
		return connData.batchConn.WriteBatch(
			connData.ipv4PC, connData.ipv6PC,
			connData.ipv4TxOffload, connData.ipv6TxOffload,
			bufs, scionEp)
	}

	// Fallback to regular SCION connection
	if connData.scionConn != nil {
		return s.sendSCION(bufs, scionEp, connData.scionConn)
	}

	return fmt.Errorf("no suitable transport for endpoint")
}

func (s *ScionNetBind) sendSCION(bufs [][]byte, ep *ScionNetEndpoint, conn *snet.Conn) error {
	for _, buf := range bufs {
		_, err := conn.WriteTo(buf, ep.scionAddr)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *ScionNetBind) ParseEndpoint(str string) (Endpoint, error) {
	// Try parsing as SCION address first
	if strings.Contains(str, ",") {
		scionAddr, err := snet.ParseUDPAddr(str)
		if err != nil {
			return nil, fmt.Errorf("failed to parse SCION address %s: %w", str, err)
		}

		scionEndpoint := &ScionNetEndpoint{
			scionAddr: scionAddr,
		}

		s.mu.RLock()
		pathManager := s.cachedConnData.pathManager
		s.mu.RUnlock()

		if pathManager != nil {
			pathManager.RegisterEndpoint(scionAddr.IA)
			if p, err := pathManager.GetPath(scionAddr.IA); err == nil {
				scionAddr.Path = p.Dataplane()
				scionAddr.NextHop = p.UnderlayNextHop()

				// Use optimized IP address conversion
				addr, _ := convertIPToAddr(scionAddr.NextHop.IP)

				scionEndpoint.StdNetEndpoint.AddrPort = netip.AddrPortFrom(
					addr, uint16(scionAddr.NextHop.Port))
			} else {
				return nil, fmt.Errorf("failed to get path for IA %s: %w", scionAddr.IA, err)
			}
		}
		return scionEndpoint, nil
	}

	return nil, fmt.Errorf("invalid endpoint: %s", str)
}

func (s *ScionNetBind) BatchSize() int {
	s.mu.RLock()
	batchConn := s.cachedConnData.batchConn
	s.mu.RUnlock()

	if batchConn != nil {
		return batchConn.BatchSize()
	}
	return 1 // SCION typically processes one packet at a time
}

// Path management methods
func (s *ScionNetBind) SetPathPolicy(policy string) {
	s.mu.RLock()
	pathManager := s.cachedConnData.pathManager
	s.mu.RUnlock()

	if pathManager != nil {
		pathManager.SetPolicy(policy)
	}
}

func (e *ScionNetEndpoint) GetScionAddr() *snet.UDPAddr {
	return e.scionAddr
}

func (e *ScionNetEndpoint) SetScionAndIPAddresses(scionAddr *snet.UDPAddr) {
	e.scionAddr = scionAddr
	if scionAddr != nil && scionAddr.NextHop != nil {
		// Use optimized IP address conversion
		if addr, err := convertIPToAddr(scionAddr.NextHop.IP); err == nil {
			e.StdNetEndpoint.AddrPort = netip.AddrPortFrom(
				addr, uint16(scionAddr.NextHop.Port))
		}
	}
}

// convertIPToAddr efficiently converts net.IP to netip.Addr without string parsing
func convertIPToAddr(ip net.IP) (netip.Addr, error) {
	if ip4 := ip.To4(); ip4 != nil {
		return netip.AddrFrom4([4]byte{ip4[0], ip4[1], ip4[2], ip4[3]}), nil
	}
	if ip16 := ip.To16(); ip16 != nil {
		return netip.AddrFrom16([16]byte(ip16)), nil
	}
	return netip.Addr{}, fmt.Errorf("invalid IP address")
}

// GetPathsJSON returns a JSON string containing available paths for the given IA
func (bind *ScionNetBind) GetPathsJSON(iaStr string) (string, error) {
	bind.mu.RLock()
	pathManager := bind.cachedConnData.pathManager
	bind.mu.RUnlock()

	if pathManager == nil {
		return "", fmt.Errorf("path manager not initialized")
	}
	return pathManager.GetPathsJSON(iaStr)
}

// SetPath sets a specific path for a destination IA
func (bind *ScionNetBind) SetPath(iaStr string, pathIndex int) error {
	bind.mu.RLock()
	pathManager := bind.cachedConnData.pathManager
	bind.mu.RUnlock()

	if pathManager == nil {
		return fmt.Errorf("path manager not initialized")
	}
	return pathManager.SetPath(iaStr, pathIndex)
}

// GetPathPolicy returns the current path selection policy
func (bind *ScionNetBind) GetPathPolicy() string {
	bind.mu.RLock()
	pathManager := bind.cachedConnData.pathManager
	bind.mu.RUnlock()

	if pathManager == nil {
		return "unknown"
	}
	return pathManager.policy.String()
}
