// SCION Batch Connection for WireGuard backend.
// Provides batch send/receive capabilities for SCION packets.
// Uses UDP batching for performance.

package conn

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/common"
	"github.com/scionproto/scion/pkg/snet"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	// Maximum number of retry attempts for GSO operations
	maxGSORetries = 1
)

var (
	ErrInvalidEndpointType = errors.New("invalid endpoint type, expected *ScionNetEndpoint")
	ErrInvalidAddressType  = errors.New("invalid address type, expected *net.UDPAddr")
	ErrConnectionClosed    = errors.New("connection is closed")
	ErrPacketDecode        = errors.New("failed to decode SCION packet")
	ErrNoUDPPayload        = errors.New("packet does not contain UDP payload")
	ErrNoRawPath           = errors.New("packet does not contain raw path")
)

// ScionBatchConn provides batch send/receive capabilities for SCION packets
type ScionBatchConn struct {
	mu          sync.RWMutex
	conn        *net.UDPConn
	ipv4PC      *ipv4.PacketConn
	ipv6PC      *ipv6.PacketConn
	localIA     addr.IA
	localAddr   *net.UDPAddr
	topology    snet.Topology
	pathManager *PathManager
	scmpHandler snet.SCMPHandler
	replyPather snet.ReplyPather
	logger      Logger
	closed      bool

	// Offloads
	ipv4TxOffload bool
	ipv4RxOffload bool
	ipv6TxOffload bool
	ipv6RxOffload bool

	// Object pools for memory optimization
	pools poolManager

	// Capabilities
	batchSize     int
	fastSerialize bool
}

type poolManager struct {
	msgs           sync.Pool
	scionPkt       sync.Pool
	scionEmptyPkt  sync.Pool
	scionSinglePkt sync.Pool
	udpAddr        sync.Pool
}

// ScionBatchConnConfig holds configuration options for ScionBatchConn
type ScionBatchConnConfig struct {
	// EnableIPv4RxOffload enables IPv4 receive offloading (default: false)
	EnableIPv4RxOffload bool
	// EnableIPv6RxOffload enables IPv6 receive offloading (default: false)
	EnableIPv6RxOffload bool
	// EnableIPv4TxOffload enables IPv4 transmit offloading (default: true)
	EnableIPv4TxOffload bool
	// EnableIPv6TxOffload enables IPv6 transmit offloading (default: true)
	EnableIPv6TxOffload bool
}

func NewScionBatchConn(
	conn *net.UDPConn,
	localIA addr.IA,
	topology snet.Topology,
	pathManager *PathManager,
	logger Logger,
) *ScionBatchConn {
	return NewScionBatchConnWithConfig(conn, localIA, topology, pathManager, logger, ScionBatchConnConfig{
		EnableIPv4TxOffload: false,
		EnableIPv6TxOffload: false,
		EnableIPv4RxOffload: false, // Disabled by default due to stability concerns
		EnableIPv6RxOffload: false, // Disabled by default due to stability concerns
	})
}

func NewScionBatchConnWithConfig(
	conn *net.UDPConn,
	localIA addr.IA,
	topology snet.Topology,
	pathManager *PathManager,
	logger Logger,
	config ScionBatchConnConfig,
) *ScionBatchConn {
	localAddr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		logger.Errorf("Invalid local address type: %T", conn.LocalAddr())
		return nil
	}

	sbc := &ScionBatchConn{
		conn:        conn,
		localIA:     localIA,
		localAddr:   localAddr,
		topology:    topology,
		pathManager: pathManager,
		logger:      logger,
		replyPather: snet.DefaultReplyPather{},
		batchSize:   1,
	}

	sbc.initializePools()
	sbc.configureNetworking(config)

	logger.Verbosef("Created ScionBatchConn with batch size %d, IPv4 TX/RX offload: %v/%v, IPv6 TX/RX offload: %v/%v",
		sbc.batchSize, sbc.ipv4TxOffload, sbc.ipv4RxOffload, sbc.ipv6TxOffload, sbc.ipv6RxOffload)

	return sbc
}

func (s *ScionBatchConn) initializePools() {
	s.pools.msgs = sync.Pool{
		New: func() any {
			msgs := make([]ipv6.Message, IdealBatchSize)
			for i := range msgs {
				msgs[i].Buffers = make(net.Buffers, 1)
				msgs[i].OOB = make([]byte, 0, stickyControlSize+gsoControlSize)
			}
			return &msgs
		},
	}

	s.pools.scionPkt = sync.Pool{
		New: func() any {
			scionPkts := make([]snet.Packet, IdealBatchSize)
			for i := range scionPkts {
				scionPkts[i].Bytes = make(snet.Bytes, common.SupportedMTU)
			}
			return &scionPkts
		},
	}

	s.pools.scionEmptyPkt = sync.Pool{
		New: func() any {
			scionPkts := make([]snet.Packet, IdealBatchSize)
			return &scionPkts
		},
	}

	s.pools.scionSinglePkt = sync.Pool{
		New: func() any {
			return &snet.Packet{}
		},
	}

	s.pools.udpAddr = sync.Pool{
		New: func() any {
			return &net.UDPAddr{
				IP: make([]byte, 16),
			}
		},
	}
}

func (s *ScionBatchConn) configureNetworking(config ScionBatchConnConfig) {
	if s.localAddr.IP.To4() != nil {
		s.configureIPv4(config)
	} else {
		s.configureIPv6(config)
	}

	if s.ipv4TxOffload || s.ipv6TxOffload {
		s.fastSerialize = true
	}
	s.fastSerialize = true
}

func (s *ScionBatchConn) configureIPv4(config ScionBatchConnConfig) {
	s.ipv4PC = ipv4.NewPacketConn(s.conn)
	if config.EnableIPv4TxOffload || config.EnableIPv4RxOffload {
		txOffload, rxOffload := supportsUDPOffload(s.conn)
		s.ipv4TxOffload = config.EnableIPv4TxOffload && txOffload
		s.ipv4RxOffload = config.EnableIPv4RxOffload && rxOffload
	}
	s.batchSize = IdealBatchSize
}

func (s *ScionBatchConn) configureIPv6(config ScionBatchConnConfig) {
	s.ipv6PC = ipv6.NewPacketConn(s.conn)
	if config.EnableIPv6TxOffload || config.EnableIPv6RxOffload {
		txOffload, rxOffload := supportsUDPOffload(s.conn)
		s.ipv6TxOffload = config.EnableIPv6TxOffload && txOffload
		s.ipv6RxOffload = config.EnableIPv6RxOffload && rxOffload
	}
	s.batchSize = IdealBatchSize
}

func (s *ScionBatchConn) getMessages() *[]ipv6.Message {
	return s.pools.msgs.Get().(*[]ipv6.Message)
}

func (s *ScionBatchConn) putMessages(msgs *[]ipv6.Message) {
	for i := range *msgs {
		(*msgs)[i].OOB = (*msgs)[i].OOB[:0]
		(*msgs)[i] = ipv6.Message{Buffers: (*msgs)[i].Buffers, OOB: (*msgs)[i].OOB}
	}
	s.pools.msgs.Put(msgs)
}

func (s *ScionBatchConn) getScionPkts() *[]snet.Packet {
	return s.pools.scionPkt.Get().(*[]snet.Packet)
}

func (s *ScionBatchConn) putScionPkts(pkts *[]snet.Packet) {
	for i := range *pkts {
		(*pkts)[i] = snet.Packet{
			Bytes: (*pkts)[i].Bytes,
		}
	}
	s.pools.scionPkt.Put(pkts)
}

func (s *ScionBatchConn) getScionEmptyPkts() *[]snet.Packet {
	return s.pools.scionEmptyPkt.Get().(*[]snet.Packet)
}

func (s *ScionBatchConn) putScionEmptyPkts(pkts *[]snet.Packet) {
	s.pools.scionEmptyPkt.Put(pkts)
}

func (s *ScionBatchConn) getUDPAddr() *net.UDPAddr {
	return s.pools.udpAddr.Get().(*net.UDPAddr)
}

func (s *ScionBatchConn) putUDPAddr(addr *net.UDPAddr) {
	s.pools.udpAddr.Put(addr)
}

func (s *ScionBatchConn) SetSCMPHandler(handler snet.SCMPHandler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.scmpHandler = handler
}

func (s *ScionBatchConn) LocalAddr() net.Addr {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.localAddr
}

func (s *ScionBatchConn) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}
	s.closed = true

	return s.closeConnections()
}

func (s *ScionBatchConn) closeConnections() error {
	var err error
	if s.conn != nil {
		err = s.conn.Close()
		s.resetConnections()
	}
	return err
}

func (s *ScionBatchConn) resetConnections() {
	s.conn = nil
	s.ipv4PC = nil
	s.ipv6PC = nil
	s.ipv4TxOffload = false
	s.ipv4RxOffload = false
	s.ipv6TxOffload = false
	s.ipv6RxOffload = false
	s.fastSerialize = false
}

func (s *ScionBatchConn) BatchSize() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.batchSize
}

func (s *ScionBatchConn) ReadBatch(
	ipv4PC *ipv4.PacketConn,
	ipv6PC *ipv6.PacketConn,
	scmpHandler snet.SCMPHandler,
	ipv4RxOffload bool,
	ipv6RxOffload bool,
	bufs [][]byte,
	sizes []int,
	eps []Endpoint,
) (int, error) {
	msgs := s.getMessages()
	defer s.putMessages(msgs)

	numMsgs, err := s.readMessages(msgs, ipv4PC, ipv6PC, ipv4RxOffload, ipv6RxOffload, bufs)
	if err != nil {
		return 0, err
	}

	return s.processMessages(msgs, numMsgs, scmpHandler, bufs, sizes, eps)
}

func (s *ScionBatchConn) readMessages(
	msgs *[]ipv6.Message,
	ipv4PC *ipv4.PacketConn,
	ipv6PC *ipv6.PacketConn,
	ipv4RxOffload, ipv6RxOffload bool,
	bufs [][]byte,
) (int, error) {
	for i := range bufs {
		(*msgs)[i].Buffers[0] = bufs[i]
		(*msgs)[i].OOB = (*msgs)[i].OOB[:cap((*msgs)[i].OOB)]
	}

	if ipv4PC != nil {
		return s.readIPv4Messages(msgs, ipv4PC, ipv4RxOffload)
	}
	return s.readIPv6Messages(msgs, ipv6PC, ipv6RxOffload)
}

func (s *ScionBatchConn) readIPv4Messages(msgs *[]ipv6.Message, ipv4PC *ipv4.PacketConn, rxOffload bool) (int, error) {
	if rxOffload {
		return s.readWithOffload(msgs, func(m []ipv6.Message) (int, error) {
			_, err := ipv4PC.ReadBatch(m, 0)
			return 0, err
		}, "IPv4")
	}

	numMsgs, err := ipv4PC.ReadBatch(*msgs, 0)
	if err != nil {
		return 0, fmt.Errorf("IPv4 batch read failed: %w", err)
	}
	return numMsgs, nil
}

func (s *ScionBatchConn) readIPv6Messages(msgs *[]ipv6.Message, ipv6PC *ipv6.PacketConn, rxOffload bool) (int, error) {
	if rxOffload {
		return s.readWithOffload(msgs, func(m []ipv6.Message) (int, error) {
			_, err := ipv6PC.ReadBatch(m, 0)
			return 0, err
		}, "IPv6")
	}

	numMsgs, err := ipv6PC.ReadBatch(*msgs, 0)
	if err != nil {
		return 0, fmt.Errorf("IPv6 batch read failed: %w", err)
	}
	return numMsgs, nil
}

func (s *ScionBatchConn) readWithOffload(
	msgs *[]ipv6.Message,
	readFunc func([]ipv6.Message) (int, error),
	protocol string,
) (int, error) {
	readAt := len(*msgs) - (IdealBatchSize / udpSegmentMaxDatagrams)
	if readAt < 0 {
		readAt = 0
	}

	if _, err := readFunc((*msgs)[readAt:]); err != nil {
		return 0, fmt.Errorf("%s batch read failed: %w", protocol, err)
	}

	numMsgs, err := splitCoalescedMessages(*msgs, readAt, getGSOSize)
	if err != nil {
		return 0, fmt.Errorf("failed to split coalesced messages: %w", err)
	}
	return numMsgs, nil
}

func (s *ScionBatchConn) processMessages(
	msgs *[]ipv6.Message,
	numMsgs int,
	scmpHandler snet.SCMPHandler,
	bufs [][]byte,
	sizes []int,
	eps []Endpoint,
) (int, error) {
	scionPkts := s.getScionEmptyPkts()
	defer s.putScionEmptyPkts(scionPkts)

	processedCount := 0
	for i := 0; i < numMsgs; i++ {
		if s.processMessage(&(*msgs)[i], &(*scionPkts)[i], scmpHandler, bufs[i], &sizes[i], &eps[i]) {
			processedCount++
		}
	}
	return processedCount, nil
}

func (s *ScionBatchConn) processMessage(
	msg *ipv6.Message,
	scionPkt *snet.Packet,
	scmpHandler snet.SCMPHandler,
	buf []byte,
	size *int,
	ep *Endpoint,
) bool {
	if msg.N == 0 {
		*size = 0
		return false
	}

	scionPkt.Bytes = msg.Buffers[0][:msg.N]
	if err := scionPkt.Decode(); err != nil {
		s.logger.Verbosef("Failed to decode SCION packet: %v", err)
		return false
	}

	if s.handleSCMPPacket(scionPkt, scmpHandler) {
		return false
	}

	udp, ok := scionPkt.Payload.(snet.UDPPayload)
	if !ok {
		s.logger.Verbosef("Packet does not contain UDP payload")
		return false
	}

	if !s.createEndpoint(scionPkt, &udp, msg, ep) {
		return false
	}

	return s.copyPayload(&udp, buf, size)
}

func (s *ScionBatchConn) handleSCMPPacket(scionPkt *snet.Packet, scmpHandler snet.SCMPHandler) bool {
	if _, ok := scionPkt.Payload.(snet.SCMPPayload); ok {
		if scmpHandler != nil {
			if err := scmpHandler.Handle(scionPkt); err != nil {
				s.logger.Verbosef("SCMP handler error: %v", err)
			}
		}
		return true
	}
	return false
}

func (s *ScionBatchConn) createEndpoint(scionPkt *snet.Packet, udp *snet.UDPPayload,
	msg *ipv6.Message, ep *Endpoint) bool {
	rpath, ok := scionPkt.Path.(snet.RawPath)
	if !ok {
		s.logger.Verbosef("Packet does not contain raw path")
		return false
	}

	replyPath, err := s.replyPather.ReplyPath(rpath)
	if err != nil {
		s.logger.Verbosef("Failed to create reply path: %v", err)
		return false
	}

	nextHop, ok := msg.Addr.(*net.UDPAddr)
	if !ok {
		s.logger.Verbosef("Invalid address type in message: %T", msg.Addr)
		return false
	}

	scionAddr := &snet.UDPAddr{
		IA: scionPkt.Source.IA,
		Host: &net.UDPAddr{
			IP:   scionPkt.Source.Host.IP().AsSlice(),
			Port: int(udp.SrcPort),
		},
		Path:    replyPath,
		NextHop: nextHop,
	}

	addr, err := convertIPToAddr(scionAddr.NextHop.IP)
	if err != nil {
		s.logger.Verbosef("Failed to convert IP address: %v", err)
		return false
	}
	addrPort := netip.AddrPortFrom(addr, uint16(scionAddr.NextHop.Port))

	*ep = &ScionNetEndpoint{
		StdNetEndpoint: StdNetEndpoint{
			AddrPort: addrPort,
		},
		scionAddr: scionAddr,
	}

	if scionEp, ok := (*ep).(*ScionNetEndpoint); ok {
		getSrcFromControl(msg.OOB[:msg.NN], &scionEp.StdNetEndpoint)
	}

	return true
}

func (s *ScionBatchConn) copyPayload(udp *snet.UDPPayload, buf []byte, size *int) bool {
	payloadLen := len(udp.Payload)
	if payloadLen > len(buf) {
		s.logger.Verbosef("UDP payload too large (%d bytes) for buffer (%d bytes)", payloadLen, len(buf))
		return false
	}

	*size = payloadLen
	copy(buf, udp.Payload)
	return true
}

func (s *ScionBatchConn) WriteBatch(
	ipv4PC *ipv4.PacketConn,
	ipv6PC *ipv6.PacketConn,
	ipv4TxOffload bool,
	ipv6TxOffload bool,
	bufs [][]byte,
	endpoint Endpoint,
) error {
	if len(bufs) == 0 {
		return nil
	}

	scionEp, ok := endpoint.(*ScionNetEndpoint)
	if !ok {
		return ErrInvalidEndpointType
	}

	msgs := s.getMessages()
	defer s.putMessages(msgs)

	scionPkts := s.getScionPkts()
	defer s.putScionPkts(scionPkts)

	ua := s.getUDPAddr()
	defer s.putUDPAddr(ua)

	sbufs, err := s.prepareSCIONPackets(scionPkts, scionEp, bufs, ua, ipv4PC != nil)
	if err != nil {
		return err
	}

	return s.sendBatchWithRetry(ipv4PC, ipv6PC, ipv4TxOffload, ipv6TxOffload, msgs, sbufs, ua, scionEp, bufs)
}

func (s *ScionBatchConn) prepareSCIONPackets(
	scionPkts *[]snet.Packet,
	scionEp *ScionNetEndpoint,
	bufs [][]byte,
	ua *net.UDPAddr,
	isIPv4 bool,
) ([][]byte, error) {
	destination := snet.SCIONAddress{
		IA:   scionEp.scionAddr.IA,
		Host: addr.HostIP(netip.MustParseAddr(scionEp.scionAddr.Host.IP.String())),
	}
	source := snet.SCIONAddress{
		IA:   s.localIA,
		Host: addr.HostIP(netip.MustParseAddr(s.localAddr.IP.String())),
	}

	path := scionEp.scionAddr.Path
	srcPort := uint16(s.localAddr.Port)
	dstPort := uint16(scionEp.scionAddr.Host.Port)

	s.prepareUDPAddress(ua, scionEp, isIPv4)

	sbufs := make([][]byte, len(bufs))
	for i, buf := range bufs {
		(*scionPkts)[i].PacketInfo.Destination = destination
		(*scionPkts)[i].PacketInfo.Source = source
		(*scionPkts)[i].PacketInfo.Path = path
		(*scionPkts)[i].PacketInfo.Payload = snet.UDPPayload{
			SrcPort: srcPort,
			DstPort: dstPort,
			Payload: buf,
		}
	}

	if s.fastSerialize {
		if err := SerializeBatch((*scionPkts)[:len(bufs)], sbufs); err != nil {
			return nil, fmt.Errorf("failed to serialize SCION packets: %w", err)
		}
	} else {
		for i := range bufs {
			if err := (*scionPkts)[i].Serialize(); err != nil {
				return nil, fmt.Errorf("failed to serialize SCION packet %d: %w", i, err)
			}
			sbufs[i] = (*scionPkts)[i].Bytes
		}
	}

	return sbufs, nil
}

func (s *ScionBatchConn) prepareUDPAddress(ua *net.UDPAddr, scionEp *ScionNetEndpoint, isIPv4 bool) {
	dstIP := scionEp.StdNetEndpoint.DstIP()

	// Check if IP is zero value to prevent panic
	if dstIP == (netip.Addr{}) {
		// Fallback to using the SCION address NextHop IP
		if scionEp.scionAddr != nil && scionEp.scionAddr.NextHop != nil {
			ua.IP = scionEp.scionAddr.NextHop.IP
		} else {
			// Last resort: use local address IP
			ua.IP = s.localAddr.IP
		}
	} else if isIPv4 {
		as4 := dstIP.As4()
		copy(ua.IP, as4[:])
		ua.IP = ua.IP[:4]
	} else {
		as16 := dstIP.As16()
		copy(ua.IP, as16[:])
		ua.IP = ua.IP[:16]
	}
	ua.Port = int(scionEp.StdNetEndpoint.Port())
}

func (s *ScionBatchConn) sendBatchWithRetry(
	ipv4PC *ipv4.PacketConn,
	ipv6PC *ipv6.PacketConn,
	ipv4TxOffload, ipv6TxOffload bool,
	msgs *[]ipv6.Message,
	sbufs [][]byte,
	ua *net.UDPAddr,
	scionEp *ScionNetEndpoint,
	bufs [][]byte,
) error {
	for retryCount := 0; retryCount <= maxGSORetries; retryCount++ {
		err := s.sendBatch(ipv4PC, ipv6PC, ipv4TxOffload, ipv6TxOffload, msgs, sbufs, ua, scionEp, bufs)
		if err == nil {
			return nil
		}

		if !s.handleGSOError(err, ipv4PC != nil, &ipv4TxOffload, &ipv6TxOffload) {
			return fmt.Errorf("batch write failed after %d retries: %w", retryCount, err)
		}
	}

	return fmt.Errorf("batch write failed after %d retries: GSO retry limit exceeded", maxGSORetries)
}

func (s *ScionBatchConn) sendBatch(
	ipv4PC *ipv4.PacketConn,
	ipv6PC *ipv6.PacketConn,
	ipv4TxOffload, ipv6TxOffload bool,
	msgs *[]ipv6.Message,
	sbufs [][]byte,
	ua *net.UDPAddr,
	scionEp *ScionNetEndpoint,
	bufs [][]byte,
) error {
	if ipv4PC != nil {
		return s.sendIPv4Batch(ipv4PC, ipv4TxOffload, msgs, sbufs, ua, scionEp, bufs)
	}
	return s.sendIPv6Batch(ipv6PC, ipv6TxOffload, msgs, sbufs, ua, scionEp, bufs)
}

func (s *ScionBatchConn) sendIPv4Batch(
	ipv4PC *ipv4.PacketConn,
	txOffload bool,
	msgs *[]ipv6.Message,
	sbufs [][]byte,
	ua *net.UDPAddr,
	scionEp *ScionNetEndpoint,
	bufs [][]byte,
) error {
	if txOffload {
		n := coalesceMessages(ua, &scionEp.StdNetEndpoint, sbufs, *msgs, setGSOSize)
		return s.sendv4(ipv4PC, (*msgs)[:n])
	}

	for i := range bufs {
		(*msgs)[i].Buffers[0] = sbufs[i]
		(*msgs)[i].Addr = ua
		setSrcControl(&(*msgs)[i].OOB, &scionEp.StdNetEndpoint)
	}
	return s.sendv4(ipv4PC, (*msgs)[:len(bufs)])
}

func (s *ScionBatchConn) sendIPv6Batch(
	ipv6PC *ipv6.PacketConn,
	txOffload bool,
	msgs *[]ipv6.Message,
	sbufs [][]byte,
	ua *net.UDPAddr,
	scionEp *ScionNetEndpoint,
	bufs [][]byte,
) error {
	if txOffload {
		n := coalesceMessages(ua, &scionEp.StdNetEndpoint, sbufs, *msgs, setGSOSize)
		return s.sendv6(ipv6PC, (*msgs)[:n])
	}

	for i := range bufs {
		(*msgs)[i].Buffers[0] = sbufs[i]
		(*msgs)[i].Addr = ua
		setSrcControl(&(*msgs)[i].OOB, &scionEp.StdNetEndpoint)
	}
	return s.sendv6(ipv6PC, (*msgs)[:len(bufs)])
}

func (s *ScionBatchConn) handleGSOError(err error, isIPv4 bool, ipv4TxOffload, ipv6TxOffload *bool) bool {
	if !errShouldDisableUDPGSO(err) {
		return false
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if isIPv4 {
		s.logger.Verbosef("Disabling IPv4 GSO due to error: %v", err)
		s.ipv4TxOffload = false
		*ipv4TxOffload = false
	} else {
		s.logger.Verbosef("Disabling IPv6 GSO due to error: %v", err)
		s.ipv6TxOffload = false
		*ipv6TxOffload = false
	}
	return true
}

func (s *ScionBatchConn) sendv4(pc *ipv4.PacketConn, msgs []ipv6.Message) error {
	return s.sendBatchMessages(func(m []ipv6.Message) (int, error) {
		return pc.WriteBatch(m, 0)
	}, msgs)
}

func (s *ScionBatchConn) sendv6(pc *ipv6.PacketConn, msgs []ipv6.Message) error {
	return s.sendBatchMessages(func(m []ipv6.Message) (int, error) {
		return pc.WriteBatch(m, 0)
	}, msgs)
}

func (s *ScionBatchConn) sendBatchMessages(writeBatch func([]ipv6.Message) (int, error), msgs []ipv6.Message) error {
	for start := 0; start < len(msgs); {
		n, err := writeBatch(msgs[start:])
		if err != nil {
			return err
		}
		start += n
	}
	return nil
}
