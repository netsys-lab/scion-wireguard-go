// SCION Utility Functions for WireGuard backend.
// Provides helper functions for SCION packet serialization and validation.

package conn

import (
	"encoding/binary"
	"fmt"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/snet"
)

const (
	// SCION protocol constants
	SCIONCommonHeaderLen = 12
	UDPHeaderLen         = 8
	SCIONLineLen         = 4
	MaxFlowID            = 0xfffff

	// Header field offsets
	PayloadLenOffset  = 6
	UDPLengthOffset   = 4
	UDPChecksumOffset = 6

	// Reserved field offsets in common header
	ReservedField1 = 10
	ReservedField2 = 11
)

// PacketValidationError represents validation errors during packet processing
type PacketValidationError struct {
	PacketIndex int
	Field       string
	Message     string
}

func (e *PacketValidationError) Error() string {
	if e.PacketIndex >= 0 {
		return fmt.Sprintf("packet %d validation error in %s: %s", e.PacketIndex, e.Field, e.Message)
	}
	return fmt.Sprintf("validation error in %s: %s", e.Field, e.Message)
}

// ensureCapacity validates that the buffer has sufficient capacity
func ensureCapacity(buf []byte, needed int, context string) error {
	if needed > cap(buf) {
		return fmt.Errorf("%s: insufficient buffer capacity: need %d bytes, have %d",
			context, needed, cap(buf))
	}
	return nil
}

// validatePacketForSerialization performs comprehensive packet validation
func validatePacketForSerialization(p *snet.Packet, index int) error {
	if p == nil {
		return &PacketValidationError{index, "packet", "packet is nil"}
	}

	if p.Path == nil {
		return &PacketValidationError{index, "path", "no path set"}
	}

	udpPayload, ok := p.Payload.(snet.UDPPayload)
	if !ok {
		return &PacketValidationError{index, "payload", "payload is not UDPPayload"}
	}

	if len(udpPayload.Payload) > 0xffff-UDPHeaderLen {
		return &PacketValidationError{index, "payload",
			fmt.Sprintf("payload too large: %d bytes (max %d)",
				len(udpPayload.Payload), 0xffff-UDPHeaderLen)}
	}

	return nil
}

// computeFlowID generates a proper flow ID (placeholder implementation)
func computeFlowID(p *snet.Packet) uint32 {
	// TODO: Implement proper flow ID calculation based on 5-tuple hash
	// For now, use a simple hash of source/destination ports
	udpPayload, ok := p.Payload.(snet.UDPPayload)
	if !ok {
		return 1
	}

	// Simple hash combining src and dst ports
	hash := uint32(udpPayload.SrcPort)<<16 | uint32(udpPayload.DstPort)
	return hash & MaxFlowID
}

// Serialize encodes PacketInfo into p.Bytes with improved error handling and validation.
//
// Fast path: no intermediate gopacket.SerializeBuffer allocations, no
// reflection, single pass copy and checksum.
//
// It supports UDP packets only. For SCMP or other L4 protocols, use
// alternative serialization methods.
//
// Preconditions:
//   - p.Prepare has been called (keeps existing scratch-buffer logic)
//   - p.Payload must be UDPPayload
//   - p.Path must not be nil (dataplane path present)
//
// Note: Checksum calculation is disabled for performance. If checksums are
// required, they must be computed separately.
func Serialize(p *snet.Packet) error {
	// Validate packet structure
	if err := validatePacketForSerialization(p, -1); err != nil {
		return err
	}

	// Keep the original semantics
	p.Prepare()

	udpPayload := p.Payload.(snet.UDPPayload) // Safe after validation

	// ---------- Build SCION header struct ----------
	var scion slayers.SCION
	scion.Version = 0
	scion.FlowID = computeFlowID(p)
	scion.DstIA = p.Destination.IA
	scion.SrcIA = p.Source.IA
	scion.NextHdr = slayers.L4UDP

	if err := scion.SetDstAddr(p.Destination.Host); err != nil {
		return fmt.Errorf("setting destination address: %w", err)
	}
	if err := scion.SetSrcAddr(p.Source.Host); err != nil {
		return fmt.Errorf("setting source address: %w", err)
	}
	if err := p.Path.SetPath(&scion); err != nil {
		return fmt.Errorf("setting path: %w", err)
	}

	// ---------- Length bookkeeping ----------
	udpLen := UDPHeaderLen + len(udpPayload.Payload)
	scion.PayloadLen = uint16(udpLen) // no extensions
	scHdrLen := slayers.CmnHdrLen + scion.AddrHdrLen() + scion.Path.Len()
	totalLen := scHdrLen + udpLen

	// Ensure buffer capacity
	if err := ensureCapacity(p.Bytes, totalLen, "packet serialization"); err != nil {
		return err
	}

	p.Bytes = p.Bytes[:totalLen]
	buf := p.Bytes // alias for convenience

	// ---------- Common header ----------
	firstLine := uint32(scion.Version&0xf)<<28 |
		uint32(scion.TrafficClass)<<20 | (scion.FlowID & MaxFlowID)
	binary.BigEndian.PutUint32(buf[0:4], firstLine)
	buf[4] = byte(scion.NextHdr)
	buf[5] = uint8(scHdrLen / SCIONLineLen)
	binary.BigEndian.PutUint16(buf[PayloadLenOffset:PayloadLenOffset+2], scion.PayloadLen)
	buf[8] = byte(scion.PathType)
	buf[9] = byte(scion.DstAddrType&0xf)<<4 | byte(scion.SrcAddrType&0xf)

	// Explicitly zero reserved fields
	buf[ReservedField1] = 0
	buf[ReservedField2] = 0

	// ---------- Address header ----------
	off := slayers.CmnHdrLen
	binary.BigEndian.PutUint64(buf[off:], uint64(scion.DstIA))
	off += addr.IABytes
	binary.BigEndian.PutUint64(buf[off:], uint64(scion.SrcIA))
	off += addr.IABytes
	copy(buf[off:], scion.RawDstAddr)
	off += len(scion.RawDstAddr)
	copy(buf[off:], scion.RawSrcAddr)
	off += len(scion.RawSrcAddr)

	// ---------- Path header ----------
	if err := scion.Path.SerializeTo(buf[off : off+scion.Path.Len()]); err != nil {
		return fmt.Errorf("serializing path: %w", err)
	}
	off += scion.Path.Len() // now off == scHdrLen

	// ---------- UDP header ----------
	binary.BigEndian.PutUint16(buf[off+0:], udpPayload.SrcPort)
	binary.BigEndian.PutUint16(buf[off+2:], udpPayload.DstPort)
	if udpLen > 0xffff {
		// jumbogram – encode 0 per RFC 2675 / SCION spec
		binary.BigEndian.PutUint16(buf[off+UDPLengthOffset:], 0)
	} else {
		binary.BigEndian.PutUint16(buf[off+UDPLengthOffset:], uint16(udpLen))
	}
	// clear checksum for now (checksum calculation disabled for performance)
	binary.BigEndian.PutUint16(buf[off+UDPChecksumOffset:], 0)

	// ---------- Payload ----------
	copy(buf[off+UDPHeaderLen:], udpPayload.Payload)

	// ---------- Checksum (disabled) ----------
	// Note: Checksum calculation is disabled for performance reasons.
	// If checksums are required, implement separately:
	// checksum, err := scion.computeChecksum(buf[off:off+udpLen], uint8(slayers.L4UDP))
	// if err != nil {
	// 	return fmt.Errorf("computing UDP checksum: %w", err)
	// }
	// binary.BigEndian.PutUint16(buf[off+UDPChecksumOffset:], checksum)

	return nil
}

// SerializeBatch efficiently serializes multiple packets using template optimization.
//
// This function assumes all packets have the same SCION header structure
// (same address types, path types, and path lengths). It serializes the first
// packet completely, then uses it as a template for subsequent packets,
// updating only the dynamic fields (payload length, UDP length, and payload data).
//
// Preconditions:
// - All packets must be valid for UDP serialization
// - All packets must have compatible SCION header structure
// - bufs slice must have same length as pkts slice
//
// Note: If any packet fails validation, the function returns immediately
// without modifying any packets (atomic operation).
func SerializeBatch(pkts []snet.Packet, bufs [][]byte) error {
	if len(pkts) == 0 {
		return nil
	}
	if len(pkts) != len(bufs) {
		return fmt.Errorf("packets and bufs length mismatch: %d != %d", len(pkts), len(bufs))
	}

	// Pre-validate all packets to ensure atomic operation
	for i := range pkts {
		if err := validatePacketForSerialization(&pkts[i], i); err != nil {
			return err
		}
	}

	// 1. Serialize the first packet completely to serve as a template
	firstPkt := &pkts[0]
	if err := Serialize(firstPkt); err != nil {
		return fmt.Errorf("failed to serialize template packet: %w", err)
	}
	bufs[0] = firstPkt.Bytes

	// Determine SCION header length from the first serialized packet
	firstUdpPayload := firstPkt.Payload.(snet.UDPPayload) // Safe after validation
	firstUdpLen := UDPHeaderLen + len(firstUdpPayload.Payload)
	scHdrLen := len(firstPkt.Bytes) - firstUdpLen

	// Sanity check the calculated header length
	if scHdrLen <= SCIONCommonHeaderLen || scHdrLen >= len(firstPkt.Bytes) {
		return fmt.Errorf("invalid SCION header length calculated: %d (total: %d, UDP: %d)",
			scHdrLen, len(firstPkt.Bytes), firstUdpLen)
	}

	// Cache the SCION header and UDP header templates from the first packet
	scionHeaderTemplate := firstPkt.Bytes[0:scHdrLen]
	udpHeaderTemplate := firstPkt.Bytes[scHdrLen : scHdrLen+UDPHeaderLen]

	// 2. Serialize subsequent packets using the header template
	for i := 1; i < len(pkts); i++ {
		p := &pkts[i] // Work with a pointer to modify pkts[i].Bytes

		currentUdpPayload := p.Payload.(snet.UDPPayload) // Safe after validation
		currentUdpLen := UDPHeaderLen + len(currentUdpPayload.Payload)
		totalLen := scHdrLen + currentUdpLen

		// Ensure buffer capacity
		if err := ensureCapacity(p.Bytes, totalLen, fmt.Sprintf("packet %d", i)); err != nil {
			return err
		}
		p.Bytes = p.Bytes[:totalLen]

		// Copy the SCION header template
		copy(p.Bytes[0:scHdrLen], scionHeaderTemplate)

		// Update SCION common header's PayloadLen field
		binary.BigEndian.PutUint16(p.Bytes[PayloadLenOffset:PayloadLenOffset+2], uint16(currentUdpLen))

		// Copy the UDP header template (contains src/dst ports and zeroed checksum)
		copy(p.Bytes[scHdrLen:scHdrLen+UDPHeaderLen], udpHeaderTemplate)

		// Update UDP header's Length field
		udpLenOffset := scHdrLen + UDPLengthOffset
		if currentUdpLen > 0xffff { // Jumbogram case
			binary.BigEndian.PutUint16(p.Bytes[udpLenOffset:udpLenOffset+2], 0)
		} else {
			binary.BigEndian.PutUint16(p.Bytes[udpLenOffset:udpLenOffset+2], uint16(currentUdpLen))
		}

		// Copy the actual UDP payload for the current packet
		copy(p.Bytes[scHdrLen+UDPHeaderLen:], currentUdpPayload.Payload)

		// Note: If checksums were being calculated, they would be computed here
		// based on the new payload content.

		bufs[i] = p.Bytes
	}
	return nil
}

// SerializeBatchWithChecksums is a variant that computes UDP checksums
// Currently placeholder - implement if checksums are required
func SerializeBatchWithChecksums(pkts []snet.Packet, bufs [][]byte) error {
	// TODO: Implement checksum calculation for batch operations
	// This would follow the same pattern as SerializeBatch but compute
	// checksums for each packet after payload copying
	return fmt.Errorf("checksum calculation not yet implemented")
}
