package conn

import (
	"time"

	snetpath "github.com/scionproto/scion/pkg/snet/path"
)

func reservationExpirationTime(r *snetpath.Reservation) (time.Time, bool) {
	if r == nil {
		return time.Time{}, false
	}
	var earliest time.Time
	for _, hop := range r.Hops {
		if hop == nil || hop.Flyover == nil {
			continue
		}
		expiresAt := time.Unix(int64(hop.Flyover.StartTime)+int64(hop.Flyover.Duration), 0)
		if earliest.IsZero() || expiresAt.Before(earliest) {
			earliest = expiresAt
		}
	}
	if earliest.IsZero() {
		return time.Time{}, false
	}
	return earliest, true
}

func reservationRenewalDelay(forwardRes *snetpath.Reservation, renewBeforeSec uint16, durationSec uint16) time.Duration {
	fallback := time.Duration(durationSec) * time.Second
	if fallback <= 0 {
		fallback = 5 * time.Second
	}
	target := fallback - time.Duration(renewBeforeSec)*time.Second
	if target <= 0 {
		target = time.Second
	}
	if forwardRes == nil {
		return target
	}
	expiresAt, ok := reservationExpirationTime(forwardRes)
	if !ok {
		return target
	}
	untilRenew := time.Until(expiresAt.Add(-time.Duration(renewBeforeSec) * time.Second))
	if untilRenew < time.Second {
		return time.Second
	}
	return untilRenew
}

// This is workaround of the issue "all bits used, no free color found"
// After it's fixed, this function can be replaced with:
//
//	startTime := uint32(time.Now().Unix())
//
// With this change, switchAt also becomes obsolete.
func renewalRequestStartTimeUnix(forwardRes *snetpath.Reservation) uint32 {
	now := uint32(time.Now().Unix())
	if forwardRes == nil {
		return now
	}
	expiresAt, ok := reservationExpirationTime(forwardRes)
	if !ok {
		return now
	}
	expiration := uint32(expiresAt.Unix())
	if expiration < now {
		return now
	}
	return expiration
}
