package store

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

var (
	idMu   sync.Mutex
	idLast int64  // last millisecond used
	idSeq  uint16 // per-millisecond sequence (12 bits, UUIDv7 rand_a)
)

// NewID returns a UUIDv7 (time-ordered) as canonical text. Ids minted within
// the same millisecond are made monotonic through the 12-bit rand_a sequence
// (RFC 9562 §6.2, method 1) so "ORDER BY id" is a stable creation order.
func NewID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	ms := time.Now().UnixMilli()
	idMu.Lock()
	if ms <= idLast {
		ms = idLast
		idSeq++
		if idSeq >= 1<<12 { // sequence exhausted: borrow the next millisecond
			ms++
			idLast = ms
			idSeq = 0
		}
	} else {
		idLast = ms
		idSeq = uint16(b[6]&0x07)<<8 | uint16(b[7]) // random start, room to count up
	}
	seq := idSeq
	idMu.Unlock()
	u := uint64(ms)                                                                                              // #nosec G115 -- milliseconds since 1970 fit
	b[0], b[1], b[2], b[3], b[4], b[5] = byte(u>>40), byte(u>>32), byte(u>>24), byte(u>>16), byte(u>>8), byte(u) // #nosec G115 -- byte extraction of the 48-bit timestamp is the UUIDv7 layout
	b[6] = 0x70 | byte(seq>>8)&0x0f
	b[7] = byte(seq & 0xff) // #nosec G115 -- low byte of the 12-bit sequence
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}
