package gateway

import (
	"bytes"
	"errors"
	"io"
	"sync"
)

const inspectionBudget = 256 << 20

var errInspectionCapacity = errors.New("inspection memory is exhausted")
var errBodyTooLarge = errors.New("request body is too large")
var errUpgradeCapacity = errors.New("upgrade capacity is exhausted")

// Reservations cover payload buffers and their temporary copies, not total RSS.
// Growth is charged before allocation, including overlap with the old buffer.
type inspectionReservation struct {
	app   *App
	bytes int64
}

func (r *inspectionReservation) acquire(n int64) bool {
	if n == 0 {
		return true
	}
	if !r.app.bodyMemory.TryAcquire(n) {
		return false
	}
	r.bytes += n
	r.app.inspectionBytes.Add(n)
	return true
}
func (r *inspectionReservation) release() {
	if r.bytes != 0 {
		r.app.bodyMemory.Release(r.bytes)
		r.app.inspectionBytes.Add(-r.bytes)
		r.bytes = 0
	}
}
func (r *inspectionReservation) readBody(src io.Reader, limit int64) ([]byte, error) {
	var body []byte
	var chunk [32 << 10]byte
	for {
		remaining := limit + 1 - int64(len(body))
		n, err := src.Read(chunk[:min(int64(len(chunk)), remaining)])
		if n > 0 {
			needed := len(body) + n
			if int64(needed) > limit {
				return nil, errBodyTooLarge
			}
			if needed > cap(body) {
				capacity := min(limit, max(int64(needed), int64(cap(body))*2))
				// Six copies conservatively cover buffer growth, Coraza and custom rules.
				if !r.acquire(6 * (capacity - int64(cap(body)))) {
					return nil, errInspectionCapacity
				}
				next := make([]byte, len(body), int(capacity))
				copy(next, body)
				body = next
			}
			body = append(body, chunk[:n]...)
		}
		if err == io.EOF {
			return body, nil
		}
		if err != nil {
			return nil, err
		}
	}
}

// The transport may close a request body asynchronously. Clearing it under a
// lock lets upgraded connections release payload references safely.
type inspectionBody struct {
	mu     sync.Mutex
	reader *bytes.Reader
}

func (b *inspectionBody) Read(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.reader == nil {
		return 0, io.EOF
	}
	return b.reader.Read(p)
}
func (b *inspectionBody) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.reader = nil
	return nil
}
