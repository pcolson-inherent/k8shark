//go:build linux

package ebpf

import (
	"bytes"
	"encoding/binary"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

type drainStep struct {
	record TLSRecord
	before func()
}

// Scripted kernel records exercise the real decoder/drain/Close lifecycle
// without loading a BPF program or requiring kernel privileges.
type scriptedRingReader struct {
	steps  []drainStep
	next   int
	closed chan struct{}
	closes atomic.Int32
	once   sync.Once
}

func (r *scriptedRingReader) Read() (ringbuf.Record, error) {
	select {
	case <-r.closed:
		return ringbuf.Record{}, ringbuf.ErrClosed
	default:
	}
	if r.next == len(r.steps) {
		return ringbuf.Record{}, ringbuf.ErrClosed
	}
	step := r.steps[r.next]
	r.next++
	if step.before != nil {
		step.before()
	}
	ev := step.record
	raw := make([]byte, eventOffData+len(ev.Data))
	binary.LittleEndian.PutUint32(raw[eventOffPID:], ev.PID)
	binary.LittleEndian.PutUint64(raw[eventOffSSLCtx:], ev.ConnID)
	n := uint32(len(ev.Data))
	if ev.Lagged {
		n |= eventFlagLagged
	}
	binary.LittleEndian.PutUint32(raw[eventOffDataLen:], n)
	raw[eventOffDirection] = byte(ev.Direction)
	copy(raw[eventOffData:], ev.Data)
	return ringbuf.Record{RawSample: raw}, nil
}

func (r *scriptedRingReader) Close() error {
	r.closes.Add(1)
	r.once.Do(func() { close(r.closed) })
	return nil
}

func waitDrainTest(t *testing.T, done <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s (possible Close/drain WaitGroup deadlock)", what)
	}
}

func TestDrainBackpressurePreservesQueuedPrefixesOnClose(t *testing.T) {
	for _, marker := range []bool{false, true} {
		name := "oldest_data"
		if marker {
			name = "oldest_tombstone"
		}
		t.Run(name, func(t *testing.T) {
			first := TLSRecord{PID: 17, ConnID: 42, Data: []byte("K first chunk")}
			second := TLSRecord{PID: 17, ConnID: 42, Data: []byte("K second chunk")}
			if marker {
				first.Data, first.Lagged = nil, true
				second = TLSRecord{PID: 17, ConnID: 99, Data: []byte("other prefix")}
			}
			rd := &scriptedRingReader{closed: make(chan struct{}), steps: []drainStep{
				{record: first}, {record: second},
				{record: TLSRecord{PID: 17, ConnID: 100, Data: []byte("drop newest")}},
			}}
			s := &linuxSource{
				cfg: Config{Log: slog.New(slog.NewTextHandler(discard{}, nil))},
				rd:  rd, out: make(chan TLSRecord, 2), stop: make(chan struct{}),
			}
			drained := make(chan struct{})
			s.wg.Add(1)
			go func() { s.drainLoop(); close(drained) }()
			waitDrainTest(t, drained, "drainLoop")
			closed := make(chan struct{})
			go func() { _ = s.Close(); close(closed) }()
			waitDrainTest(t, closed, "source cleanup")
			var got []TLSRecord
			for ev := range s.Records() {
				got = append(got, ev)
			}
			want := []TLSRecord{first, second}
			if len(got) != len(want) {
				t.Fatalf("queued prefix changed length: got %+v, want %+v", got, want)
			}
			for i := range want {
				if got[i].ConnectionKey() != want[i].ConnectionKey() || got[i].Lagged != want[i].Lagged || string(got[i].Data) != string(want[i].Data) {
					t.Fatalf("closure retained a tail after an evicted prefix or lost a queued tombstone: got %+v, want %+v", got, want)
				}
			}
		})
	}
}

func TestDrainFullLedgerRetriesPendingMarker(t *testing.T) {
	var logs bytes.Buffer
	rd := &scriptedRingReader{closed: make(chan struct{})}
	s := &linuxSource{
		cfg: Config{Log: slog.New(slog.NewTextHandler(&logs, nil))},
		rd:  rd, out: make(chan TLSRecord, 1), stop: make(chan struct{}),
	}
	var seen []TLSRecord
	consume := func() {
		select {
		case ev := <-s.out:
			seen = append(seen, ev)
		default:
		}
	}
	rd.steps = append(rd.steps, drainStep{record: TLSRecord{PID: 17, ConnID: 9000, Data: []byte("K prefix")}})
	for id := uint64(1); id < maxLaggedConns; id++ {
		rd.steps = append(rd.steps, drainStep{record: TLSRecord{PID: 17, ConnID: id, Lagged: true}, before: consume})
	}
	rd.steps = append(rd.steps,
		drainStep{record: TLSRecord{PID: 17, ConnID: 10000, Data: []byte("blocker prefix")}, before: consume},
		drainStep{record: TLSRecord{PID: 17, ConnID: 9000, Lagged: true}},
		// Retrying a tracked loss at capacity must not clear any ledger entry.
		drainStep{record: TLSRecord{PID: 17, ConnID: 9000, Lagged: true}},
		drainStep{record: TLSRecord{PID: 17, ConnID: 9000, Data: []byte("forbidden K tail")}, before: consume},
		drainStep{record: TLSRecord{PID: 17, ConnID: 1, Data: []byte("forbidden previously truncated tail")}, before: consume},
		drainStep{record: TLSRecord{PID: 17, ConnID: 10001, Data: []byte("new safe prefix")}, before: consume},
	)
	drained := make(chan struct{})
	s.wg.Add(1)
	go func() { s.drainLoop(); close(drained) }()
	waitDrainTest(t, drained, "drainLoop")
	closed := make(chan struct{})
	go func() { _ = s.Close(); close(closed) }()
	waitDrainTest(t, closed, "source cleanup")
	for ev := range s.Records() {
		seen = append(seen, ev)
	}
	markers, safePrefixes := 0, 0
	for _, ev := range seen {
		if strings.HasPrefix(string(ev.Data), "forbidden") {
			t.Fatalf("tail crossed a tracked loss at capacity: %+v", ev)
		}
		if ev.ConnID == 9000 && ev.Lagged {
			markers++
		}
		if string(ev.Data) == "new safe prefix" {
			safePrefixes++
		}
	}
	if markers != 1 || safePrefixes != 1 || logs.Len() != 0 || rd.next != len(rd.steps) {
		t.Fatalf("tracked marker retry at capacity: markers=%d safe prefixes=%d consumed=%d/%d logs=%s", markers, safePrefixes, rd.next, len(rd.steps), &logs)
	}
}

func TestDrainLedgerSaturationNeverReadmitsPendingLoss(t *testing.T) {
	for _, kernelLoss := range []bool{true, false} {
		name := "local_backpressure"
		if kernelLoss {
			name = "kernel_tombstone"
		}
		t.Run(name, func(t *testing.T) {
			var logs bytes.Buffer
			rd := &scriptedRingReader{closed: make(chan struct{})}
			static, dynamic := &countedLink{}, &countedLink{}
			s := &linuxSource{
				cfg: Config{Log: slog.New(slog.NewTextHandler(&logs, nil)), ProcRoot: t.TempDir(), Rescan: time.Hour},
				rd:  rd, out: make(chan TLSRecord, 1), stop: make(chan struct{}),
				staticLinks: []link.Link{static}, grace: time.Hour,
				attached: map[string]*attachment{"dynamic": {links: []link.Link{dynamic}, lastSeen: time.Now()}},
			}
			key := TLSRecord{PID: 17, ConnID: 9000, Direction: TLSDirWrite}
			prefix := key
			prefix.Data = []byte("K contiguous prefix")
			var seen []TLSRecord
			consume := func() {
				select {
				case ev := <-s.out:
					seen = append(seen, ev)
				default:
					t.Error("expected a queued record before the next kernel record")
				}
			}
			rd.steps = append(rd.steps, drainStep{record: prefix})
			// 4095 delivered identities plus K's undelivered tombstone fill
			// the 4096-entry ledger. The output queue blocks K's marker.
			for id := uint64(1); id < maxLaggedConns; id++ {
				rd.steps = append(rd.steps, drainStep{
					record: TLSRecord{PID: 17, ConnID: id, Lagged: true}, before: consume,
				})
			}
			rd.steps = append(rd.steps,
				drainStep{record: TLSRecord{PID: 17, ConnID: 10000, Data: []byte("blocker prefix")}, before: consume},
				drainStep{record: TLSRecord{PID: key.PID, ConnID: key.ConnID, Lagged: true}},
				// One more loss must stop the source, never reset the ledger.
				drainStep{record: TLSRecord{PID: 17, ConnID: 10001, Lagged: kernelLoss, Data: []byte("additional loss")}},
				drainStep{record: TLSRecord{PID: key.PID, ConnID: key.ConnID, Data: []byte("K forbidden continuation")}, before: consume},
			)
			drained := make(chan struct{})
			s.wg.Add(2)
			go s.scanLoop()
			go func() { s.drainLoop(); close(drained) }()
			waitDrainTest(t, drained, "drainLoop")
			waitDrainTest(t, s.stop, "automatic saturation shutdown")
			closed := make(chan struct{})
			go func() {
				var closers sync.WaitGroup
				for i := 0; i < 8; i++ {
					closers.Add(1)
					go func() { defer closers.Done(); _ = s.Close() }()
				}
				closers.Wait()
				close(closed)
			}()
			waitDrainTest(t, closed, "source cleanup")
			for ev := range s.Records() {
				seen = append(seen, ev)
			}
			for _, ev := range seen {
				if ev.ConnectionKey() == key.ConnectionKey() && string(ev.Data) == "K forbidden continuation" {
					t.Fatalf("K continuation re-admitted after known loss with an undelivered tombstone at 4096 identities; logs: %s", &logs)
				}
			}
			if !strings.Contains(logs.String(), "ledger saturated") || !strings.Contains(logs.String(), "restart") {
				t.Fatalf("missing explicit fail-closed/restart diagnostic: %s", &logs)
			}
			if rd.closes.Load() != 1 {
				t.Fatalf("reader closed %d times, want once", rd.closes.Load())
			}
			if rd.next != len(rd.steps)-1 {
				t.Fatalf("source read past saturation: consumed %d of %d steps", rd.next, len(rd.steps))
			}
			if static.closes != 1 || dynamic.closes != 1 || len(s.attached) != 0 || len(s.staticLinks) != 0 {
				t.Fatalf("concurrent Close did not release links exactly once: static=%d dynamic=%d", static.closes, dynamic.closes)
			}
			t.Log(strings.TrimSpace(logs.String()))
		})
	}
}
