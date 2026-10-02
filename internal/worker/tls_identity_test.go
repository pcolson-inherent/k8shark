package worker

import (
	"context"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/pablocolson/k8shark/internal/worker/ebpf"
	"github.com/pablocolson/k8shark/pkg/api"
)

func TestConsumeTLSSeparatesProcessesSharingSSLPointer(t *testing.T) {
	for _, firstPID := range []uint32{101, 0} {
		t.Run(fmt.Sprintf("first_pid_%d", firstPID), func(t *testing.T) {
			p, src := startTLSIdentityPipeline(t, 4)
			first := ebpf.TLSRecord{PID: firstPID, TID: 7, ConnID: 42}
			second := ebpf.TLSRecord{PID: 202, TID: 9, ConnID: 42}
			sendTLSIdentityRecord(src, first, ebpf.TLSDirWrite, "GET /first HTTP/1.1\r\nHost: first\r\n\r\n")
			sendTLSIdentityRecord(src, second, ebpf.TLSDirWrite, "GET /second HTTP/1.1\r\nHost: second\r\n\r\n")
			waitTLSIdentity(t, "both requests parsed", func() bool { return tlsIdentityPending(p) == 2 })

			// Reverse response order: a shared stream would incorrectly pair
			// the second process's response with the first process's request.
			// Neither direction is required to stay on the original thread.
			first.TID++
			second.TID++
			sendTLSIdentityRecord(src, second, ebpf.TLSDirRead, "HTTP/1.1 202 Accepted\r\nContent-Length: 1\r\n\r\nB")
			assertTLSIdentityEntry(t, nextTLSIdentityEntry(t, p.sink), second.PID, "/second", 202, "B")
			sendTLSIdentityRecord(src, first, ebpf.TLSDirRead, "HTTP/1.1 201 Created\r\nContent-Length: 1\r\n\r\nA")
			assertTLSIdentityEntry(t, nextTLSIdentityEntry(t, p.sink), first.PID, "/first", 201, "A")
		})
	}
}

func TestConsumeTLSLaggedIsolatesProcessesSharingSSLPointer(t *testing.T) {
	for _, laggedPID := range []uint32{101, 0} {
		t.Run(fmt.Sprintf("lagged_pid_%d", laggedPID), func(t *testing.T) {
			p, src := startTLSIdentityPipeline(t, 4)
			lagged := ebpf.TLSRecord{PID: laggedPID, TID: 7, ConnID: 42}
			healthy := ebpf.TLSRecord{PID: 202, TID: 9, ConnID: 42}
			sendTLSIdentityRecord(src, healthy, ebpf.TLSDirWrite, "GET /healthy HTTP/1.1\r\nHost: hea")
			sendTLSIdentityRecord(src, lagged, ebpf.TLSDirWrite, "GET /lost HTTP/1.1\r\nHost: los")
			marker := lagged
			marker.TID++ // Loss must close the connection, not just one thread.
			marker.Lagged = true
			src.ch <- marker
			waitTLSIdentity(t, "one stream truncated", func() bool { return p.sink.tlsLagDrops.Load() == 1 })

			// Only the healthy process's stream may accept this continuation.
			sendTLSIdentityRecord(src, healthy, ebpf.TLSDirWrite, "lthy\r\n\r\n")
			sendTLSIdentityRecord(src, healthy, ebpf.TLSDirRead, "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nH")
			assertTLSIdentityEntry(t, nextTLSIdentityEntry(t, p.sink), healthy.PID, "/healthy", 200, "H")
			if p.sink.tlsLagDrops.Load() != 1 {
				t.Fatal("one tombstone truncated more than one process")
			}

			// A new record for the truncated identity must start a fresh stream.
			sendTLSIdentityRecord(src, lagged, ebpf.TLSDirWrite, "GET /fresh HTTP/1.1\r\nHost: fresh\r\n\r\n")
			waitTLSIdentity(t, "fresh request parsed", func() bool { return tlsIdentityPending(p) == 1 })
			sendTLSIdentityRecord(src, lagged, ebpf.TLSDirRead, "HTTP/1.1 201 Created\r\nContent-Length: 1\r\n\r\nF")
			assertTLSIdentityEntry(t, nextTLSIdentityEntry(t, p.sink), lagged.PID, "/fresh", 201, "F")
		})
	}
}

func TestConsumeTLSAdmissionCountsProcessesSharingSSLPointer(t *testing.T) {
	p, src := startTLSIdentityPipeline(t, 1)
	sendTLSIdentityRecord(src, ebpf.TLSRecord{PID: 0, ConnID: 42}, ebpf.TLSDirWrite, "G")
	sendTLSIdentityRecord(src, ebpf.TLSRecord{PID: 202, ConnID: 42}, ebpf.TLSDirWrite, "G")
	waitTLSIdentity(t, "second process rejected by stream limit", func() bool { return p.sink.tlsBudgetDrops.Load() == 1 })
}

func startTLSIdentityPipeline(t *testing.T, streamLimit int) (*pipeline, *fakeTLSSource) {
	t.Helper()
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "", discardLogger())
	src := newFakeTLSSource()
	budget := newTLSByteBudget(4096)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		p.consumeTLSBounded(ctx, src, streamLimit, budget)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("TLS consumer did not stop")
		}
		waitTLSIdentity(t, "byte budget released after shutdown", func() bool {
			budget.mu.Lock()
			defer budget.mu.Unlock()
			return budget.used == 0
		})
	})
	return p, src
}

func sendTLSIdentityRecord(src *fakeTLSSource, rec ebpf.TLSRecord, dir ebpf.TLSDirection, data string) {
	rec.Direction, rec.Data = dir, []byte(data)
	src.ch <- rec // Ownership transfers; each record gets its own backing buffer.
}

func tlsIdentityPending(p *pipeline) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, cs := range p.conns {
		for _, req := range cs.reqs {
			if req.filled {
				n++
			}
		}
	}
	return n
}

func waitTLSIdentity(t *testing.T, what string, ready func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !ready() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

func nextTLSIdentityEntry(t *testing.T, s *sink) *api.Entry {
	t.Helper()
	var entries []*api.Entry
	waitTLSIdentity(t, "paired entry", func() bool {
		entries = drain(s)
		return len(entries) > 0
	})
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want exactly one", len(entries))
	}
	return entries[0]
}

func assertTLSIdentityEntry(t *testing.T, e *api.Entry, pid uint32, path string, status int, body string) {
	t.Helper()
	wantIP := "pid:" + strconv.FormatUint(uint64(pid), 10)
	if e.Protocol != api.ProtocolHTTP || e.Request.Path != path || e.Response.StatusCode != status || e.Response.Body != body || e.Source.IP != wantIP {
		t.Fatalf("got protocol=%s path=%q status=%d body=%q source=%q; want HTTP path=%q status=%d body=%q source=%q", e.Protocol, e.Request.Path, e.Response.StatusCode, e.Response.Body, e.Source.IP, path, status, body, wantIP)
	}
}
