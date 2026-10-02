package worker

import (
	"errors"
	"io"
	"testing"
	"time"

	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

func TestConsumeStreamDrainsMalformedHTTP(t *testing.T) {
	p := newPipeline(newSink("", "", "n", discardLogger()), "n", "", discardLogger())
	netFlow, transport, _, _ := flows(44001, 80)
	r := tcpreader.NewReaderStream()
	r.LossErrors = true
	consumerDone := make(chan struct{})
	go func() {
		p.consumeStream(netFlow, transport, &r)
		close(consumerDone)
	}()

	assembled := make(chan struct{})
	go func() {
		r.Reassembled([]tcpassembly.Reassembly{{Bytes: []byte("GET / HTTP/1.1\r\nbroken-header\r\n\r\n")}})
		// A later gap must not stop cleanup: the assembler still needs every
		// fragment acknowledged, even after the HTTP parser has returned.
		r.Reassembled([]tcpassembly.Reassembly{{Bytes: []byte("discarded bytes"), Skip: 1}})
		r.ReassemblyComplete()
		close(assembled)
	}()

	select {
	case <-assembled:
	case <-time.After(2 * time.Second):
		// On the unfixed code the consumer has returned. Drain its real
		// ReaderStream here so the failing regression does not leak a sender.
		select {
		case <-consumerDone:
			var buf [1024]byte
			for {
				_, err := r.Read(buf[:])
				if err != nil && !errors.Is(err, tcpreader.DataLost) {
					if !errors.Is(err, io.EOF) {
						t.Errorf("cleanup: %v", err)
					}
					break
				}
			}
			<-assembled
		default:
			t.Fatal("consumer and reassembler both stalled")
		}
		t.Fatal("malformed HTTP left the assembler blocked on an unread stream")
	}
	select {
	case <-consumerDone:
	case <-time.After(2 * time.Second):
		t.Fatal("consumer did not finish after reassembly completed")
	}
}
