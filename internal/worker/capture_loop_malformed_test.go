package worker

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func drainRegressionTCPPacket(t *testing.T, srcPort, dstPort layers.TCPPort, seq uint32, syn, fin bool, payload string) gopacket.Packet {
	t.Helper()
	src, dst := net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2)
	if srcPort == 80 {
		src, dst = dst, src
	}
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{5, 4, 3, 2, 1, 0}, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, TTL: 64, SrcIP: src, DstIP: dst, Protocol: layers.IPProtocolTCP}
	tcp := &layers.TCP{SrcPort: srcPort, DstPort: dstPort, Seq: seq, SYN: syn, FIN: fin, ACK: !syn}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, tcp, gopacket.Payload(payload)); err != nil {
		t.Fatal(err)
	}
	packet := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	packet.Metadata().CaptureInfo.Timestamp = time.Now()
	return packet
}

func TestCaptureLoopContinuesAfterMalformedHTTP(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "", discardLogger())
	src := newFakeSource()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	loopDone := make(chan error, 1)
	go func() { loopDone <- captureLoop(ctx, discardLogger(), p, src, nil) }()

	bad := "GET / HTTP/1.1\r\nbroken-header\r\n\r\n"
	good := "GET /healthy HTTP/1.1\r\nHost: example.test\r\n\r\n"
	response := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
	packets := []gopacket.Packet{
		drainRegressionTCPPacket(t, 44010, 80, 1, true, false, ""),
		drainRegressionTCPPacket(t, 44010, 80, 2, false, false, bad),
		drainRegressionTCPPacket(t, 44010, 80, 2+uint32(len(bad)), false, true, ""),
		drainRegressionTCPPacket(t, 44011, 80, 1, true, false, ""),
		drainRegressionTCPPacket(t, 44011, 80, 2, false, false, good),
		drainRegressionTCPPacket(t, 44011, 80, 2+uint32(len(good)), false, true, ""),
		drainRegressionTCPPacket(t, 80, 44011, 1, true, false, ""),
		drainRegressionTCPPacket(t, 80, 44011, 2, false, false, response),
		drainRegressionTCPPacket(t, 80, 44011, 2+uint32(len(response)), false, true, ""),
	}
	fed := make(chan struct{})
	go func() {
		defer close(fed)
		for _, packet := range packets {
			select {
			case src.ch <- packet:
			case <-ctx.Done():
				return
			}
		}
	}()
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
waitHTTP:
	for {
		select {
		case entry := <-s.ch:
			// A malformed flow can legitimately produce a generic L4 entry.
			if entry.Protocol != "http" {
				continue
			}
			if entry.Request.Path != "/healthy" || entry.Response.Body != "OK" {
				t.Fatalf("unexpected healthy-flow pair: %+v", entry)
			}
			break waitHTTP
		case <-deadline.C:
			t.Fatal("malformed HTTP prevented the capture loop from pairing another connection")
		}
	}
	select {
	case <-fed:
	case <-time.After(2 * time.Second):
		t.Fatal("capture loop did not consume the remaining packets")
	}
	waitForBool(t, func() bool {
		p.mu.Lock()
		defer p.mu.Unlock()
		return len(p.afPacketStreams) == 0
	}, true, "all TCP consumers drained")
	cancel()
	select {
	case err := <-loopDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("capture loop did not observe cancellation after the malformed flow")
	}
}
