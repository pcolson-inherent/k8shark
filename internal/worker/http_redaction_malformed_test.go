package worker

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestHTTPMalformedQueryRedaction(t *testing.T) {
	const secret = "fixture-secret-marker"
	for _, query := range []string{
		"token=" + secret + ";x=1&user=alice",
		"token=" + secret + "&bad=%ZZ&user=alice",
	} {
		t.Run(query, func(t *testing.T) {
			s := newSink("", "", "n", discardLogger())
			p := newPipeline(s, "n", "", discardLogger())
			p.redactHeaders = true
			p.rawCap = -1
			reqNet, reqTr, respNet, respTr := flows(44002, 80)
			p.consumeHTTP(reqNet, reqTr, strings.NewReader("GET /login?"+query+" HTTP/1.1\r\nHost: example.test\r\n\r\n"))
			p.consumeHTTP(respNet, respTr, strings.NewReader("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
			entries := drain(s)
			if len(entries) != 1 {
				t.Fatalf("got %d entries, want one request/response pair", len(entries))
			}
			encoded, err := json.Marshal(entries[0])
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(encoded), secret) {
				t.Fatalf("malformed query leaked a credential into the entry: %s", encoded)
			}
			if got, want := entries[0].Request.Path, "/login?%5BREDACTED%5D"; got != want {
				t.Errorf("Path = %q, want fail-closed query %q", got, want)
			}
			if got := entries[0].Request.HTTP.Query; got != nil {
				t.Errorf("malformed query should not expose a misleading partial map: %v", got)
			}
		})
	}
}
