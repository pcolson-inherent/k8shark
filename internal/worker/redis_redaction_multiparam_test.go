package worker

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/pablocolson/k8shark/pkg/api"
)

func TestRedisMultiParameterConfigRedaction(t *testing.T) {
	const secret = "SECRET"
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "", discardLogger())
	p.redactHeaders = true
	p.rawCap = -1
	reqNet, reqTr, respNet, respTr := flows(44003, redisPort)
	wire := "*6\r\n$6\r\nCONFIG\r\n$3\r\nSET\r\n$9\r\nmaxmemory\r\n$4\r\n1024\r\n$11\r\nrequirepass\r\n$6\r\nSECRET\r\n"
	p.consumeRedis(reqNet, reqTr, strings.NewReader(wire), true, api.ProtocolRedis)
	p.consumeRedis(respNet, respTr, strings.NewReader("+OK\r\n"), false, api.ProtocolRedis)
	entries := drain(s)
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want one request/response pair", len(entries))
	}
	encoded, err := json.Marshal(entries[0])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), secret) {
		t.Fatalf("CONFIG SET leaked a credential into the entry: %s", encoded)
	}
	want := []string{"CONFIG", "SET", "maxmemory", "1024", "requirepass", redactedValue}
	if got := entries[0].Request.Redis.Args; !reflect.DeepEqual(got, want) {
		t.Errorf("Args = %v, want %v", got, want)
	}
	if got, want := entries[0].Request.Command, strings.Join(want, " "); got != want {
		t.Errorf("Command = %q, want %q", got, want)
	}
}

func TestRedisConfigRedactionPreservesParameterPairs(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want []string
	}{
		{"first", []string{"CONFIG", "SET", "requirepass", "secret", "maxmemory", "1024"}, []string{"CONFIG", "SET", "requirepass", redactedValue, "maxmemory", "1024"}},
		{"middle", []string{"CONFIG", "SET", "maxmemory", "1024", "masterauth", "secret", "timeout", "1"}, []string{"CONFIG", "SET", "maxmemory", "1024", "masterauth", redactedValue, "timeout", "1"}},
		{"multiple and case insensitive", []string{"config", "set", "requirepass", "one", "MASTERauth", "two"}, []string{"config", "set", "requirepass", redactedValue, "MASTERauth", redactedValue}},
		{"malformed odd tail", []string{"CONFIG", "SET", "maxmemory", "1024", "requirepass", "secret", "orphan"}, []string{"CONFIG", "SET", redactedValue, redactedValue, redactedValue, redactedValue, redactedValue}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			original := append([]string(nil), tc.args...)
			got, ok := redactSensitiveRedisArgs(tc.args)
			if !ok || !reflect.DeepEqual(got, tc.want) {
				t.Errorf("redaction = %v, %v; want %v, true", got, ok, tc.want)
			}
			if !reflect.DeepEqual(tc.args, original) {
				t.Errorf("redaction mutated the caller's arguments: %v", tc.args)
			}
		})
	}
}

func TestRedisConfigRedactionAcceptsShortArgLists(t *testing.T) {
	for _, args := range [][]string{nil, {}, {"CONFIG"}, {"CONFIG", "SET"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			got, ok := redactSensitiveRedisArgs(args)
			if ok || !reflect.DeepEqual(got, args) {
				t.Errorf("redaction = %v, %v; want unchanged %v, false", got, ok, args)
			}
		})
	}
}
