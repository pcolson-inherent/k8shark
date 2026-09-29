package hub

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func captureTestManager(t *testing.T) (*captureManager, *[]string) {
	t.Helper()
	var patches []string
	ds := `{"metadata":{"annotations":{"k8shark.io/capture-state":"stopped"}},"spec":{"template":{"spec":{"nodeSelector":{"k8shark.io/capture-disabled":"true","pool":"capture"},"schedulingGates":[{"name":"user-gate"}]}}},"status":{"desiredNumberScheduled":0,"numberReady":0,"currentNumberScheduled":0}}`
	m := &captureManager{api: "https://kube.test", token: "token", namespace: "ns", name: "k8shark-worker", defaultDuration: 15 * time.Minute, maxDuration: time.Hour}
	m.client = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodPatch {
			b, _ := io.ReadAll(r.Body)
			patches = append(patches, string(b))
			return &http.Response{StatusCode: 200, Status: "200 OK", Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
		}
		return &http.Response{StatusCode: 200, Status: "200 OK", Body: io.NopCloser(strings.NewReader(ds)), Header: make(http.Header)}, nil
	})}
	return m, &patches
}

func TestCaptureStartPatchesOnlyRuntimeSelectorAndAnnotations(t *testing.T) {
	m, patches := captureTestManager(t)
	s, err := m.start(context.Background(), 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if s.State != "stopped" {
		t.Fatalf("state after patch read = %q, want stopped fake status", s.State)
	}
	if len(*patches) != 1 {
		t.Fatalf("patches = %d", len(*patches))
	}
	p := (*patches)[0]
	if !strings.Contains(p, `"k8shark.io/capture-state":"running"`) || !strings.Contains(p, `"nodeSelector":{"k8shark.io/capture-disabled":null}`) || strings.Contains(p, "schedulingGates") || strings.Contains(p, "pool") {
		t.Fatalf("unexpected start patch: %s", p)
	}
}

func TestCaptureStopAddsSelectorAndClearsExpiry(t *testing.T) {
	m, patches := captureTestManager(t)
	ds := daemonSet{}
	ds.Spec.Template.Spec.SchedulingGates = []struct {
		Name string `json:"name"`
	}{{Name: "user-gate"}}
	if err := m.patch(context.Background(), ds, "stopped", nil, true); err != nil {
		t.Fatal(err)
	}
	p := (*patches)[0]
	if !strings.Contains(p, `"k8shark.io/capture-state":"stopped"`) || !strings.Contains(p, `"k8shark.io/capture-expiry":null`) || !strings.Contains(p, `"nodeSelector":{"k8shark.io/capture-disabled":"true"}`) || strings.Contains(p, "schedulingGates") {
		t.Fatalf("unexpected stop patch: %s", p)
	}
}

func TestCaptureStartBoundsDuration(t *testing.T) {
	m, _ := captureTestManager(t)
	if _, err := m.start(context.Background(), 2*time.Hour); err == nil {
		t.Fatal("expected max-duration error")
	}
}

func TestCaptureSessionReportsUnavailableKubernetesAccess(t *testing.T) {
	s := New(slog.Default(), Options{OnDemandCapture: true})
	// The unit-test process has no ServiceAccount token, which is precisely the
	// actionable failure a chart-installed hub must surface instead of faking a
	// stopped/healthy session.
	rec := httptest.NewRecorder()
	s.handleCaptureSession(rec, httptest.NewRequest(http.MethodGet, "/api/capture/session", nil))
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "kubernetes access is unavailable") {
		t.Fatalf("session response = %d %s", rec.Code, rec.Body.String())
	}
}

func TestCaptureDescribeWaitsForObservedWorkerLifecycle(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		name, intent, want                    string
		disabled                              bool
		observed                              int64
		desired, current, ready, misscheduled int32
	}{
		{name: "legacy gated workers", intent: "stopped", want: "stopping", observed: 2, desired: 27, current: 27},
		{name: "stop not observed", intent: "stopped", want: "stopping", disabled: true, observed: 1},
		{name: "workers terminating", intent: "stopped", want: "stopping", disabled: true, observed: 2, misscheduled: 27},
		{name: "stopped", intent: "stopped", want: "stopped", disabled: true, observed: 2},
		{name: "start not observed", intent: "running", want: "starting", observed: 1, desired: 27, current: 27, ready: 27},
		{name: "starting", intent: "running", want: "starting", observed: 2, desired: 27, current: 27, ready: 26},
		{name: "running", intent: "running", want: "running", observed: 2, desired: 27, current: 27, ready: 27},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var ds daemonSet
			ds.Metadata.Generation = 2
			ds.Metadata.Annotations = map[string]string{captureStateAnno: tc.intent}
			if tc.disabled {
				ds.Spec.Template.Spec.NodeSelector = map[string]string{captureDisabled: "true"}
			}
			ds.Status.ObservedGeneration = tc.observed
			ds.Status.DesiredNumberScheduled = tc.desired
			ds.Status.CurrentNumberScheduled = tc.current
			ds.Status.NumberReady = tc.ready
			ds.Status.NumberMisscheduled = tc.misscheduled
			if got := (&captureManager{}).describe(ds, now).State; got != tc.want {
				t.Fatalf("state=%s, want %s", got, tc.want)
			}
		})
	}
}

func TestCaptureReconcileMigratesLegacyAndEnforcesExpiry(t *testing.T) {
	future := time.Now().Add(time.Hour).UTC().Truncate(time.Second).Format(time.RFC3339)
	past := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	for _, tc := range []struct {
		name, intent, expiry string
		legacy, disabled     bool
		wantState            string
		wantPatch            bool
	}{
		{"legacy stopped", "stopped", "", true, false, "stopped", true},
		{"legacy active", "running", future, true, false, "running", true},
		{"expired with zero workers", "running", past, false, false, "stopped", true},
		{"interrupted stop", "stopped", "", false, false, "stopped", true},
		{"stopped idempotent", "stopped", "", false, true, "", false},
		{"active idempotent", "running", future, false, false, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var ds daemonSet
			ds.Metadata.Annotations = map[string]string{captureStateAnno: tc.intent, captureExpiryAnno: tc.expiry}
			ds.Metadata.ResourceVersion = "12"
			if tc.disabled {
				ds.Spec.Template.Spec.NodeSelector = map[string]string{captureDisabled: "true"}
			}
			if tc.legacy {
				if err := json.Unmarshal([]byte(`{"spec":{"template":{"spec":{"schedulingGates":[{"name":"k8shark.io/capture-stopped"},{"name":"user-gate"}]}}}}`), &ds); err != nil {
					t.Fatal(err)
				}
			}
			raw, err := json.Marshal(ds)
			if err != nil {
				t.Fatal(err)
			}
			var patch map[string]any
			m := &captureManager{api: "https://kube.test", namespace: "ns", name: "k8shark-worker"}
			m.client = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				body := string(raw)
				if r.Method == http.MethodPatch {
					if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
						t.Fatal(err)
					}
					body = `{}`
				}
				return &http.Response{StatusCode: 200, Status: "200 OK", Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
			})}
			m.reconcile(context.Background())
			if (patch != nil) != tc.wantPatch {
				t.Fatalf("patch=%v, wantPatch=%v", patch, tc.wantPatch)
			}
			if patch == nil {
				return
			}
			meta := patch["metadata"].(map[string]any)
			annotations := meta["annotations"].(map[string]any)
			if meta["resourceVersion"] != "12" || annotations[captureStateAnno] != tc.wantState {
				t.Fatalf("metadata=%v", meta)
			}
			podSpec := patch["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)
			selector := podSpec["nodeSelector"].(map[string]any)
			if tc.wantState == "running" {
				if selector[captureDisabled] != nil || annotations[captureExpiryAnno] != future {
					t.Fatalf("active session changed: %v", patch)
				}
			} else if selector[captureDisabled] != "true" || annotations[captureExpiryAnno] != nil {
				t.Fatalf("stop patch=%v", patch)
			}
			if tc.legacy {
				gates := podSpec["schedulingGates"].([]any)
				if len(gates) != 1 || gates[0].(map[string]any)["name"] != "user-gate" {
					t.Fatalf("gates=%v", gates)
				}
			}
		})
	}
}
