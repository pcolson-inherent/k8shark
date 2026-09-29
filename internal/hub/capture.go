package hub

// The on-demand capture controller deliberately talks to the Kubernetes API
// directly. Keeping this small client here avoids bringing client-go (and its
// large dependency graph) into the hub just to patch one DaemonSet.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"
)

const (
	captureGate       = "k8shark.io/capture-stopped" // legacy gate, removed during migration
	captureDisabled   = "k8shark.io/capture-disabled"
	captureStateAnno  = "k8shark.io/capture-state"
	captureExpiryAnno = "k8shark.io/capture-expiry"
)

// CaptureSession is the observed state of the worker lifecycle. It is kept in
// the DaemonSet annotations so a restarted hub resumes the same session.
type CaptureSession struct {
	Enabled         bool      `json:"enabled"`
	State           string    `json:"state"`
	ExpiresAt       time.Time `json:"expiresAt,omitempty"`
	DesiredWorkers  int32     `json:"desiredWorkers"`
	ReadyWorkers    int32     `json:"readyWorkers"`
	Error           string    `json:"error,omitempty"`
	DefaultDuration string    `json:"defaultDuration,omitempty"`
	MaxDuration     string    `json:"maxDuration,omitempty"`
}

type captureManager struct {
	mu              sync.Mutex
	client          *http.Client
	api             string
	token           string
	namespace       string
	name            string
	defaultDuration time.Duration
	maxDuration     time.Duration
	logf            func(string, ...any)
}

type daemonSet struct {
	Metadata struct {
		Annotations     map[string]string `json:"annotations"`
		Generation      int64             `json:"generation"`
		ResourceVersion string            `json:"resourceVersion"`
	} `json:"metadata"`
	Spec struct {
		Template struct {
			Spec struct {
				NodeSelector    map[string]string `json:"nodeSelector"`
				SchedulingGates []struct {
					Name string `json:"name"`
				} `json:"schedulingGates"`
			} `json:"spec"`
		} `json:"template"`
	} `json:"spec"`
	Status struct {
		ObservedGeneration     int64 `json:"observedGeneration"`
		NumberMisscheduled     int32 `json:"numberMisscheduled"`
		DesiredNumberScheduled int32 `json:"desiredNumberScheduled"`
		NumberReady            int32 `json:"numberReady"`
		CurrentNumberScheduled int32 `json:"currentNumberScheduled"`
	} `json:"status"`
}

func newCaptureManager(namespace, name string, defaultDuration, maxDuration time.Duration) *captureManager {
	if namespace == "" {
		namespace = os.Getenv("POD_NAMESPACE")
	}
	if namespace == "" {
		namespace = "default"
	}
	if name == "" {
		name = "k8shark-worker"
	}
	if defaultDuration <= 0 {
		defaultDuration = 15 * time.Minute
	}
	if maxDuration <= 0 {
		maxDuration = time.Hour
	}
	r := newResolver(slog.Default())
	if !r.enabled() {
		return &captureManager{namespace: namespace, name: name, defaultDuration: defaultDuration, maxDuration: maxDuration}
	}
	return &captureManager{client: r.client, api: r.api, token: r.token, namespace: namespace, name: name, defaultDuration: defaultDuration, maxDuration: maxDuration}
}

func (m *captureManager) available() bool { return m != nil && m.client != nil }

func (m *captureManager) session(ctx context.Context) (CaptureSession, error) {
	if !m.available() {
		return CaptureSession{}, fmt.Errorf("kubernetes access is unavailable; on-demand capture requires the hub ServiceAccount")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	ds, err := m.get(ctx)
	if err != nil {
		return CaptureSession{}, err
	}
	return m.describe(ds, time.Now()), nil
}

func (m *captureManager) start(ctx context.Context, duration time.Duration) (CaptureSession, error) {
	if !m.available() {
		return CaptureSession{}, fmt.Errorf("kubernetes access is unavailable; on-demand capture requires the hub ServiceAccount")
	}
	if duration == 0 {
		duration = m.defaultDuration
	}
	if duration <= 0 || duration > m.maxDuration {
		return CaptureSession{}, fmt.Errorf("duration must be between 1s and %s", m.maxDuration)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	ds, err := m.get(ctx)
	if err != nil {
		return CaptureSession{}, err
	}
	current := m.describe(ds, time.Now())
	// Start is idempotent: a retry does not silently extend an active session.
	if current.State == "starting" || current.State == "running" {
		return current, nil
	}
	expires := time.Now().Add(duration).UTC()
	if err := m.patch(ctx, ds, "running", &expires, false); err != nil {
		return CaptureSession{}, err
	}
	ds, err = m.get(ctx)
	if err != nil {
		return CaptureSession{}, err
	}
	return m.describe(ds, time.Now()), nil
}

func (m *captureManager) stop(ctx context.Context) (CaptureSession, error) {
	if !m.available() {
		return CaptureSession{}, fmt.Errorf("kubernetes access is unavailable; on-demand capture requires the hub ServiceAccount")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	ds, err := m.get(ctx)
	if err != nil {
		return CaptureSession{}, err
	}
	current := m.describe(ds, time.Now())
	if current.State == "stopped" {
		return current, nil
	}
	if err := m.patch(ctx, ds, "stopped", nil, true); err != nil {
		return CaptureSession{}, err
	}
	ds, err = m.get(ctx)
	if err != nil {
		return CaptureSession{}, err
	}
	return m.describe(ds, time.Now()), nil
}

// reconcile enforces expiry after hub restart or a period of unavailability.
func (m *captureManager) reconcile(ctx context.Context) {
	if !m.available() {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	ds, err := m.get(ctx)
	if err != nil {
		return
	}
	now := time.Now()
	s := m.describe(ds, now)
	stopped := ds.Metadata.Annotations[captureStateAnno] != "running" || (!s.ExpiresAt.IsZero() && !s.ExpiresAt.After(now))
	_, disabled := ds.Spec.Template.Spec.NodeSelector[captureDisabled]
	legacy := false
	for _, gate := range ds.Spec.Template.Spec.SchedulingGates {
		legacy = legacy || gate.Name == captureGate
	}
	// Repair legacy gates and interrupted transitions without extending sessions.
	if legacy || (stopped && ds.Spec.Template.Spec.NodeSelector[captureDisabled] != "true") || (!stopped && disabled) || (stopped && ds.Metadata.Annotations[captureExpiryAnno] != "") {
		state := "stopped"
		var expiry *time.Time
		if !stopped {
			state = "running"
			if !s.ExpiresAt.IsZero() {
				expiry = &s.ExpiresAt
			}
		}
		if err := m.patch(ctx, ds, state, expiry, stopped); err != nil && m.logf != nil {
			m.logf("capture session reconciliation failed: %v", err)
		}
	}
}

func (m *captureManager) describe(ds daemonSet, now time.Time) CaptureSession {
	s := CaptureSession{Enabled: true, DesiredWorkers: ds.Status.DesiredNumberScheduled, ReadyWorkers: ds.Status.NumberReady, DefaultDuration: m.defaultDuration.String(), MaxDuration: m.maxDuration.String()}
	a := ds.Metadata.Annotations
	if raw := a[captureExpiryAnno]; raw != "" {
		s.ExpiresAt, _ = time.Parse(time.RFC3339, raw)
	}
	stopped := a[captureStateAnno] != "running" || (!s.ExpiresAt.IsZero() && !s.ExpiresAt.After(now))
	if stopped {
		if ds.Spec.Template.Spec.NodeSelector[captureDisabled] == "true" && ds.Status.ObservedGeneration >= ds.Metadata.Generation && ds.Status.DesiredNumberScheduled == 0 && ds.Status.NumberReady == 0 && ds.Status.CurrentNumberScheduled == 0 && ds.Status.NumberMisscheduled == 0 {
			s.State = "stopped"
		} else {
			s.State = "stopping"
		}
	} else if ds.Status.ObservedGeneration >= ds.Metadata.Generation && ds.Status.DesiredNumberScheduled > 0 && ds.Status.NumberReady >= ds.Status.DesiredNumberScheduled {
		s.State = "running"
	} else {
		s.State = "starting"
	}
	return s
}

func (m *captureManager) get(ctx context.Context) (daemonSet, error) {
	var ds daemonSet
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.api+"/apis/apps/v1/namespaces/"+m.namespace+"/daemonsets/"+m.name, nil)
	if err != nil {
		return ds, err
	}
	req.Header.Set("Authorization", "Bearer "+m.token)
	resp, err := m.client.Do(req)
	if err != nil {
		return ds, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return ds, fmt.Errorf("read worker DaemonSet: Kubernetes returned %s: %s", resp.Status, bytes.TrimSpace(b))
	}
	if err := json.NewDecoder(resp.Body).Decode(&ds); err != nil {
		return ds, fmt.Errorf("decode worker DaemonSet: %w", err)
	}
	return ds, nil
}

func (m *captureManager) patch(ctx context.Context, ds daemonSet, state string, expiry *time.Time, stopped bool) error {
	annotations := map[string]any{captureStateAnno: state, captureExpiryAnno: nil}
	if expiry != nil {
		annotations[captureExpiryAnno] = expiry.Format(time.RFC3339)
	}
	// Merge only our reserved selector key; all other scheduling settings stay
	// Git-owned. A null value removes only this key on start.
	var disabled any
	if stopped {
		disabled = "true"
	}
	podSpec := map[string]any{"nodeSelector": map[string]any{captureDisabled: disabled}}
	gates := make([]map[string]string, 0, len(ds.Spec.Template.Spec.SchedulingGates))
	legacy := false
	for _, gate := range ds.Spec.Template.Spec.SchedulingGates {
		if gate.Name == captureGate {
			legacy = true
		} else {
			gates = append(gates, map[string]string{"name": gate.Name})
		}
	}
	if legacy {
		podSpec["schedulingGates"] = gates
	}
	metadata := map[string]any{"annotations": annotations}
	if ds.Metadata.ResourceVersion != "" {
		// Protect the read/modify/write of the legacy gate list against other writers.
		metadata["resourceVersion"] = ds.Metadata.ResourceVersion
	}
	body, _ := json.Marshal(map[string]any{"metadata": metadata, "spec": map[string]any{"template": map[string]any{"spec": podSpec}}})
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, m.api+"/apis/apps/v1/namespaces/"+m.namespace+"/daemonsets/"+m.name, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+m.token)
	req.Header.Set("Content-Type", "application/merge-patch+json")
	resp, err := m.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("update worker DaemonSet: Kubernetes returned %s: %s", resp.Status, bytes.TrimSpace(b))
	}
	return nil
}
