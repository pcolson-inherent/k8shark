// Package k8s drives cluster operations by shelling out to helm and kubectl,
// which keeps the binary light and reuses whatever kubeconfig/context the user
// already has. The Helm chart is extracted from the embedded FS at runtime.
package k8s

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/pablocolson/k8shark/helm"
)

// extractChart writes the embedded chart to a temp dir and returns its path and
// a cleanup func.
func extractChart() (string, func(), error) {
	tmp, err := os.MkdirTemp("", "k8shark-chart-")
	if err != nil {
		return "", func() {}, err
	}
	cleanup := func() { _ = os.RemoveAll(tmp) }

	err = fs.WalkDir(helm.Chart, "k8shark", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		target := filepath.Join(tmp, path)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := helm.Chart.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	})
	if err != nil {
		cleanup()
		return "", func() {}, err
	}
	return filepath.Join(tmp, "k8shark"), cleanup, nil
}

// namespaceManifest renders the target namespace with the privileged Pod
// Security Admission labels. A privileged, hostNetwork worker DaemonSet is
// rejected on a PSA-enforcing cluster (e.g. Talos, which enforces "baseline"/
// "restricted" by default) unless its namespace opts into the privileged
// profile. The labels match deploy/k8shark.yaml (the static manifest) exactly.
func namespaceManifest(namespace string) string {
	return fmt.Sprintf(`apiVersion: v1
kind: Namespace
metadata:
  name: %s
  labels:
    app.kubernetes.io/part-of: k8shark
    pod-security.kubernetes.io/enforce: privileged
    pod-security.kubernetes.io/enforce-version: latest
    pod-security.kubernetes.io/warn: privileged
    pod-security.kubernetes.io/audit: privileged
`, namespace)
}

// ensureNamespace creates (or updates) the target namespace with the PSA labels
// before Helm runs. We do this with `kubectl apply` rather than letting Helm own
// the namespace because a chart cannot own the very namespace it installs into
// (Helm writes its release record there first) — and because the labels must be
// present *before* the worker pods are admitted.
func ensureNamespace(ctx context.Context, log *slog.Logger, namespace string) error {
	log.Info("ensuring namespace with privileged PSA labels", "namespace", namespace)
	return runStdin(ctx, log, namespaceManifest(namespace), "kubectl", "apply", "-f", "-")
}

// Install runs `helm upgrade --install` for the embedded chart, after ensuring
// the namespace exists with the privileged PSA labels.
func Install(ctx context.Context, log *slog.Logger, release, namespace string, sets []string) error {
	if err := ensureNamespace(ctx, log, namespace); err != nil {
		return fmt.Errorf("ensure namespace: %w", err)
	}

	chartDir, cleanup, err := extractChart()
	if err != nil {
		return fmt.Errorf("extract chart: %w", err)
	}
	defer cleanup()

	// No --create-namespace: ensureNamespace already created it with the PSA
	// labels (Helm's --create-namespace makes an unlabelled namespace).
	args := []string{
		"upgrade", "--install", release, chartDir,
		"--namespace", namespace,
		"--wait", "--timeout", "3m",
	}
	for _, s := range sets {
		args = append(args, "--set", s)
	}
	log.Info("installing chart", "release", release, "namespace", namespace)
	return run(ctx, log, "helm", args...)
}

// Uninstall removes the release and keeps its namespace unless deleteNamespace
// is explicitly requested by the caller.
func Uninstall(ctx context.Context, log *slog.Logger, release, namespace string, deleteNamespace bool) error {
	if err := run(ctx, log, "helm", "uninstall", release, "--namespace", namespace); err != nil {
		return err
	}
	if !deleteNamespace {
		log.Info("keeping namespace", "namespace", namespace)
		return nil
	}
	// Neither PSA labels nor `kubectl get all` establish namespace ownership:
	// Install also labels pre-existing namespaces, and get all omits many kinds.
	// This explicit opt-in deletes everything, including unrelated resources.
	log.Warn("deleting entire namespace and ALL remaining resources (--delete-namespace)", "namespace", namespace)
	return run(ctx, log, "kubectl", "delete", "namespace", namespace, "--ignore-not-found")
}

// PortForward starts `kubectl port-forward` for a service. The returned command
// is already started; call Wait or Process.Kill to stop it.
func PortForward(ctx context.Context, namespace, svc string, local, remote int) (*exec.Cmd, error) {
	cmd := exec.CommandContext(ctx, "kubectl", "port-forward",
		"--namespace", namespace,
		"svc/"+svc, fmt.Sprintf("%d:%d", local, remote))
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	return cmd, cmd.Start()
}

// Logs streams logs from a component (by app.kubernetes.io/name label).
func Logs(ctx context.Context, namespace, component string, follow bool) error {
	args := []string{"logs", "--namespace", namespace,
		"-l", "app.kubernetes.io/name=k8shark-" + component,
		"--all-containers", "--max-log-requests", "20", "--tail", "100"}
	if follow {
		args = append(args, "-f")
	}
	cmd := exec.CommandContext(ctx, "kubectl", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// OpenBrowser best-effort opens url in the default browser.
func OpenBrowser(url string) {
	var cmd string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		cmd = "open"
	case "windows":
		cmd, args = "rundll32", []string{"url.dll,FileProtocolHandler"}
	default:
		cmd = "xdg-open"
	}
	_ = exec.Command(cmd, append(args, url)...).Start()
}

func run(ctx context.Context, log *slog.Logger, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %v: %w", name, args, err)
	}
	return nil
}

// runStdin runs a command feeding stdin from a string (used to `kubectl apply -f -`).
func runStdin(ctx context.Context, log *slog.Logger, stdin, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	cmd.Stdin = strings.NewReader(stdin)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %v: %w", name, args, err)
	}
	return nil
}
