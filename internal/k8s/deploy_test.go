package k8s

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os/exec"
	"strings"
	"testing"
)

func TestUninstallPropagatesMissingHelm(t *testing.T) {
	// An empty PATH ensures no installed cluster binary can be invoked.
	t.Setenv("PATH", t.TempDir())
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	for _, deleteNamespace := range []bool{false, true} {
		err := Uninstall(context.Background(), log, "audit-release", "monitoring", deleteNamespace)
		if !errors.Is(err, exec.ErrNotFound) || !strings.HasPrefix(err.Error(), "helm [uninstall audit-release --namespace monitoring]:") {
			t.Errorf("deleteNamespace=%t: want wrapped missing helm error, got %v", deleteNamespace, err)
		}
	}
}
