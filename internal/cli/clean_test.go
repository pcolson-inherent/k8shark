package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type cleanCommandStep struct {
	Args     []string
	ExitCode int
}

// The only helm/kubectl executables visible to clean are this test binary.
// Every invocation is recorded, and an unplanned command fails closed.
func TestMain(m *testing.M) {
	switch filepath.Base(os.Args[0]) {
	case "helm", "kubectl":
		os.Exit(cleanCommandHelper())
	default:
		os.Exit(m.Run())
	}
}

func cleanCommandHelper() int {
	var steps []cleanCommandStep
	if err := json.Unmarshal([]byte(os.Getenv("K8SHARK_CLEAN_STEPS")), &steps); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 97
	}
	path := os.Getenv("K8SHARK_CLEAN_COMMANDS")
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 97
	}
	var calls [][]string
	if err := json.Unmarshal(data, &calls); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 97
	}
	args := append([]string{filepath.Base(os.Args[0])}, os.Args[1:]...)
	index := len(calls)
	calls = append(calls, args)
	data, err = json.Marshal(calls)
	if err != nil {
		return 97
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 97
	}
	if index >= len(steps) || !reflect.DeepEqual(args, steps[index].Args) {
		fmt.Fprintf(os.Stderr, "unplanned cluster command blocked: %q\n", args)
		return 97
	}
	return steps[index].ExitCode
}

func expectCleanCommands(t *testing.T, steps ...cleanCommandStep) {
	t.Helper()
	dir := t.TempDir()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"helm", "kubectl"} {
		if err := os.Symlink(exe, filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(dir, "commands.json")
	if err := os.WriteFile(path, []byte("[]"), 0o600); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(steps)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir) // Never fall back to the user's helm or kubectl.
	t.Setenv("K8SHARK_CLEAN_STEPS", string(data))
	t.Setenv("K8SHARK_CLEAN_COMMANDS", path)
	previousLog := log
	log = slog.New(slog.NewTextHandler(io.Discard, nil))
	t.Cleanup(func() { log = previousLog })
	t.Cleanup(func() {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var got [][]string
		if err := json.Unmarshal(data, &got); err != nil {
			t.Fatal(err)
		}
		want := make([][]string, 0, len(steps))
		for _, step := range steps {
			want = append(want, step.Args)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("cluster commands = %q, want exactly %q", got, want)
		}
	})
}

func TestCleanPropagatesHelmFailureWithoutFurtherCommands(t *testing.T) {
	for _, deleteNamespace := range []bool{false, true} {
		t.Run(fmt.Sprintf("deleteNamespace=%t", deleteNamespace), func(t *testing.T) {
			expectCleanCommands(t, cleanCommandStep{
				Args:     []string{"helm", "uninstall", "audit-release", "--namespace", "monitoring"},
				ExitCode: 23,
			})
			cmd := cleanCmd()
			cmd.SetArgs([]string{"--namespace", "monitoring", "--release", "audit-release", fmt.Sprintf("--delete-namespace=%t", deleteNamespace)})
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)
			err := cmd.Execute()
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitCode() != 23 || !strings.HasPrefix(err.Error(), "helm [uninstall audit-release --namespace monitoring]:") {
				t.Fatalf("want original helm exit 23, got %v", err)
			}
		})
	}
}

func TestCleanRejectsConflictingNamespaceFlagsBeforeUninstall(t *testing.T) {
	expectCleanCommands(t)
	cmd := cleanCmd()
	cmd.SetArgs([]string{"--delete-namespace", "--keep-namespace"})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "--delete-namespace") || !strings.Contains(err.Error(), "--keep-namespace") {
		t.Fatalf("conflicting flags must fail before uninstall, got %v", err)
	}
}

func TestCleanDeletesNamespaceWithExplicitOptIn(t *testing.T) {
	for _, flags := range [][]string{{"--delete-namespace"}, {"--delete-namespace", "--keep-namespace=false"}} {
		t.Run(fmt.Sprint(flags), func(t *testing.T) {
			expectCleanCommands(t,
				cleanCommandStep{Args: []string{"helm", "uninstall", "audit-release", "--namespace", "monitoring"}},
				cleanCommandStep{Args: []string{"kubectl", "delete", "namespace", "monitoring", "--ignore-not-found"}},
			)
			cmd := cleanCmd()
			cmd.SetArgs(append([]string{"--namespace", "monitoring", "--release", "audit-release"}, flags...))
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)
			if err := cmd.Execute(); err != nil {
				t.Fatalf("clean with deletion opt-in: %v", err)
			}
		})
	}
}

func TestCleanKeepsNamespaceWithLegacyFlag(t *testing.T) {
	for _, flag := range []string{"--keep-namespace", "--keep-namespace=false"} {
		t.Run(flag, func(t *testing.T) {
			expectCleanCommands(t, cleanCommandStep{Args: []string{"helm", "uninstall", "audit-release", "--namespace", "monitoring"}})
			cmd := cleanCmd()
			cmd.SetArgs([]string{"--namespace", "monitoring", "--release", "audit-release", flag})
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)
			if err := cmd.Execute(); err != nil {
				t.Fatalf("clean with legacy flag %s: %v", flag, err)
			}
		})
	}
}

func TestCleanPropagatesNamespaceDeletionFailure(t *testing.T) {
	expectCleanCommands(t,
		cleanCommandStep{Args: []string{"helm", "uninstall", "audit-release", "--namespace", "monitoring"}},
		cleanCommandStep{Args: []string{"kubectl", "delete", "namespace", "monitoring", "--ignore-not-found"}, ExitCode: 17},
	)
	cmd := cleanCmd()
	cmd.SetArgs([]string{"--namespace", "monitoring", "--release", "audit-release", "--delete-namespace"})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	err := cmd.Execute()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 17 || !strings.HasPrefix(err.Error(), "kubectl [delete namespace monitoring --ignore-not-found]:") {
		t.Fatalf("want original kubectl exit 17, got %v", err)
	}
}

func TestCleanKeepsNamespaceByDefault(t *testing.T) {
	expectCleanCommands(t, cleanCommandStep{Args: []string{"helm", "uninstall", "audit-release", "--namespace", "monitoring"}})
	cmd := cleanCmd()
	cmd.SetArgs([]string{"--namespace", "monitoring", "--release", "audit-release"})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("clean without deletion opt-in: %v", err)
	}
}
