package cli

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/pablocolson/k8shark/internal/config"
	"github.com/pablocolson/k8shark/internal/k8s"
	"github.com/spf13/cobra"
)

func cleanCmd() *cobra.Command {
	var namespace, release string
	var deleteNamespace, keepNamespace bool
	cmd := &cobra.Command{
		Use:   "clean",
		Short: "Uninstall the k8shark release (keep the namespace by default)",
		Long: "Uninstalls the Helm release and keeps the namespace by default.\n\n" +
			"--delete-namespace opts into deleting the entire namespace and ALL remaining\n" +
			"resources, including unrelated Secrets, PVCs, ConfigMaps and custom resources,\n" +
			"only after a successful Helm uninstall. No ownership check is performed.\n" +
			"The legacy --keep-namespace flag is accepted; setting it to false does not\n" +
			"request deletion. --delete-namespace and --keep-namespace cannot both be true.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if deleteNamespace && keepNamespace {
				return fmt.Errorf("--delete-namespace and --keep-namespace cannot both be true")
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			return k8s.Uninstall(ctx, log, release, namespace, deleteNamespace)
		},
	}
	cmd.Flags().StringVarP(&namespace, "namespace", "n", config.DefaultNamespace, "namespace to remove")
	cmd.Flags().StringVar(&release, "release", "k8shark", "helm release name")
	cmd.Flags().BoolVar(&deleteNamespace, "delete-namespace", false,
		"delete the entire namespace and ALL remaining resources after a successful helm uninstall")
	cmd.Flags().BoolVar(&keepNamespace, "keep-namespace", false,
		"keep the namespace (legacy flag; already the default, even with --keep-namespace=false)")
	return cmd
}
