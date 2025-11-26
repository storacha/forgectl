package providers

import (
	"github.com/spf13/cobra"
	"github.com/storacha/forgectl/cli/config"
	"github.com/storacha/forgectl/cli/printer"
	"github.com/storacha/forgectl/pkg/services/inspector"
)

var (
	listLimit  int64
	listOffset int64
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List registered service providers",
	Args:  cobra.NoArgs,
	RunE:  runList,
}

func init() {
	listCmd.Flags().Int64Var(&listLimit, "limit", 50, "Maximum number of providers to display")
	listCmd.Flags().Int64Var(&listOffset, "offset", 0, "Starting offset for pagination")
}

func runList(cmd *cobra.Command, _ []string) error {
	ctx := cmd.Context()
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	inspctr, err := inspector.New(inspector.Config{
		ClientEndpoint:            cfg.RPCUrl,
		PaymentsContractAddress:   cfg.PaymentsAddr(),
		ServiceContractAddress:    cfg.ServiceAddr(),
		ProviderRegistryAddress:   cfg.ServiceRegistryAddr(),
		TokenAddress:              cfg.TokenAddr(),
		SessionKeyRegistryAddress: cfg.SessionKeyRegistryAddr(),
	})
	if err != nil {
		return err
	}

	res, err := inspctr.ListProviders(ctx, listOffset, listLimit)
	if err != nil {
		return err
	}
	return printer.AsJson(cmd.OutOrStdout(), res)
}
