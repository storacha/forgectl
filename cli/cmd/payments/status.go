package payments

import (
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/spf13/cobra"
	"github.com/storacha/forgectl/cli/config"
	"github.com/storacha/forgectl/cli/printer"
	"github.com/storacha/forgectl/pkg/services/inspector"
)

var (
	payer      string
	listLimit  int64
	listOffset int64
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Display account balance, operator approval, and active payment rails",
	RunE:  runStatus,
}

func init() {
	statusCmd.Flags().StringVar(&payer, "payer", "", "payer address")
	cobra.CheckErr(statusCmd.MarkFlagRequired("payer"))
	statusCmd.Flags().Int64Var(&listLimit, "limit", 50, "Maximum number of providers to display")
	statusCmd.Flags().Int64Var(&listOffset, "offset", 0, "Starting offset for pagination")
}

func runStatus(cmd *cobra.Command, args []string) error {
	if !common.IsHexAddress(payer) {
		return fmt.Errorf("invalid payer address: %s", payer)
	}
	payerAddr := common.HexToAddress(payer)

	ctx := cmd.Context()
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	inspctr, err := inspector.New(inspector.Config{
		ClientEndpoint:          cfg.RPCUrl,
		PaymentsContractAddress: cfg.PaymentsAddr(),
		ServiceContractAddress:  cfg.ServiceAddr(),
		ProviderRegistryAddress: cfg.ServiceRegistryAddr(),
	})
	if err != nil {
		return err
	}

	res, err := inspctr.PaymentsStatus(ctx, cfg.TokenAddr(), payerAddr, 0, 100)
	if err != nil {
		return err
	}
	return printer.AsJson(cmd.OutOrStdout(), res)
}
