package providers

import (
	"fmt"
	"strconv"

	"github.com/ethereum/go-ethereum/common"
	"github.com/spf13/cobra"
	"github.com/storacha/forgectl/cli/config"
	"github.com/storacha/forgectl/cli/printer"
	"github.com/storacha/forgectl/pkg/services/inspector"
	"github.com/storacha/forgectl/pkg/services/types"
)

var getCmd = &cobra.Command{
	Use:   "get",
	Short: "Get registered service provider by ID or address",
	Args:  cobra.ExactArgs(1),
	RunE:  runGet,
}

func runGet(cmd *cobra.Command, args []string) error {
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

	var res *types.ProviderInfo

	// Check if the argument is a hex address
	if common.IsHexAddress(args[0]) {
		addr := common.HexToAddress(args[0])
		res, err = inspctr.GetProviderByAddress(ctx, addr)
		if err != nil {
			return err
		}
	} else {
		// Try to parse as provider ID
		providerID, err := strconv.ParseUint(args[0], 10, 64)
		if err != nil {
			return fmt.Errorf("invalid argument: %s (must be a valid provider ID number or hex address)", args[0])
		}
		res, err = inspctr.GetProviderByID(ctx, providerID)
		if err != nil {
			return err
		}
	}

	return printer.AsJson(cmd.OutOrStdout(), res)
}
