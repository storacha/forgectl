package providers

import (
	"fmt"
	"strconv"

	"github.com/spf13/cobra"
	"github.com/storacha/forgectl/cli/config"
	"github.com/storacha/forgectl/cli/printer"
	"github.com/storacha/forgectl/pkg/services/chain"
	"github.com/storacha/forgectl/pkg/services/inspector"
	"github.com/storacha/forgectl/pkg/services/operator"
)

var approveCmd = &cobra.Command{
	Use:   "approve <provider-id>",
	Short: "Approve a provider to create datasets",
	Long: `Approve a provider by their ID to allow them to create datasets in the FilecoinWarmStorageService.

The provider must already be registered in the ServiceProviderRegistry before approval.
Only the contract owner can approve providers.`,
	Args: cobra.ExactArgs(1),
	RunE: runApprove,
}

// TODO: room for improvement here, this method will return success even if:
// 1. the provider is already approved
// 2. the provider doesn't exist
// we should modify the contract to allow inspection of approved operators
func runApprove(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()

	providerID, err := strconv.ParseUint(args[0], 10, 64)
	if err != nil {
		return fmt.Errorf("invalid provider ID: %s (must be a valid number)", args[0])
	}

	// Load config
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	// Create Inspector, then Operator
	is, err := inspector.New(inspector.Config{
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

	chainID, err := is.ChainID(ctx)
	if err != nil {
		return err
	}

	txtr, err := chain.NewTransactor(chainID, chain.TransactorConfig{
		KeystorePath:     cfg.OwnerKeystorePath,
		KeystorePassword: cfg.OwnerKeystorePassword,
	})
	if err != nil {
		return err
	}
	op, err := operator.New(is, txtr)
	if err != nil {
		return err
	}

	res, err := op.ApproveProvider(ctx, providerID)
	if err != nil {
		return err
	}

	return printer.AsJson(cmd.OutOrStdout(), res)
}
