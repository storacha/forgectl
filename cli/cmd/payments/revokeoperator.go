package payments

import (
	"fmt"
	"math/big"

	"github.com/spf13/cobra"
	"github.com/storacha/forgectl/cli/config"
	"github.com/storacha/forgectl/cli/printer"
	"github.com/storacha/forgectl/pkg/services/chain"
	"github.com/storacha/forgectl/pkg/services/inspector"
	payerservice "github.com/storacha/forgectl/pkg/services/payer"
)

var revokeOperatorCmd = &cobra.Command{
	Use:   "revoke-operator",
	Short: "Revoke operator approval for the service contract",
	Long: `Revoke operator approval for the service contract.
This calls the Payments contract's setOperatorApproval method with approve=false and zero allowances.`,
	RunE: runRevokeOperator,
}

func runRevokeOperator(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	cfg, err := config.Load()
	if err != nil {
		return err
	}

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
		KeystorePath:     cfg.PayerKeystorePath,
		KeystorePassword: cfg.PayerKeystorePassword,
	})
	if err != nil {
		return err
	}

	payerSvc, err := payerservice.New(is, txtr)
	if err != nil {
		return err
	}

	// Revoke with all zero allowances
	res, err := payerSvc.SetOperatorApproval(ctx, payerservice.SetOperatorApprovalParams{
		Approve:         false,
		RateAllowance:   big.NewInt(0),
		LockupAllowance: big.NewInt(0),
		MaxLockupPeriod: big.NewInt(0),
	})
	if err != nil {
		return fmt.Errorf("revoking operator approval: %w", err)
	}

	return printer.AsJson(cmd.OutOrStdout(), res)
}
