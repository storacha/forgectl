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

var (
	rateAllowance   string
	lockupAllowance string
	maxLockupPeriod string
)

var approveOperatorCmd = &cobra.Command{
	Use:   "approve-operator",
	Short: "Approve operator for the service contract",
	Long: `Approve operator for the service contract to manage payments.
This calls the Payments contract's setOperatorApproval method using the service and token addresses from the config.`,
	RunE: runApproveOperator,
}

func init() {
	approveOperatorCmd.Flags().StringVar(&rateAllowance, "rate-allowance", "0", "rate allowance (in token base units)")
	approveOperatorCmd.Flags().StringVar(&lockupAllowance, "lockup-allowance", "0", "lockup allowance (in token base units)")
	approveOperatorCmd.Flags().StringVar(&maxLockupPeriod, "max-lockup-period", "0", "maximum lockup period (in epochs)")
	cobra.CheckErr(approveOperatorCmd.MarkFlagRequired("rate-allowance"))
	cobra.CheckErr(approveOperatorCmd.MarkFlagRequired("lockup-allowance"))
	cobra.CheckErr(approveOperatorCmd.MarkFlagRequired("max-lockup-period"))
}

func runApproveOperator(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	// Parse allowances and periods as big.Int
	rateAllowanceBig, ok := new(big.Int).SetString(rateAllowance, 10)
	if !ok {
		return fmt.Errorf("invalid rate allowance: %s", rateAllowance)
	}

	lockupAllowanceBig, ok := new(big.Int).SetString(lockupAllowance, 10)
	if !ok {
		return fmt.Errorf("invalid lockup allowance: %s", lockupAllowance)
	}

	maxLockupPeriodBig, ok := new(big.Int).SetString(maxLockupPeriod, 10)
	if !ok {
		return fmt.Errorf("invalid max lockup period: %s", maxLockupPeriod)
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

	res, err := payerSvc.SetOperatorApproval(ctx, payerservice.SetOperatorApprovalParams{
		Approve:         true,
		RateAllowance:   rateAllowanceBig,
		LockupAllowance: lockupAllowanceBig,
		MaxLockupPeriod: maxLockupPeriodBig,
	})
	if err != nil {
		return fmt.Errorf("setting operator approval: %w", err)
	}

	return printer.AsJson(cmd.OutOrStdout(), res)
}
