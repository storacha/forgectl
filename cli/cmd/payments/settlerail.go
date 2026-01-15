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
	railID     string
	untilEpoch string
)

var settleRailCmd = &cobra.Command{
	Use:   "settle-rail",
	Short: "Settle payments for a rail up to a specified epoch",
	Long: `Settle payments for a rail up to the specified epoch.
Settlement may fail to reach the target epoch if either the client lacks the funds to pay up to the current epoch
or the validator refuses to settle the entire requested range.`,
	RunE: runSettleRail,
}

func init() {
	settleRailCmd.Flags().StringVar(&railID, "rail-id", "", "ID of the rail to settle")
	settleRailCmd.Flags().StringVar(&untilEpoch, "until-epoch", "", "epoch up to which to settle (must not exceed current block number)")
	cobra.CheckErr(settleRailCmd.MarkFlagRequired("rail-id"))
	cobra.CheckErr(settleRailCmd.MarkFlagRequired("until-epoch"))
}

func runSettleRail(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	railIDBig, ok := new(big.Int).SetString(railID, 10)
	if !ok {
		return fmt.Errorf("invalid rail ID: %s", railID)
	}

	untilEpochBig, ok := new(big.Int).SetString(untilEpoch, 10)
	if !ok {
		return fmt.Errorf("invalid until epoch: %s", untilEpoch)
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

	res, err := payerSvc.SettleRail(ctx, railIDBig, untilEpochBig)
	if err != nil {
		return fmt.Errorf("settling rail: %w", err)
	}

	return printer.AsJson(cmd.OutOrStdout(), res)
}
